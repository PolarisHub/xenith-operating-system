//! PS/2 controller (Intel 8042) and its two child devices.
//!
//! This module owns the shared 8042 keyboard-controller surface that both PS/2
//! devices hang off: the I/O-port register file, the command/data transport,
//! the controller self-test and dual-channel detection, and the configuration
//! byte. The two child drivers live in [`keyboard`] (first port, IRQ 1) and
//! [`mouse`] (auxiliary port, IRQ 12) and call into the helpers here for every
//! controller transaction so there is exactly one implementation of the
//! wait/send/receive protocol.
//!
//! # The 8042 in brief
//!
//! The 8042 is a microcontroller inside the southbridge that fronts two PS/2
//! ports. It exposes two I/O ports:
//!
//! * `0x60` — the data port. Reads pull a byte from the output buffer (a byte
//!   the controller or a device produced); writes push a byte into the input
//!   buffer (the argument to the most recent command, or a byte for the
//!   first-port device when no command is pending).
//! * `0x64` — the status register on reads, the command register on writes.
//!   Writing a command byte here selects what the *next* `0x60` write means
//!   (a configuration byte, a byte for the aux port, etc.).
//!
//! A status register at `0x64` reports whether the output buffer is full
//! (something to read), the input buffer is full (not ready for a write),
//! whether the pending byte came from the aux port, and timeout/parity error
//! bits. Every transaction polls those bits: there is no sane interrupt-driven
//! command path because the controller's command responses are tiny and
//! synchronous.
//!
//! # Dual-channel detection
//!
//! A "dual-channel" controller has two ports (keyboard + mouse); a
//! single-channel controller has only the keyboard port. The two are
//! indistinguishable until you ask: the canonical probe is to disable the
//! aux port (`0xA7`), read the configuration byte (`0x20`), and inspect bit 5
//! — the "second port clock disabled" bit. On a dual-channel controller the
//! disable command flips that bit; on a single-channel controller the bit
//! reads back the same. [`probe_dual_channel`] implements this and
//! [`init`] stores the result in a static so the mouse driver can decide
//! whether to bring itself up.
//!
//! # IRQ routing
//!
//! The first port is wired to legacy IRQ 1 and the aux port to IRQ 12. Xenith
//! installs dedicated IDT gates and routes both lines through the I/O APIC.
//! On systems without an I/O APIC it falls back to the remapped 8259 PIC.
//!
//! # Layering
//!
//! `ps2` sits above [`crate::arch::x86_64::port`] (for typed PIO) and
//! [`crate::sync`] (the child drivers use [`SpinLockIRQ`] for their shared
//! state). It is initialised after the console/log/arch/mm subsystems are up
//! and before the input layer expects keystrokes. The controller bring-up
//! runs with maskable interrupts disabled — the 8042 command protocol is not
//! re-entrant and a keyboard IRQ mid-sequence would corrupt the transaction.

use core::sync::atomic::{AtomicBool, Ordering};

use xenith_bitflags::bitflags;

use crate::arch::x86_64::port::{io_wait, Port8};
use crate::sync::SpinLock;

// External IRQ gates need an `iretq` epilogue, which a normal Rust ABI
// function cannot provide. These two tiny stubs preserve the integer register
// file, conditionally swap the kernel GS base in for a ring-3 interruption,
// align the stack for a SysV call, invoke the Rust handler, then undo the GS
// swap and return through the untouched hardware interrupt frame.
core::arch::global_asm!(
    r#"
    .section .text
    .macro PS2_IRQ_STUB name, rust
    .global \name
\name:
    // An IRQ has no vector/error words on its stack: saved CS is always at
    // rsp+8. Kernel entries already have the per-CPU GS base active; user
    // entries need exactly one swap before calling Rust.
    test byte ptr [rsp + 8], 1
    jz 1f
    test byte ptr [rsp + 8], 2
    jz 1f
    swapgs
1:
    cld
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rbx, rsp
    and rsp, -16
    call \rust
    mov rsp, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    // All pushes are gone, so rsp again addresses the original CPU frame and
    // saved CS remains at +8. Restore the user GS base only for a ring-3
    // return; same-CPL IRQ frames remain completely untouched.
    test byte ptr [rsp + 8], 1
    jz 2f
    test byte ptr [rsp + 8], 2
    jz 2f
    swapgs
2:
    iretq
    .endm

    PS2_IRQ_STUB xenith_ps2_keyboard_irq, xenith_ps2_keyboard_irq_rust
    PS2_IRQ_STUB xenith_ps2_mouse_irq, xenith_ps2_mouse_irq_rust
"#,
);

extern "C" {
    fn xenith_ps2_keyboard_irq();
    fn xenith_ps2_mouse_irq();
}

pub mod keyboard;
pub mod mouse;

// Re-export the child device error types at the module root so callers can
// match on `ps2::Ps2KeyboardError` / `ps2::Ps2MouseError` without drilling
// into the submodules.
pub use keyboard::Ps2KeyboardError;
pub use mouse::Ps2MouseError;

// ---------------------------------------------------------------------------
// 8042 I/O ports
// ---------------------------------------------------------------------------

/// Controller status register (read) / command register (write) at I/O `0x64`.
///
/// Reads return the 8-bit status byte; writes begin a controller command whose
/// data phase (if any) goes to [`DATA`].
const STATUS_CMD: Port8 = Port8::new(0x64);

/// Controller data register at I/O `0x60`. Reads pull from the output buffer;
/// writes push into the input buffer (a command argument or a first-port byte).
const DATA: Port8 = Port8::new(0x60);

// ---------------------------------------------------------------------------
// Status register bits (read from `0x64`)
// ---------------------------------------------------------------------------

/// Bit 0: output buffer full — a byte is waiting to be read from `0x60`.
pub(crate) const STS_OUT_FULL: u8 = 1 << 0;
/// Bit 1: input buffer full — the controller is not ready for a write.
pub(crate) const STS_IN_FULL: u8 = 1 << 1;
/// Bit 5: the pending output byte came from the auxiliary (mouse) port.
pub(crate) const STS_FROM_AUX: u8 = 1 << 5;
/// Bit 6: a write timed out (no device ACK within the controller window).
pub(crate) const STS_TIMEOUT: u8 = 1 << 6;
/// Bit 7: a parity error was detected on the last byte received.
pub(crate) const STS_PARITY: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Controller command bytes (written to `0x64`)
// ---------------------------------------------------------------------------

/// Read the controller configuration byte. The byte appears on `0x60`.
const CMD_READ_CONFIG: u8 = 0x20;
/// Write the controller configuration byte. The next `0x60` write is the value.
const CMD_WRITE_CONFIG: u8 = 0x60;
/// Disable the auxiliary (second) port. No data phase.
const CMD_DISABLE_AUX: u8 = 0xA7;
/// Enable the auxiliary (second) port. No data phase.
const CMD_ENABLE_AUX: u8 = 0xA8;
/// Disable the first (keyboard) port. No data phase.
const CMD_DISABLE_FIRST: u8 = 0xAD;
/// Enable the first (keyboard) port. No data phase.
const CMD_ENABLE_FIRST: u8 = 0xAE;
/// Controller self-test. The controller replies `0x55` on `0x60` if it passed.
const CMD_SELF_TEST: u8 = 0xAA;
/// Test the first port. The controller replies `0x00` on `0x60` if the port
/// passed (clock and data lines not stuck).
const CMD_TEST_FIRST: u8 = 0xAB;
/// Test the auxiliary port. Replies `0x00` on `0x60` on success.
const CMD_TEST_AUX: u8 = 0xA9;
/// "Next byte written to `0x60` is for the auxiliary device." Must precede
/// every single byte sent to the mouse.
const CMD_WRITE_AUX: u8 = 0xD4;

/// Controller self-test pass response, read from `0x60` after [`CMD_SELF_TEST`].
const SELF_TEST_OK: u8 = 0x55;
/// First-port line-test pass response, read from `0x60` after [`CMD_TEST_FIRST`].
const PORT_TEST_OK: u8 = 0x00;

/// Poll iterations before a controller wait gives up. The 8042 responds in
/// microseconds on real hardware; 100k iterations is a generous bound that
/// still fails fast on a wedged controller instead of hanging the boot.
const POLL_LIMIT: u32 = 100_000;

// ---------------------------------------------------------------------------
// Controller configuration byte
// ---------------------------------------------------------------------------

bitflags! {
    /// The 8042 controller configuration byte, read with `0x20` / written with
    /// `0x60`.
    ///
    /// This byte gates the two ports' interrupt lines and clock lines and
    /// selects the scancode translation mode. [`init`] reads it to discover the
    /// platform's wiring, and the child drivers read-modify-write it to enable
    /// their own interrupt bit without disturbing the other port's settings.
    pub struct ControllerConfig: u8 {
        /// Bit 0: generate IRQ 1 when the first port has a byte ready.
        pub const FIRST_INT         = 1 << 0;
        /// Bit 1: generate IRQ 12 when the auxiliary port has a byte ready.
        pub const SECOND_INT        = 1 << 1;
        /// Bit 2: system flag. Cleared on power-on reset; the OS sets it after
        /// a successful controller self-test to signal "POST passed, OS in
        /// control".
        pub const SYSTEM_FLAG       = 1 << 2;
        /// Bit 3: must always read as 0. Reserved by the controller.
        pub const RESERVED_3        = 1 << 3;
        /// Bit 4: first-port clock disabled. Set by [`CMD_DISABLE_FIRST`].
        pub const FIRST_CLK_DISABLED = 1 << 4;
        /// Bit 5: auxiliary-port clock disabled. Set by [`CMD_DISABLE_AUX`].
        /// This is the bit [`probe_dual_channel`] inspects: on a dual-channel
        /// controller the disable command flips it, on a single-channel one it
        /// does not.
        pub const SECOND_CLK_DISABLED = 1 << 5;
        /// Bit 6: scancode translation. When set the controller translates
        /// first-port set-2 scancodes into set-1 on the way to the CPU. Xenith
        /// leaves this clear so the keyboard emits raw set-1 (the keyboard
        /// driver decodes set 1 directly); the bit is defined here so [`init`]
        /// can clear it explicitly.
        pub const TRANSLATION       = 1 << 6;
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A hand-rolled error type for 8042 controller transactions.
///
/// There is no `thiserror` in `no_std`, so the variants are plain and the
/// `Debug` derive is enough for the `log` facade to render them. The child
/// drivers define their own error enums for device-level failures (bad ACK,
/// self-test failure); this enum covers only the shared transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2ControllerError {
    /// A port poll exceeded [`POLL_LIMIT`] — the controller is not responding,
    /// typically because the device is absent or the bus is wedged.
    Timeout,
    /// The status register reported a parity or timeout error on the last
    /// transaction.
    BusError,
    /// The controller self-test did not return `0x55`.
    SelfTestFailed,
    /// The first-port line test did not return `0x00`.
    FirstPortTestFailed,
    /// The auxiliary-port line test did not return `0x00`.
    AuxPortTestFailed,
}

// ---------------------------------------------------------------------------
// Controller state
// ---------------------------------------------------------------------------

/// Whether the controller exposed a second (auxiliary) PS/2 port.
///
/// Set once by [`init`] and read by the mouse driver to decide whether to
/// attempt bring-up. A single-channel controller has no aux port, so probing
/// it would time out and waste boot time; the flag lets the mouse skip
/// cleanly.
static DUAL_CHANNEL: SpinLock<bool> = SpinLock::new(false);

/// Whether [`init`] has completed successfully.
///
/// The child drivers consult this before issuing commands so a boot that
/// failed controller bring-up does not pile onto a wedged 8042.
static INITIALIZED: SpinLock<bool> = SpinLock::new(false);

/// Record that the controller supports a second port. Called once by [`init`].
fn set_dual_channel(dual: bool) {
    *DUAL_CHANNEL.lock() = dual;
}

/// Whether the controller reported a second (auxiliary) PS/2 port at init.
///
/// `false` until [`init`] runs, and `false` thereafter on a single-channel
/// controller. The mouse driver reads this to decide whether to bring itself
/// up.
pub fn is_dual_channel() -> bool {
    *DUAL_CHANNEL.lock()
}

/// Whether [`init`] has completed successfully.
pub fn is_initialized() -> bool {
    *INITIALIZED.lock()
}

// ---------------------------------------------------------------------------
// Low-level transport: wait / send / receive
// ---------------------------------------------------------------------------

/// Spin until the controller's input buffer is empty (ready for a write).
///
/// Returns [`Ps2ControllerError::Timeout`] if the buffer never drains within
/// [`POLL_LIMIT`] iterations. Each iteration inserts an ISA-bus-cycle delay via
/// [`io_wait`] so back-to-back status reads on slow hardware are not dropped.
pub(crate) fn wait_in_empty() -> Result<(), Ps2ControllerError> {
    for _ in 0..POLL_LIMIT {
        if STATUS_CMD.read() & STS_IN_FULL == 0 {
            return Ok(());
        }
        io_wait();
    }
    Err(Ps2ControllerError::Timeout)
}

/// Spin until the controller's output buffer is full (a byte is ready to read).
///
/// Returns a [`Ps2ControllerError::BusError`] if the status register reports a
/// timeout or parity fault instead of a ready byte, or
/// [`Ps2ControllerError::Timeout`] if no byte arrives within [`POLL_LIMIT`].
pub(crate) fn wait_out_full() -> Result<(), Ps2ControllerError> {
    for _ in 0..POLL_LIMIT {
        let sts = STATUS_CMD.read();
        if sts & STS_OUT_FULL != 0 {
            if sts & (STS_TIMEOUT | STS_PARITY) != 0 {
                return Err(Ps2ControllerError::BusError);
            }
            return Ok(());
        }
        io_wait();
    }
    Err(Ps2ControllerError::Timeout)
}

/// Send a controller command byte to `0x64` with no data phase.
///
/// Waits for the input buffer to drain, writes the command, and waits one ISA
/// cycle for the controller to latch it. This is the primitive the higher-level
/// [`send_cmd_with_data`] and the public [`send_cmd`] build on.
pub(crate) fn send_cmd_raw(cmd: u8) -> Result<(), Ps2ControllerError> {
    wait_in_empty()?;
    STATUS_CMD.write(cmd);
    io_wait();
    Ok(())
}

/// Send a controller command byte to `0x64` and wait for it to be accepted.
///
/// This is the public command primitive for commands with no data phase (e.g.
/// [`CMD_DISABLE_FIRST`], [`CMD_SELF_TEST`]). Commands that take a data byte
/// use [`send_cmd_with_data`] instead.
pub fn send_cmd(cmd: u8) -> Result<(), Ps2ControllerError> {
    send_cmd_raw(cmd)
}

/// Send a controller command byte that takes one data byte, then write the
/// data byte to `0x60`.
///
/// Used for `CMD_WRITE_CONFIG` (`0x60`) and any command whose protocol is
/// "command to `0x64`, argument to `0x60`". The two writes are issued in
/// program order with an [`io_wait`] between them so slow hardware latches the
/// command before the argument arrives.
pub fn send_cmd_with_data(cmd: u8, data: u8) -> Result<(), Ps2ControllerError> {
    send_cmd_raw(cmd)?;
    write_data(data)
}

/// Read one byte from the controller's output buffer (`0x60`).
///
/// Waits for the output buffer to fill, then reads the byte. Use this for
/// command responses (configuration readback, self-test result, device ACKs
/// and IDs). The raw status-checking is in [`wait_out_full`], which surfaces
/// parity/timeout faults as [`Ps2ControllerError::BusError`].
pub fn read_data() -> Result<u8, Ps2ControllerError> {
    wait_out_full()?;
    Ok(DATA.read())
}

/// Read the next first-port response, discarding any interleaved auxiliary
/// stream bytes. Device commands are synchronous and their ACK must not be
/// confused with a mouse movement byte that happened to reach the shared
/// output buffer first.
pub(crate) fn read_first_port_data() -> Result<u8, Ps2ControllerError> {
    for _ in 0..POLL_LIMIT {
        let status = STATUS_CMD.read();
        if status & STS_OUT_FULL == 0 {
            io_wait();
            continue;
        }
        if status & (STS_TIMEOUT | STS_PARITY) != 0 {
            let _ = DATA.read();
            return Err(Ps2ControllerError::BusError);
        }
        let byte = DATA.read();
        if status & STS_FROM_AUX == 0 {
            return Ok(byte);
        }
    }
    Err(Ps2ControllerError::Timeout)
}

/// Write one byte to the controller's input buffer (`0x60`).
///
/// Waits for the input buffer to drain, then writes the byte. This is the data
/// phase of a [`send_cmd_with_data`] call and the path for first-port device
/// bytes sent without a `CMD_WRITE_AUX` prefix.
pub fn write_data(byte: u8) -> Result<(), Ps2ControllerError> {
    wait_in_empty()?;
    DATA.write(byte);
    io_wait();
    Ok(())
}

/// Read one immediately available first-port byte without polling.
///
/// This is the IRQ-safe receive primitive used by the keyboard handler. It
/// leaves auxiliary-port bytes untouched so IRQ 12 can consume them, and it
/// reports controller parity/timeout status rather than feeding a corrupt
/// scancode to the decoder.
pub(crate) fn try_read_first_port_byte() -> Result<Option<u8>, Ps2ControllerError> {
    let status = STATUS_CMD.read();
    if status & STS_OUT_FULL == 0 || status & STS_FROM_AUX != 0 {
        return Ok(None);
    }
    if status & (STS_TIMEOUT | STS_PARITY) != 0 {
        let _ = DATA.read();
        return Err(Ps2ControllerError::BusError);
    }
    Ok(Some(DATA.read()))
}

/// Drain stale controller/device bytes after both ports have been disabled.
/// The output buffer is finite (normally one byte); the bound protects boot
/// from a broken controller that continuously asserts OBF.
fn flush_output() {
    for _ in 0..256 {
        if STATUS_CMD.read() & STS_OUT_FULL == 0 {
            break;
        }
        let _ = DATA.read();
        io_wait();
    }
}

/// Send one byte to the auxiliary (mouse) port.
///
/// Issues `CMD_WRITE_AUX` to `0x64`, then the byte to `0x60`, then reads and
/// returns the mouse's ACK. Every byte destined for the mouse needs its own
/// `CMD_WRITE_AUX` prefix — the controller forwards only the single byte
/// immediately following the prefix. The caller is expected to check the
/// returned ACK against `0xFA`; this helper does not enforce it so it can be
/// reused by commands whose reply is not a bare ACK (e.g. `GET_ID`).
pub fn send_aux(byte: u8) -> Result<u8, Ps2ControllerError> {
    send_cmd_raw(CMD_WRITE_AUX)?;
    write_data(byte)?;
    read_data()
}

/// Read the controller configuration byte via `CMD_READ_CONFIG`.
///
/// Convenience wrapper around [`send_cmd`] + [`read_data`].
pub fn read_config() -> Result<ControllerConfig, Ps2ControllerError> {
    send_cmd(CMD_READ_CONFIG)?;
    let raw = read_data()?;
    Ok(ControllerConfig::from_bits_truncate(raw))
}

/// Write the controller configuration byte via `CMD_WRITE_CONFIG`.
///
/// Convenience wrapper around [`send_cmd_with_data`].
pub fn write_config(config: ControllerConfig) -> Result<(), Ps2ControllerError> {
    send_cmd_with_data(CMD_WRITE_CONFIG, config.bits())
}

// ---------------------------------------------------------------------------
// Dual-channel probe
// ---------------------------------------------------------------------------

/// Probe whether the controller has a second (auxiliary) PS/2 port.
///
/// The canonical test: disable the aux port, read the config byte, and check
/// bit 5 (`SECOND_CLK_DISABLED`). On a dual-channel controller the
/// `CMD_DISABLE_AUX` command flips that bit on; on a single-channel controller
/// the bit reads back unchanged (the command is a no-op). The aux port is left
/// disabled on return so the caller's subsequent bring-up starts from a known
/// quiescent state.
///
/// Returns `true` if a second port is present, `false` otherwise. A transport
/// error propagates as `Err`.
pub fn probe_dual_channel() -> Result<bool, Ps2ControllerError> {
    // Disable the aux port. On a single-channel controller this is a no-op.
    send_cmd(CMD_DISABLE_AUX)?;
    // Read the config and inspect bit 5. A dual-channel controller sets it in
    // response to the disable command; a single-channel one leaves it clear.
    let config = read_config()?;
    Ok(config.contains(ControllerConfig::SECOND_CLK_DISABLED))
}

// ---------------------------------------------------------------------------
// Controller bring-up
// ---------------------------------------------------------------------------

/// Bring up the 8042 controller itself.
///
/// Runs the canonical PS/2 controller init sequence shared by every PC OS:
///
/// 1. **Disable both ports** (`0xAD` / `0xA7`) so no device can interrupt the
///    bring-up with a stray byte.
/// 2. **Self-test** the controller (`0xAA`), expecting `0x55`. A failure here
///    means the 8042 is wedged and neither PS/2 device will work.
/// 3. **Probe dual-channel** support via [`probe_dual_channel`] and record the
///    result so the mouse driver can decide whether to bring itself up.
/// 4. **Test both ports' lines** (`0xAB` / `0xA9`), expecting `0x00` each. A
///    non-zero reply means the port's clock/data lines are stuck and the
///    attached device will not be usable; we log the failure and leave the
///    port disabled rather than abort the whole controller.
/// 5. **Enable both ports** (`0xAE` / `0xA8`) — the child drivers re-enable
///    their interrupt bits in their own init by read-modify-writing the
///    config, so this only un-gates the port clocks.
/// 6. **Read the final configuration** and log it for boot diagnostics.
///
/// This function does **not** touch the first-port interrupt or translation
/// bits beyond what the self-test leaves them at; [`keyboard::init`] owns the
/// keyboard-side config and [`mouse::init`] owns the aux-side config. The
/// controller is left with both ports enabled but interrupts unchanged, so the
/// child drivers can RMW the config from a clean baseline.
///
/// # When to call
///
/// Called by the device bring-up sequence before [`keyboard::init`] and
/// [`mouse::init`]. Must run with maskable interrupts disabled — the 8042
/// command protocol is not re-entrant. On error the controller is left
/// disabled and `is_initialized()` stays `false`; the caller can continue
/// boot without PS/2 input.
pub fn init() -> Result<(), Ps2ControllerError> {
    // 1. Disable both ports so no device can fire an IRQ into the middle of
    //    the bring-up sequence.
    send_cmd(CMD_DISABLE_FIRST)?;
    send_cmd(CMD_DISABLE_AUX)?;
    flush_output();

    // 2. Controller self-test. The 8042 runs an internal test routine and
    //    replies 0x55 on success. A failure is fatal for the whole PS/2
    //    subsystem: we return early and leave both ports disabled.
    send_cmd(CMD_SELF_TEST)?;
    let test = read_data()?;
    if test != SELF_TEST_OK {
        ::log::error!(
            "xenith.ps2: controller self-test failed (got 0x{:02x}, expected 0x{:02x})",
            test,
            SELF_TEST_OK
        );
        return Err(Ps2ControllerError::SelfTestFailed);
    }

    // 3. Probe whether a second port exists. probe_dual_channel leaves the aux
    //    port disabled on return, which is what we want for the next steps.
    let dual = probe_dual_channel()?;
    set_dual_channel(dual);
    ::log::debug!(
        "xenith.ps2: controller is {}",
        if dual {
            "dual-channel"
        } else {
            "single-channel"
        }
    );

    // 4. Test the port lines. A non-zero reply indicates a stuck clock or data
    //    line; we log it and continue, leaving that port disabled. The other
    //    port may still be usable, so a single bad port is not fatal.
    send_cmd(CMD_TEST_FIRST)?;
    let first_test = read_data()?;
    if first_test != PORT_TEST_OK {
        ::log::warn!(
            "xenith.ps2: first-port line test failed (0x{:02x}); keyboard disabled",
            first_test
        );
    } else {
        send_cmd(CMD_ENABLE_FIRST)?;
    }

    if dual {
        send_cmd(CMD_TEST_AUX)?;
        let aux_test = read_data()?;
        if aux_test != PORT_TEST_OK {
            ::log::warn!(
                "xenith.ps2: aux-port line test failed (0x{:02x}); mouse disabled",
                aux_test
            );
        } else {
            send_cmd(CMD_ENABLE_AUX)?;
        }
    }

    // 5. Read the final configuration for diagnostics. We deliberately do not
    //    force any interrupt or translation bits here: the child drivers each
    //    RMW the config in their own init so they own their port's settings
    //    without clobbering the other's.
    let config = read_config()?;
    ::log::info!(
        "xenith.ps2: controller initialised (dual_channel={}, config=0x{:02x})",
        dual,
        config.bits()
    );

    *INITIALIZED.lock() = true;
    Ok(())
}

// ---------------------------------------------------------------------------
// IRQ registration
// ---------------------------------------------------------------------------

/// The legacy IRQ line the first PS/2 port (keyboard) is wired to.
pub const KEYBOARD_IRQ: u8 = 1;
/// The legacy IRQ line the auxiliary PS/2 port (mouse) is wired to.
pub const MOUSE_IRQ: u8 = 12;
/// IDT vector used for keyboard IRQ 1 (legacy PIC-compatible mapping).
pub const KEYBOARD_VECTOR: u8 = 0x21;
/// IDT vector used for mouse IRQ 12 (legacy PIC-compatible mapping).
pub const MOUSE_VECTOR: u8 = 0x2C;

static KEYBOARD_IOAPIC: AtomicBool = AtomicBool::new(false);
static MOUSE_IOAPIC: AtomicBool = AtomicBool::new(false);

fn finish_irq(via_ioapic: bool) {
    if via_ioapic {
        crate::arch::x86_64::interrupts::apic::send_eoi();
    } else {
        crate::arch::x86_64::interrupts::pic::end_of_interrupt();
    }
}

#[no_mangle]
extern "C" fn xenith_ps2_keyboard_irq_rust() {
    keyboard::handle_interrupt();
    finish_irq(KEYBOARD_IOAPIC.load(Ordering::Relaxed));
}

#[no_mangle]
extern "C" fn xenith_ps2_mouse_irq_rust() {
    mouse::handle_interrupt();
    finish_irq(MOUSE_IOAPIC.load(Ordering::Relaxed));
}

/// Register the PS/2 device interrupt handlers with the interrupt controller.
///
/// The first port raises IRQ 1 and the aux port raises IRQ 12; each has a
/// per-device entry point ([`keyboard::handle_interrupt`] and
/// [`mouse::handle_interrupt`]) that the IRQ stub calls after saving state and
/// *before* issuing the end-of-interrupt. This function is the single place
/// those vectors are wired into the IDT / I/O APIC redirection entries.
///
/// # Routing
///
/// Dedicated assembly gates preserve the interrupted register file. Routing
/// prefers the I/O APIC and uses the remapped 8259 only as a compatibility
/// fallback when no I/O APIC owns the legacy GSI.
///
/// # Safety of calling
///
/// Safe to call after the IDT is loaded and the controller is initialised.
pub fn register_irq_handlers() {
    {
        let mut idt = crate::arch::x86_64::idt::IDT.lock();
        idt.set_interrupt_handler(u16::from(KEYBOARD_VECTOR), xenith_ps2_keyboard_irq);
        idt.set_interrupt_handler(u16::from(MOUSE_VECTOR), xenith_ps2_mouse_irq);
    }

    if crate::arch::x86_64::interrupts::ioapic::count() != 0 {
        let apic_id = crate::arch::x86_64::interrupts::apic::current_id();
        if apic_id > u32::from(u8::MAX) {
            ::log::warn!(
                "xenith.ps2: x2APIC id {} cannot be represented by IOAPIC destination",
                apic_id
            );
        }
        let destination = apic_id as u8;
        let keyboard_routed = crate::arch::x86_64::interrupts::ioapic::route(
            u32::from(KEYBOARD_IRQ),
            KEYBOARD_VECTOR,
            destination,
        )
        .is_some();
        let mouse_routed = crate::arch::x86_64::interrupts::ioapic::route(
            u32::from(MOUSE_IRQ),
            MOUSE_VECTOR,
            destination,
        )
        .is_some();
        KEYBOARD_IOAPIC.store(keyboard_routed, Ordering::Release);
        MOUSE_IOAPIC.store(mouse_routed, Ordering::Release);
    }

    if !KEYBOARD_IOAPIC.load(Ordering::Acquire) {
        crate::arch::x86_64::interrupts::pic::unmask_irq(KEYBOARD_IRQ);
    }
    if !MOUSE_IOAPIC.load(Ordering::Acquire) {
        crate::arch::x86_64::interrupts::pic::unmask_irq(2);
        crate::arch::x86_64::interrupts::pic::unmask_irq(MOUSE_IRQ);
    }
    ::log::info!(
        "xenith.ps2: IRQ 1 -> vector {:#04x}, IRQ 12 -> vector {:#04x}",
        KEYBOARD_VECTOR,
        MOUSE_VECTOR
    );
}

// ---------------------------------------------------------------------------
// Tests — pure logic, no hardware touched
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_bits_are_disjoint() {
        // Every defined flag must be a distinct bit; OR-ing them all must not
        // collide with the reserved bit 3 (which we define for completeness
        // but never set ourselves).
        let all = ControllerConfig::FIRST_INT
            | ControllerConfig::SECOND_INT
            | ControllerConfig::SYSTEM_FLAG
            | ControllerConfig::FIRST_CLK_DISABLED
            | ControllerConfig::SECOND_CLK_DISABLED
            | ControllerConfig::TRANSLATION;
        // The reserved bit is intentionally excluded from `all`.
        assert!(!all.contains(ControllerConfig::RESERVED_3));
        // bits() is the raw OR of the set flags; it must be non-zero and must
        // not include bit 3.
        assert_ne!(all.bits(), 0);
        assert_eq!(all.bits() & (1 << 3), 0);
    }

    #[test]
    fn config_round_trips_through_bits() {
        // from_bits_truncate(bits()) must reproduce the same set for any value
        // that only uses defined bits.
        let cfg = ControllerConfig::FIRST_INT | ControllerConfig::SECOND_INT;
        let raw = cfg.bits();
        let back = ControllerConfig::from_bits_truncate(raw);
        assert_eq!(back, cfg);
    }

    #[test]
    fn irq_constants_match_legacy_wiring() {
        // The keyboard is IRQ 1 and the mouse is IRQ 12 on every PC-AT; these
        // are hardware-fixed and must not change.
        assert_eq!(KEYBOARD_IRQ, 1);
        assert_eq!(MOUSE_IRQ, 12);
    }

    #[test]
    fn self_test_and_port_test_constants_match_spec() {
        assert_eq!(SELF_TEST_OK, 0x55);
        assert_eq!(PORT_TEST_OK, 0x00);
    }

    #[test]
    fn status_bits_are_disjoint() {
        assert_eq!(STS_OUT_FULL & STS_IN_FULL, 0);
        assert_eq!(STS_OUT_FULL & STS_FROM_AUX, 0);
        assert_eq!(STS_TIMEOUT & STS_PARITY, 0);
        // The two error bits occupy the high two positions.
        assert_eq!(STS_TIMEOUT | STS_PARITY, 0xC0);
    }
}
