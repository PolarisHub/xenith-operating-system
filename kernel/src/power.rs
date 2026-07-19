//! Kernel-initiated power control: `poweroff`, `reboot`, and a SysRq-style
//! dispatch hook.
//!
//! This is the top-level power surface the rest of the kernel (syscalls,
//! panic, the shell's `halt`/`reboot` builtins) calls into. It layers the
//! available mechanisms most-portable-first and falls through on any failure,
//! because power commands are the one place a "best effort" must never give
//! up: if ACPI does not cut power we try a hypervisor debug port, and if that
//! does not reset we force a triple fault. Every public entry is `-> !`; the
//! caller may assume control never returns.
//!
//! # Mechanism ordering
//!
//! `poweroff`:
//! 1. **ACPI S5** via [`crate::acpi::shutdown::acpi_shutdown`] — the correct,
//!    portable path on real hardware with a FADT.
//! 2. **QEMU `isa-debug-exit`** (I/O port `0x501`) — a development-only exit
//!    that works under `qemu-system-x86_64 -device isa-debug-exit`. The write
//!    is a benign no-op on bare metal and on hypervisors without the device.
//! 3. **Halt** — mask interrupts and `hlt` forever. The machine stays
//!    running but the kernel is parked; this is the honest last resort when
//!    no hardware path took effect.
//!
//! `reboot`:
//! 1. **ACPI `RESET_REG`** via [`crate::acpi::shutdown::acpi_reset`] — the
//!    FADT-declared reset, typically an 8042 command-port write.
//! 2. **8042 keyboard-controller reset** — write `0xFE` to the command port
//!    `0x64`, which pulses the CPU's reset line. This is the de facto PC
//!    reset and what most bootloaders' "reset" uses.
//! 3. **Triple fault** — load a zero-length IDT and raise an exception. With
//!    no valid handler the CPU double-faults, then triple-faults, and the
//!    platform resets. This works on every x86 implementation, period.
//!
//! # Safety
//!
//! The reset and poweroff stores are real device accesses with side effects
//! (power removal, CPU reset). They are safe to *call* — the worst a stray
//! store can do is reset a machine that was going to reset anyway — so the
//! public functions are safe. The triple-fault path executes `lidt` with a
//! null descriptor, which is `unsafe` in the instruction wrapper and is
//! wrapped here in a safe `-> !` function because its only effect is the
//! intended reset.

use core::arch::asm;

use crate::arch::instructions::{cli, hlt, DescriptorTablePointer};
use crate::arch::Port8;

// ---------------------------------------------------------------------------
// Well-known I/O ports
// ---------------------------------------------------------------------------

/// QEMU `isa-debug-exit` data port.
///
/// A write to this port terminates the QEMU process when launched with
/// `-device isa-debug-exit,iobase=0x501,iosize=0x01`. The exit code is
/// `(value << 1) | 1`, so a zero write yields exit code 1. On bare metal or
/// under a hypervisor without the device the write is a harmless no-op, which
/// is exactly the graceful-degradation property the poweroff fallback wants.
const QEMU_DEBUG_EXIT_PORT: u16 = 0x501;

/// 8042 keyboard-controller command/status port.
///
/// The 8042 exposes a command port at `0x64` and a data port at `0x60`.
/// Writing `0xFE` to the command port pulses the CPU's `-INIT` line, forcing
/// a system reset. This predates ACPI and is the most broadly compatible
/// reset on PC hardware.
const KBC_CMD_PORT: u16 = 0x64;

/// 8042 command: pulse the CPU reset line.
///
/// Bit 0 of the pulse-output command (`0xFE`) selects the reset line; the
/// controller asserts it for its internal cycle and the CPU reboots.
const KBC_RESET_CMD: u8 = 0xFE;

/// 8042 status bit 1: "input buffer full". When set, the controller has not
/// yet consumed the last command byte and a new write would be lost. We poll
/// this before sending the reset command so the `0xFE` is not dropped.
const KBC_STATUS_IBF: u8 = 1 << 1;

/// How many status polls to wait for the 8042 input buffer to drain before
/// giving up and sending the reset command anyway. The controller drains in a
/// few microseconds; 10_000 iterations is a generous bound that still fails
/// fast if the chip is wedged.
const KBC_POLL_LIMIT: u32 = 10_000;

// ---------------------------------------------------------------------------
// Final fallbacks
// ---------------------------------------------------------------------------

/// Mask interrupts and halt the CPU forever.
///
/// This is the terminal state for any power path whose hardware mechanism did
/// not take effect: the kernel is parked, the machine is still powered, but
/// no further code runs. It is also the honest action when no power-off
/// hardware exists at all (e.g. a kernel running under a debugger that traps
/// I/O).
///
/// `cli` first so a timer tick cannot wake us back out of `hlt`; without it,
/// an interrupt between iterations would briefly resume the kernel.
pub fn halt_forever() -> ! {
    ::log::info!("power: halting CPU (no hardware power-off took effect)");
    // SAFETY: `cli` clears EFLAGS.IF in ring 0. It touches no memory and no
    // stack; the only effect is masking external interrupts so the `hlt`
    // below cannot be woken. We do not pass `preserves_flags` because `cli`
    // modifies EFLAGS.IF.
    unsafe {
        cli();
    }
    loop {
        // `hlt` is a safe wrapper (the unsafe `asm!` is internal to
        // `instructions::hlt`); with interrupts disabled above it is a
        // permanent park — no interrupt can wake the core back out.
        hlt();
    }
}

/// Force a CPU reset by triple-faulting.
///
/// Loads a zero-length IDT (limit 0, base 0) and then executes `ud2`, which
/// raises an invalid-opcode exception. Because the IDT reports no handlers,
/// the exception becomes a double fault, and the double fault — also
/// unhandled — becomes a triple fault. The processor's documented response to
/// a triple fault is to assert RESET, rebooting the platform.
///
/// This is the most portable reset on x86: it depends only on the CPU, not on
/// any chipset, controller, or firmware table, so it works whenever control
/// reaches this function.
pub fn triple_fault() -> ! {
    ::log::info!("power: forcing triple-fault reset");
    // A zero-length IDT: any interrupt/exception delivery consults the IDT,
    // finds `limit = 0` (no valid entries), and raises a double fault; the
    // double fault does the same and becomes a triple fault → RESET.
    let null_idt = DescriptorTablePointer::new(0, 0);
    // SAFETY: `lidt` loads the IDT register. Loading a zero-length table is
    // explicitly permitted by the architecture; the unsafe contract is only
    // "the operand points at a valid pseudo-descriptor", which a stack local
    // satisfies. The subsequent `ud2` deliberately triggers the fault chain.
    unsafe {
        crate::arch::x86_64::lidt(&null_idt);
        // `ud2` is guaranteed to raise #UD on every x86_64 part. With the null
        // IDT above, delivery triple-faults and resets the machine.
        asm!("ud2", options(nostack, nomem, preserves_flags));
    }
    // Unreachable: `ud2` does not return (it raises #UD), and even if the
    // compiler could not prove that, the null IDT makes the fault path
    // reset-only. The marker is here for the type system.
    #[allow(unreachable_code)]
    {
        loop {
            // `hlt` is safe; interrupts are irrelevant once the IDT is null,
            // but halting keeps the core in a defined state if the triple
            // fault somehow did not reset.
            hlt();
        }
    }
}

// ---------------------------------------------------------------------------
// Power off
// ---------------------------------------------------------------------------

/// Power the machine off.
///
/// Tries ACPI S5 first; if ACPI is unavailable or the PM1 write does not cut
/// power, tries the QEMU debug-exit port; if that too is a no-op, parks the
/// CPU with [`halt_forever`]. Never returns.
pub fn poweroff() -> ! {
    ::log::info!("power: poweroff requested");

    // 1. ACPI S5. On real hardware with a parsed FADT this is the path that
    //    actually removes power; `acpi_shutdown` returns Ok after writing
    //    PM1a/b, so reaching the fallback means the firmware did not honor
    //    the write (or no FADT was registered).
    if let Err(e) = crate::acpi::shutdown::acpi_shutdown() {
        ::log::debug!("power: ACPI S5 unavailable ({e:?}); trying fallbacks");
    }

    // 2. QEMU isa-debug-exit. A single byte write; harmless where the device
    //    is absent. We write 0 so the QEMU exit code is `(0 << 1) | 1 = 1`,
    //    the conventional "clean shutdown" sentinel in Xenith's test harness.
    Port8::new(QEMU_DEBUG_EXIT_PORT).write(0);

    // 3. No hardware path worked. Park the core rather than return into a
    //    caller that expected the machine to be off.
    halt_forever();
}

// ---------------------------------------------------------------------------
// Reboot
// ---------------------------------------------------------------------------

/// Reset the machine.
///
/// Tries the FADT `RESET_REG` first, then the 8042 keyboard-controller
/// reset, then a triple fault. Never returns.
pub fn reboot() -> ! {
    ::log::info!("power: reboot requested");

    // 1. ACPI RESET_REG. Typically an 8042 command-port write declared in
    //    the FADT; if the GAS names a space we do not drive, fall through.
    if let Err(e) = crate::acpi::shutdown::acpi_reset() {
        ::log::debug!("power: ACPI reset unavailable ({e:?}); trying 8042");
    }

    // 2. 8042 keyboard-controller reset. Wait for the input buffer to drain
    //    so the command byte is not lost, then send 0xFE. A wedged or absent
    //    controller (some virtual platforms omit it) just makes us fall
    //    through to the triple fault below.
    kbc_reset();

    // 3. The universal last resort: triple-fault the CPU into RESET.
    triple_fault();
}

/// Send the 8042 reset command, with a bounded input-buffer drain first.
///
/// Polling the status port is the documented precondition for writing a
/// command: if the input buffer is full the controller drops the byte and the
/// reset never happens. We poll up to [`KBC_POLL_LIMIT`] times, then send the
/// command regardless — a wedged controller should not prevent the triple
/// fault fallback from running, and sending into a full buffer is harmless.
fn kbc_reset() {
    let cmd = Port8::new(KBC_CMD_PORT);
    let status = Port8::new(KBC_CMD_PORT);
    for _ in 0..KBC_POLL_LIMIT {
        // Bit 1 set means "input buffer full" — the controller has not yet
        // consumed the previous byte. Wait until it clears.
        if status.read() & KBC_STATUS_IBF == 0 {
            break;
        }
        // A brief pause between polls: `pause` yields the core to a sibling
        // hyperthread and costs nothing on bare metal, where the loop body
        // is already just a port read.
        crate::arch::x86_64::pause();
    }
    ::log::debug!("power: writing 0xFE to 8042 command port");
    cmd.write(KBC_RESET_CMD);
    // Give the controller a cycle to assert reset before we fall through to
    // the triple fault. One dummy write to the POST debug port is the
    // canonical ~1us ISA-bus delay.
    crate::arch::x86_64::port::io_wait();
}

// ---------------------------------------------------------------------------
// SysRq-style hook
// ---------------------------------------------------------------------------

/// Magic-SysRq-style dispatch, mirroring Linux's `sysrq` letter commands.
///
/// The kernel's keyboard driver (and any other input source) funnels a single
/// byte through here when a SysRq sequence is recognised. Recognised letters:
///
/// | Letter | Action |
/// |--------|--------|
/// | `o` / `O` | [`poweroff`] |
/// | `b` / `B` | [`reboot`] |
/// | `h` / `H` | [`halt_forever`] |
///
/// Any other byte is logged and ignored, so the hook is safe to wire into a
/// generic input path without filtering upstream. The three action letters
/// diverge (`-> !`); the ignore case returns normally.
pub fn sysrq(cmd: u8) {
    match cmd {
        b'o' | b'O' => poweroff(),
        b'b' | b'B' => reboot(),
        b'h' | b'H' => halt_forever(),
        other => {
            ::log::debug!("power: ignoring unknown sysrq 0x{other:02x}");
        },
    }
}
