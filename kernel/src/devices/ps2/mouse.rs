//! PS/2 mouse driver: Intellimouse 4-byte packet mode, IRQ 12 delivery.
//!
//! The PC's auxiliary PS/2 port (the second channel of the 8042 keyboard
//! controller) is wired to IRQ 12 and carries a stream-mode mouse. This module
//! brings the device up, negotiates the Microsoft Intellimouse extension so the
//! mouse emits 4-byte packets with a scroll axis (Z) and two extra buttons,
//! decodes the movement/button stream, and exposes the resulting
//! [`MouseEvent`]s through a bounded ring buffer.
//!
//! # Bring-up sequence
//!
//! [`init`] runs the canonical PS/2 mouse enablement, touching only the
//! controller's *second-port* configuration bits and the auxiliary enable /
//! write-aux commands so it never disturbs the first-port keyboard (owned by
//! the sibling `keyboard` module). The sequence is:
//!
//! 1. Disable the auxiliary port (`0xA7`) to quiesce any in-flight data.
//! 2. Read the controller configuration byte (`0x20`) and set the second-port
//!    interrupt bit while clearing the second-port disable bit, preserving the
//!    keyboard bits untouched.
//! 3. Enable the auxiliary port (`0xA8`).
//! 4. Reset the mouse (`0xFF`), expecting `ACK`, self-test-passed (`0xAA`),
//!    and a plain-mouse ID (`0x00`).
//! 5. Set defaults (`0xF6`), 1:1 scaling (`0xE6`), resolution 1 count/mm
//!    (`0xE8 0x00`), sample rate 60 Hz (`0xF3 0x3C`).
//! 6. Negotiate the Intellimouse extension: set sample rate 200, 100, 80 in
//!    sequence then read the device ID. An ID of `0x03` means the mouse now
//!    emits 4-byte packets; otherwise it stays a 3-byte mouse and the scroll
//!    axis is reported as zero.
//! 7. Enable data reporting (`0xF4`) so the mouse starts streaming packets.
//!
//! # Packet format
//!
//! A 3-byte packet is `[flags, dx, dy]`; a 4-byte packet appends a `[zflags]`
//! byte. The flags byte carries the three primary buttons, the always-set
//! synchronisation bit (bit 3), the 9th sign bit for each axis, and an overflow
//! bit per axis. The fourth byte packs a 4-bit signed Z delta and the back /
//! forward buttons. Y is reported with the mouse's "up" positive, which is the
//! opposite of screen coordinates, so [`decode_packet`] negates `dy`.
//!
//! # Interrupt handling
//!
//! IRQ 12 is the mouse's line. [`handle_interrupt`] is the per-device handler
//! the IRQ-12 stub calls after the CPU has saved state and *before* the stub
//! issues the end-of-interrupt; it does not send EOI itself, so the interrupt
//! controller driver retains sole ownership of the EOI path. The handler reads
//! the status register, confirms the pending byte came from the auxiliary port
//! (bit 5), reads it from `0x60`, feeds it to the [`PacketDecoder`] state
//! machine, and pushes any completed [`MouseEvent`] onto the event ring.
//!
//! # Synchronisation
//!
//! The packet decoder and event ring live behind a [`SpinLockIRQ`]: the IRQ
//! handler and process-context readers/writers (init, [`pop_event`]) share the
//! same state, so disabling interrupts around the critical section prevents the
//! handler from re-entering against itself or against a process-context access.
//! The handler itself runs with interrupts already cleared by the CPU, so
//! acquiring the lock is a no-op interrupt-wise and cannot self-deadlock.
//!
//! # Controller command helpers
//!
//! The 8042 command protocol (write `0x64`, wait, write/read `0x60`, wait) is
//! implemented here as private helpers because the shared `ps2::controller`
//! module does not exist on disk yet. When it lands, these helpers move
//! wholesale into it and this file calls `controller::send_aux(...)` etc.; the
//! mouse logic above them is unchanged.

use xenith_bitflags::bitflags;

use crate::arch::x86_64::port::{io_wait, Port8};
use crate::sync::SpinLockIRQ;
use crate::util::RingBuffer;

// ---------------------------------------------------------------------------
// 8042 controller I/O ports and register bits
// ---------------------------------------------------------------------------

/// Controller status register (read) / command register (write) at I/O 0x64.
const CTRL_CMD: Port8 = Port8::new(0x64);
/// Controller data register at I/O 0x60: output buffer on reads, input buffer
/// on writes (the byte that follows a command written to `0x64`).
const CTRL_DATA: Port8 = Port8::new(0x60);

/// Status bit 0: output buffer full — a byte is waiting to be read from `0x60`.
const STS_OUT_FULL: u8 = 1 << 0;
/// Status bit 1: input buffer full — the controller is not ready for a write.
const STS_IN_FULL: u8 = 1 << 1;
/// Status bit 5: the pending output byte came from the auxiliary (mouse) port.
const STS_FROM_AUX: u8 = 1 << 5;
/// Status bit 6: a write timed out (no device ACK within the controller window).
const STS_TIMEOUT: u8 = 1 << 6;
/// Status bit 7: a parity error was detected on the last byte received.
const STS_PARITY: u8 = 1 << 7;

// Controller commands written to `0x64`.
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_AUX: u8 = 0xA7;
const CMD_ENABLE_AUX: u8 = 0xA8;
/// "Next byte written to `0x60` is for the auxiliary device." Must precede
/// every single byte sent to the mouse.
const CMD_WRITE_AUX: u8 = 0xD4;

// Controller configuration byte bits. Only the two second-port bits are
// manipulated here; the full layout is documented for reference:
//   bit 0 first-port interrupt enable   (keyboard-owned, preserved)
//   bit 1 second-port interrupt enable   (set by this driver)
//   bit 2 system flag                    (read-only, ignored)
//   bit 4 second-port clock disabled     (left clear)
//   bit 5 second-port disabled           (cleared by this driver)
//   bit 6 first-port translation         (keyboard-owned, preserved)
const CFG_SECOND_INT: u8 = 1 << 1;
const CFG_DISABLE_SECOND: u8 = 1 << 5;

// Mouse (auxiliary) command bytes, each sent as `CMD_WRITE_AUX` + the byte.
const MOUSE_RESET: u8 = 0xFF;
const MOUSE_SET_DEFAULTS: u8 = 0xF6;
const MOUSE_ENABLE_REPORTING: u8 = 0xF4;
const MOUSE_SET_SAMPLE_RATE: u8 = 0xF3;
const MOUSE_GET_ID: u8 = 0xF2;
const MOUSE_SET_RESOLUTION: u8 = 0xE8;
const MOUSE_SCALING_1_1: u8 = 0xE6;

/// Universal mouse ACK for every accepted command.
const ACK: u8 = 0xFA;
/// Self-test passed byte returned after a reset.
const SELF_TEST_PASSED: u8 = 0xAA;
/// Device ID for a plain (3-byte) PS/2 mouse.
const ID_STANDARD: u8 = 0x00;
/// Device ID for an Intellimouse (4-byte packets with Z + extra buttons).
const ID_INTELLIMOUSE: u8 = 0x03;

/// Poll iterations before a port wait gives up. Each iteration issues a
/// status-register read (~1 us) plus an [`io_wait`] cycle (~1 us), so the
/// bound is roughly 2 us per iteration. 200k iterations gives ~400 ms, which
/// covers a real mouse's reset self-test window (~300-350 ms for the 0xAA
/// reply) while still failing fast on a wedged controller instead of hanging
/// the boot. Fast ACK replies complete in well under this bound.
const POLL_LIMIT: u32 = 200_000;

/// Sample rate (Hz) used for the final operating mode. 60 Hz is a quiet,
/// responsive default that keeps the IRQ rate modest while feeling immediate.
const SAMPLE_RATE: u8 = 60;
/// The magic sample-rate triplet that flips a compliant mouse into Intellimouse
/// 4-byte mode. The controller must send each as a distinct SET_SAMPLE_RATE
/// command; the mouse counts the sequence and switches its ID on the third.
const SCROLL_MAGIC_RATES: [u8; 3] = [200, 100, 80];

// ---------------------------------------------------------------------------
// Packet field masks (byte 0 and byte 3 of a movement packet)
// ---------------------------------------------------------------------------

const BTN_LEFT_BIT: u8 = 1 << 0;
const BTN_RIGHT_BIT: u8 = 1 << 1;
const BTN_MIDDLE_BIT: u8 = 1 << 2;
/// Always-1 bit in byte 0; used to re-synchronise a desynchronised stream.
const SYNC_BIT: u8 = 1 << 3;
const X_SIGN_BIT: u8 = 1 << 4;
const Y_SIGN_BIT: u8 = 1 << 5;
const X_OVERFLOW_BIT: u8 = 1 << 6;
const Y_OVERFLOW_BIT: u8 = 1 << 7;

/// Low nibble of byte 3 holds the 4-bit signed Z (scroll) delta.
const Z_MASK: u8 = 0x0F;
/// Bit 3 of byte 3 is the sign bit of the Z nibble.
const Z_SIGN_BIT: u8 = 1 << 3;
/// Bit 4 of byte 3: back / "4th" mouse button.
const BTN_BACK_BIT: u8 = 1 << 4;
/// Bit 5 of byte 3: forward / "5th" mouse button.
const BTN_FORWARD_BIT: u8 = 1 << 5;

/// Capacity of the completed-event ring. The producer is the IRQ handler and
/// the consumer is whatever drains events (input layer, userspace read). A
/// modest bound drops the oldest movement under sustained burst pressure
/// rather than blocking the IRQ handler, which must never spin waiting on a
/// consumer.
const EVENT_QUEUE_CAP: usize = 64;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A hand-rolled error type for PS/2 mouse bring-up and command transport.
///
/// There is no `thiserror` in `no_std`, so the variants are plain and the
/// `Debug` derive is enough for the `log` facade to render them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2MouseError {
    /// A port poll exceeded [`POLL_LIMIT`] — the controller is not responding,
    /// typically because the device is absent or the bus is wedged.
    Timeout,
    /// The mouse returned a byte other than `ACK` (or the expected self-test /
    /// ID sequence) in response to a command.
    BadAck,
    /// The controller's status register reported a parity or timeout error on
    /// the last transaction.
    BusError,
    /// The mouse self-test did not report `0xAA` after reset.
    SelfTestFailed,
    /// The Intellimouse negotiation did not yield ID `0x03`; the mouse is
    /// usable but stays in 3-byte mode (no scroll axis).
    ScrollUnsupported,
}

// ---------------------------------------------------------------------------
// Button flags
// ---------------------------------------------------------------------------

bitflags! {
    /// The set of mouse buttons reported in a [`MouseEvent`].
    ///
    /// The primary three (left/right/middle) come from packet byte 0; the
    /// back/forward pair comes from byte 3 of a 4-byte packet and is empty for
    /// a 3-byte mouse. Using a bitflags type lets consumers test combinations
    /// (`btn.contains(MouseButtons::LEFT | MouseButtons::RIGHT)`) without
    /// caring which physical bit each button maps to.
    pub struct MouseButtons: u8 {
        /// Left button (packet byte 0, bit 0).
        const LEFT = BTN_LEFT_BIT;
        /// Right button (packet byte 0, bit 1).
        const RIGHT = BTN_RIGHT_BIT;
        /// Middle button / scroll-wheel click (packet byte 0, bit 2).
        const MIDDLE = BTN_MIDDLE_BIT;
        /// Back / "4th" button (packet byte 3, bit 4 — Intellimouse only).
        const BACK = BTN_BACK_BIT;
        /// Forward / "5th" button (packet byte 3, bit 5 — Intellimouse only).
        const FORWARD = BTN_FORWARD_BIT;
    }
}

// ---------------------------------------------------------------------------
// MouseEvent
// ---------------------------------------------------------------------------

/// One decoded mouse movement sample.
///
/// `dx`/`dy` are in mouse counts (the device's native resolution, 1 count/mm
/// at the configured resolution) with screen-orientation Y: positive `dy` is
/// *down*, i.e. the raw mouse Y has already been negated. `dz` is the scroll
/// wheel delta in notches; positive is scroll-up, negative is scroll-down, and
/// it is zero for a 3-byte mouse that lacks the Intellimouse extension.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MouseEvent {
    /// Button state at this sample. A bit is set for as long as the button is
    /// held; the consumer derives edge transitions by diffing consecutive
    /// events.
    pub buttons: MouseButtons,
    /// Horizontal movement in counts; positive is right.
    pub dx: i16,
    /// Vertical movement in counts; positive is down (screen orientation).
    pub dy: i16,
    /// Scroll-wheel movement in notches; positive is up. Zero when the mouse
    /// is in 3-byte mode.
    pub dz: i8,
}

// ---------------------------------------------------------------------------
// Packet decoder state machine
// ---------------------------------------------------------------------------

/// Reassembles a movement packet from the byte stream delivered by IRQ 12.
///
/// The mouse emits one packet per movement sample. Each packet starts with a
/// byte whose bit 3 ([`SYNC_BIT`]) is always set; a byte without that bit, at
/// the start-of-packet position, means the stream has slipped (a byte was lost
/// or an extra one inserted) and the decoder drops it and waits for the next
/// candidate sync byte. Once `packet_len` bytes are accumulated the decoder
/// hands them to [`decode_packet`] and returns the resulting event.
#[derive(Debug)]
struct PacketDecoder {
    /// Accumulated packet bytes.
    bytes: [u8; 4],
    /// Index of the next byte to fill within `bytes`.
    index: usize,
    /// Whether the mouse is in Intellimouse 4-byte mode (vs. plain 3-byte).
    four_byte: bool,
}

impl PacketDecoder {
    /// Compile-time-constructible empty decoder. Starts in 3-byte mode; the
    /// init sequence flips `four_byte` on after the Intellimouse ID check.
    const fn new() -> Self {
        Self {
            bytes: [0; 4],
            index: 0,
            four_byte: false,
        }
    }

    /// Expected bytes per packet: 4 in Intellimouse mode, 3 otherwise.
    #[inline]
    const fn packet_len(&self) -> usize {
        if self.four_byte {
            4
        } else {
            3
        }
    }

    /// Absorb one byte from the IRQ handler.
    ///
    /// Returns `Some(event)` when a full packet has been assembled and decoded,
    /// or `None` if more bytes are needed, the byte was a dropped resync, or
    /// the completed packet had an axis-overflow and was discarded.
    fn feed(&mut self, byte: u8) -> Option<MouseEvent> {
        if self.index == 0 {
            // Start-of-packet position: the byte must carry the always-set
            // sync bit. If it does not, the stream is misaligned (we either
            // lost a byte or gained a spurious one); drop this byte and keep
            // waiting for a real header rather than locking onto garbage.
            if byte & SYNC_BIT == 0 {
                return None;
            }
            self.bytes[0] = byte;
            self.index = 1;
            return None;
        }
        // Mid-packet data byte: there is no sync check on these, so a single
        // dropped data byte corrupts the current packet. That is detected at
        // decode time only if an overflow bit is also wrong; the practical
        // impact is one bad sample, after which the next header's sync bit
        // realigns the stream.
        self.bytes[self.index] = byte;
        self.index += 1;
        if self.index < self.packet_len() {
            return None;
        }
        // Full packet accumulated: reset the index first so a decode error
        // (overflow drop) leaves the decoder ready for the next header, then
        // decode.
        self.index = 0;
        decode_packet(&self.bytes, self.four_byte)
    }
}

/// Sign-extend a movement byte to a 9-bit signed value.
///
/// The low 8 bits live in the data byte; the 9th (sign) bit is the per-axis
/// bit in the header. When the sign bit is set the value is negative, with a
/// range of `-256..=-1` for the set-sign case and `0..=255` otherwise. We
/// express the extension as a subtract of 256, which is exact and avoids any
/// bitwise reinterpretation that would obscure the intent.
#[inline]
fn sign_extend_9(sign_set: bool, low: u8) -> i16 {
    let v = i16::from(low);
    if sign_set {
        v - 256
    } else {
        v
    }
}

/// Sign-extend a 4-bit Z nibble to a signed 8-bit value.
///
/// Bit 3 of the nibble is the sign; when set the value is `-8..=-1`, otherwise
/// `0..=7`. As with the axes, the subtraction form is exact and readable.
#[inline]
fn sign_extend_4(nibble: u8) -> i8 {
    let v = nibble as i8;
    if nibble & Z_SIGN_BIT != 0 {
        v - 16
    } else {
        v
    }
}

/// Decode a complete packet into a [`MouseEvent`], or `None` if it should be
/// dropped.
///
/// Packets with either axis overflow bit set are discarded: the mouse sets
/// overflow when movement exceeds the 9-bit range in one sample, and the
/// reported deltas are clamped to the sign rather than the true magnitude, so
/// forwarding them would produce a wrong-direction jump. Dropping the single
/// sample is the conventional behaviour and the user perceives at most a
/// momentary under-report during very fast motion.
fn decode_packet(bytes: &[u8], four_byte: bool) -> Option<MouseEvent> {
    let flags = bytes[0];

    // Overflow: discard the packet entirely (see function docs).
    if flags & (X_OVERFLOW_BIT | Y_OVERFLOW_BIT) != 0 {
        return None;
    }

    // Primary three buttons live in the low three bits of byte 0.
    let mut buttons =
        MouseButtons::from_bits_truncate(flags & (BTN_LEFT_BIT | BTN_RIGHT_BIT | BTN_MIDDLE_BIT));

    let dx = sign_extend_9(flags & X_SIGN_BIT != 0, bytes[1]);
    // Y is inverted to screen orientation: the mouse reports "up" as positive,
    // but screen coordinates grow downward, so we negate the decoded value.
    let dy = -sign_extend_9(flags & Y_SIGN_BIT != 0, bytes[2]);

    let mut dz: i8 = 0;
    if four_byte {
        let zbyte = bytes[3];
        dz = sign_extend_4(zbyte & Z_MASK);
        if zbyte & BTN_BACK_BIT != 0 {
            buttons.insert(MouseButtons::BACK);
        }
        if zbyte & BTN_FORWARD_BIT != 0 {
            buttons.insert(MouseButtons::FORWARD);
        }
    }

    Some(MouseEvent {
        buttons,
        dx,
        dy,
        dz,
    })
}

// ---------------------------------------------------------------------------
// 8042 controller command helpers
// ---------------------------------------------------------------------------
//
// These are private to the mouse module because the shared `ps2::controller`
// abstraction has not landed yet (see the module-level docs). They are the
// minimum protocol surface the mouse needs: wait for the input buffer to
// drain, wait for the output buffer to fill, send a controller command, send a
// byte to the mouse, and read a mouse reply. When `controller` lands, the
// bodies here move there and the mouse calls through its public API.

/// Spin until the controller's input buffer is empty, i.e. it is ready to
/// accept a write to `0x64` or `0x60`.
fn wait_in_empty() -> Result<(), Ps2MouseError> {
    for _ in 0..POLL_LIMIT {
        if CTRL_CMD.read() & STS_IN_FULL == 0 {
            return Ok(());
        }
        io_wait();
    }
    Err(Ps2MouseError::Timeout)
}

/// Spin until the controller's output buffer is full, i.e. a byte is waiting
/// to be read from `0x60`. Returns a bus error if the status register reports
/// a timeout or parity fault instead.
fn wait_out_full() -> Result<(), Ps2MouseError> {
    for _ in 0..POLL_LIMIT {
        let sts = CTRL_CMD.read();
        if sts & STS_OUT_FULL != 0 {
            if sts & (STS_TIMEOUT | STS_PARITY) != 0 {
                return Err(Ps2MouseError::BusError);
            }
            return Ok(());
        }
        io_wait();
    }
    Err(Ps2MouseError::Timeout)
}

/// Send a controller command byte to `0x64` (no data phase).
fn controller_cmd(cmd: u8) -> Result<(), Ps2MouseError> {
    wait_in_empty()?;
    CTRL_CMD.write(cmd);
    io_wait();
    Ok(())
}

/// Read one byte from the controller's output buffer (`0x60`), waiting for it
/// to be ready first.
fn read_data() -> Result<u8, Ps2MouseError> {
    wait_out_full()?;
    Ok(CTRL_DATA.read())
}

/// Write one byte to the controller's input buffer (`0x60`), waiting for the
/// input buffer to drain first. Used for the data phase of commands like
/// `CMD_WRITE_CONFIG` and for bytes forwarded to the mouse after
/// `CMD_WRITE_AUX`.
fn write_data(byte: u8) -> Result<(), Ps2MouseError> {
    wait_in_empty()?;
    CTRL_DATA.write(byte);
    io_wait();
    Ok(())
}

/// Send one byte to the mouse: `CMD_WRITE_AUX` to `0x64`, then the byte to
/// `0x60`, then read and verify the mouse's ACK. Every byte destined for the
/// mouse needs its own `CMD_WRITE_AUX` prefix — the controller forwards only
/// the single byte immediately following the prefix.
fn mouse_write(byte: u8) -> Result<(), Ps2MouseError> {
    controller_cmd(CMD_WRITE_AUX)?;
    write_data(byte)?;
    let ack = read_data()?;
    if ack != ACK {
        return Err(Ps2MouseError::BadAck);
    }
    Ok(())
}

/// Read the device ID after a command that produces one. The mouse ACKs the
/// command (handled by the caller via [`mouse_write`]) and then sends the ID
/// byte on its own, so this is just a buffered read.
fn read_mouse_id() -> Result<u8, Ps2MouseError> {
    read_data()
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// The IRQ-handler / process-context shared state, protected by
/// [`SpinLockIRQ`] so the handler cannot re-enter against a reader or the init
/// path.
struct MouseState {
    decoder: PacketDecoder,
    events: RingBuffer<MouseEvent, EVENT_QUEUE_CAP>,
    /// `true` once [`init`] has succeeded; the handler ignores bytes before
    /// this is set so a stray IRQ 12 during bring-up cannot corrupt the
    /// decoder with a partial controller response.
    initialized: bool,
}

impl MouseState {
    /// Const-constructible empty state for the static initializer.
    const fn new() -> Self {
        Self {
            decoder: PacketDecoder::new(),
            events: RingBuffer::new(),
            initialized: false,
        }
    }
}

/// The single PS/2 mouse. There is at most one auxiliary port per PC, so a
/// global is appropriate and matches the rest of the device layer (e.g. the
/// serial `COM1`).
static MOUSE: SpinLockIRQ<MouseState> = SpinLockIRQ::new(MouseState::new());

// ---------------------------------------------------------------------------
// Public initialisation
// ---------------------------------------------------------------------------

/// Bring up the PS/2 mouse and enable Intellimouse 4-byte streaming.
///
/// Runs with maskable interrupts disabled by the caller (the boot sequence
/// invokes it before `sti`, and the controller command protocol is not
/// re-entrant). On success the mouse is streaming packets into IRQ 12 and the
/// decoder is armed; on error the mouse is left disabled and the caller can
/// decide whether to continue without a pointer.
pub fn init() -> Result<(), Ps2MouseError> {
    // 1. Disable the auxiliary port so any in-flight mouse data is dropped
    //    while we reconfigure the controller. This does not touch the keyboard
    //    port.
    controller_cmd(CMD_DISABLE_AUX)?;

    // 2. Read-modify-write the configuration byte, setting only the second-
    //    port interrupt bit and clearing the second-port disable bit. The
    //    first-port interrupt and translation bits (owned by the keyboard
    //    driver) are preserved verbatim.
    controller_cmd(CMD_READ_CONFIG)?;
    let mut config = read_data()?;
    config |= CFG_SECOND_INT;
    config &= !CFG_DISABLE_SECOND;
    controller_cmd(CMD_WRITE_CONFIG)?;
    write_data(config)?;

    // 3. Re-enable the auxiliary port now that the interrupt is routed.
    controller_cmd(CMD_ENABLE_AUX)?;

    // 4. Reset the mouse. The response is ACK, then 0xAA (self-test passed),
    //    then the ID byte (0x00 for a plain mouse). We consume all three.
    mouse_write(MOUSE_RESET)?;
    if read_data()? != SELF_TEST_PASSED {
        return Err(Ps2MouseError::SelfTestFailed);
    }
    let _initial_id = read_data()?;

    // 5. Defaults, 1:1 scaling, resolution 1 count/mm, then the scroll-wheel
    //    negotiation triplet. Every byte to the mouse — including command
    //    arguments — is preceded by `CMD_WRITE_AUX` and acknowledged, so the
    //    rate / resolution arguments go through `mouse_write` just like the
    //    command bytes themselves.
    mouse_write(MOUSE_SET_DEFAULTS)?;
    mouse_write(MOUSE_SCALING_1_1)?;
    mouse_write(MOUSE_SET_RESOLUTION)?;
    mouse_write(0x00)?;

    // 6. The Intellimouse magic: set sample rate 200, 100, 80 in sequence, then
    //    read the ID. A compliant mouse flips to 4-byte mode and returns 0x03.
    //    If it returns 0x00 we keep 3-byte mode and proceed without a scroll
    //    axis (reported as dz == 0). The triplet must be exact; a mouse that
    //    does not understand it simply ignores the sequence.
    let mut four_byte = false;
    for rate in SCROLL_MAGIC_RATES {
        mouse_write(MOUSE_SET_SAMPLE_RATE)?;
        mouse_write(rate)?;
    }
    mouse_write(MOUSE_GET_ID)?;
    let id = read_mouse_id()?;
    if id == ID_INTELLIMOUSE {
        four_byte = true;
    } else if id != ID_STANDARD {
        // An unexpected ID is not fatal: treat as a standard 3-byte mouse so
        // the user still gets a pointer, just without scroll.
        ::log::warn!(
            "xenith.ps2.mouse: unexpected device ID 0x{:02x}, assuming 3-byte mode",
            id
        );
    }

    // 7. Final operating-mode sample rate (60 Hz). Done after the magic
    //    triplet so the negotiation is not disturbed by a stray rate change.
    mouse_write(MOUSE_SET_SAMPLE_RATE)?;
    mouse_write(SAMPLE_RATE)?;

    // 8. Enable data reporting. From here the mouse streams a packet on every
    //    movement/button change and each one raises IRQ 12.
    mouse_write(MOUSE_ENABLE_REPORTING)?;

    // Publish the mode and mark the device ready so the handler starts
    // accepting bytes. The decoder's four_byte flag is set under the lock so
    // the handler observes a consistent (initialized, four_byte) pair.
    {
        let mut state = MOUSE.lock();
        state.decoder.four_byte = four_byte;
        state.initialized = true;
    }

    ::log::info!(
        "xenith.ps2.mouse: initialised ({}-byte packets, sample rate {} Hz)",
        if four_byte { 4 } else { 3 },
        SAMPLE_RATE
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// IRQ 12 handler
// ---------------------------------------------------------------------------

/// PS/2 mouse interrupt handler, invoked by the IRQ-12 stub.
///
/// Reads one byte from the controller's output buffer (if it carries a
/// mouse-origin byte), feeds it to the decoder, and enqueues any completed
/// [`MouseEvent`]. Does **not** send end-of-interrupt: the caller owns the EOI
/// path so the interrupt-controller driver keeps a single, consistent EOI
/// surface.
///
/// Safe to call with interrupts already disabled (the normal IRQ-entry state)
/// and re-entrant-safe by virtue of the [`SpinLockIRQ`] around the shared
/// state. If the device has not been initialised the handler drains and
/// discards the byte so a spurious IRQ 12 during bring-up does not leave the
/// controller's output buffer full and de-assert the line.
pub fn handle_interrupt() {
    let sts = CTRL_CMD.read();
    if sts & STS_OUT_FULL == 0 {
        // Nothing pending — the IRQ was spurious or already serviced. Let the
        // caller EOI and return.
        return;
    }
    // Only consume the byte if it came from the auxiliary port. If the AUX bit
    // is clear the byte is from the keyboard port and belongs to the keyboard
    // handler; leaving it lets that handler pick it up on its own IRQ.
    if sts & STS_FROM_AUX == 0 {
        return;
    }
    let byte = CTRL_DATA.read();

    let (epoch, event) = {
        let mut state = MOUSE.lock();
        if !state.initialized {
            // Pre-init byte (e.g. a controller response that arrived late):
            // drop it so the decoder never sees non-movement data.
            return;
        }
        let epoch = crate::ui::input_epoch();
        (epoch, state.decoder.feed(byte))
    };
    if let Some(event) = event {
        crate::ui::route_mouse_event(epoch, event);
    }
}

/// Queue a decoded sample for the kernel device path.
///
/// The UI router calls this while holding its epoch lock so acquiring a new
/// graphical input session cannot race a late device-queue insertion.
pub(crate) fn enqueue_device_event(event: MouseEvent) {
    let _ = MOUSE.lock().events.push(event);
}

// ---------------------------------------------------------------------------
// Public consumer API
// ---------------------------------------------------------------------------

/// Pop the oldest buffered [`MouseEvent`], or `None` if the queue is empty.
///
/// Intended for the input layer or a userspace read path. Acquires the
/// IRQ-safe lock so a concurrent IRQ 12 cannot mutate the ring mid-pop.
pub fn pop_event() -> Option<MouseEvent> {
    MOUSE.lock().events.pop()
}

/// Discard queued pointer samples without resetting packet/device state.
pub(crate) fn clear_events() {
    let mut state = MOUSE.lock();
    state.events.clear();
    state.decoder.index = 0;
}

/// Whether the mouse is emitting 4-byte Intellimouse packets (scroll axis
/// active). `false` until [`init`] completes and `false` for a mouse that did
/// not accept the Intellimouse negotiation.
pub fn is_four_byte() -> bool {
    MOUSE.lock().decoder.four_byte
}

/// Whether [`init`] has completed and the handler is accepting bytes.
pub fn is_initialized() -> bool {
    MOUSE.lock().initialized
}

/// Force the byte-stream decoder back to the start-of-packet state.
///
/// Useful if a consumer observes corrupted motion and wants to resync without
/// re-running bring-up. The next byte must carry [`SYNC_BIT`] to be accepted as
/// a header.
pub fn resync() {
    MOUSE.lock().decoder.index = 0;
}

// ---------------------------------------------------------------------------
// Tests — pure decode logic, no hardware touched
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal right-and-down 3-byte packet with no buttons.
    #[test]
    fn decode_3byte_plain_motion() {
        // flags: sync bit only; dx = 5; dy = 3 (raw, before inversion).
        let bytes = [SYNC_BIT, 5, 3];
        let ev = decode_packet(&bytes, false).expect("plain packet decodes");
        assert_eq!(ev.dx, 5);
        assert_eq!(ev.dy, -3, "Y must be negated to screen orientation");
        assert_eq!(ev.dz, 0, "no Z in 3-byte mode");
        assert!(ev.buttons.is_empty());
    }

    /// Left button held, negative X (leftward) using the 9-bit sign bit.
    #[test]
    fn decode_3byte_negative_x_with_sign() {
        // flags: left button + sync + X sign bit; dx = 0xFE (254 -> -2 with sign).
        let flags = BTN_LEFT_BIT | SYNC_BIT | X_SIGN_BIT;
        let bytes = [flags, 0xFE, 0];
        let ev = decode_packet(&bytes, false).expect("signed packet decodes");
        assert_eq!(ev.dx, -2, "0xFE with X_SIGN must sign-extend to -2");
        assert!(ev.buttons.contains(MouseButtons::LEFT));
    }

    /// Full-negative Y (raw -256) sign-extends correctly, then is negated.
    #[test]
    fn decode_full_negative_y() {
        // Y sign set, dy byte 0 -> raw -256 -> screen +256.
        let flags = SYNC_BIT | Y_SIGN_BIT;
        let bytes = [flags, 0, 0x00];
        let ev = decode_packet(&bytes, false).expect("full-negative Y decodes");
        assert_eq!(ev.dy, 256, "raw -256 negated to screen +256");
    }

    /// A 4-byte packet with scroll-up and the back button held.
    #[test]
    fn decode_4byte_scroll_and_back_button() {
        // byte 3: Z = +2, back button bit set.
        let zbyte = 0x02 | BTN_BACK_BIT;
        let bytes = [SYNC_BIT, 0, 0, zbyte];
        let ev = decode_packet(&bytes, true).expect("4-byte packet decodes");
        assert_eq!(ev.dz, 2, "Z nibble 0x02 sign-extends to +2");
        assert!(ev.buttons.contains(MouseButtons::BACK));
        assert!(!ev.buttons.contains(MouseButtons::FORWARD));
    }

    /// Negative scroll (scroll-down) sign-extends from the 4-bit nibble.
    #[test]
    fn decode_4byte_negative_scroll() {
        // Z nibble 0x08: sign bit set -> 8 - 16 = -8.
        let bytes = [SYNC_BIT, 0, 0, 0x08];
        let ev = decode_packet(&bytes, true).expect("negative scroll decodes");
        assert_eq!(ev.dz, -8);
    }

    /// X overflow causes the packet to be dropped, not clamped.
    #[test]
    fn overflow_packet_is_dropped() {
        // flags byte carries X_OVERFLOW_BIT; the overflow check returns None
        // before any data byte is indexed, so the trailing zeros are never
        // read but keep the slice well-formed for a 3-byte packet.
        let bytes: [u8; 3] = [SYNC_BIT | X_OVERFLOW_BIT, 0, 0];
        assert!(decode_packet(&bytes, false).is_none());
    }

    /// Y overflow alone also drops the packet.
    #[test]
    fn y_overflow_packet_is_dropped() {
        let bytes: [u8; 3] = [SYNC_BIT | Y_OVERFLOW_BIT, 0, 0];
        assert!(decode_packet(&bytes, false).is_none());
    }

    /// Byte 0 without the sync bit, at the start position, is dropped by the
    /// decoder and the stream stays aligned for the next real header.
    #[test]
    fn feed_drops_desync_header() {
        let mut dec = PacketDecoder::new();
        // 0x00 has no sync bit — must be dropped, no event, index stays 0.
        assert!(dec.feed(0x00).is_none());
        assert_eq!(dec.index, 0);
        // A real header is then accepted.
        assert!(dec.feed(SYNC_BIT).is_none());
        assert_eq!(dec.index, 1);
    }

    /// A complete 3-byte packet assembles into one event and resets the index.
    #[test]
    fn feed_assembles_3byte_packet() {
        let mut dec = PacketDecoder::new();
        assert!(dec.feed(SYNC_BIT | BTN_RIGHT_BIT).is_none());
        assert!(dec.feed(10).is_none());
        let ev = dec.feed(0).expect("third byte completes the packet");
        assert_eq!(ev.dx, 10);
        assert_eq!(ev.dy, 0);
        assert!(ev.buttons.contains(MouseButtons::RIGHT));
        assert_eq!(dec.index, 0, "index resets after a completed packet");
    }

    /// In 4-byte mode the decoder waits for a fourth byte before emitting.
    #[test]
    fn feed_assembles_4byte_packet() {
        let mut dec = PacketDecoder::new();
        dec.four_byte = true;
        assert!(dec.feed(SYNC_BIT).is_none());
        assert!(dec.feed(1).is_none());
        assert!(
            dec.feed(2).is_none(),
            "three bytes do not complete a 4-byte packet"
        );
        let ev = dec.feed(0x01).expect("fourth byte completes the packet");
        assert_eq!(ev.dx, 1);
        assert_eq!(ev.dy, -2);
        assert_eq!(ev.dz, 1);
    }

    /// The sign-extension helpers cover their full ranges.
    #[test]
    fn sign_extend_9_ranges() {
        assert_eq!(sign_extend_9(false, 0), 0);
        assert_eq!(sign_extend_9(false, 255), 255);
        assert_eq!(sign_extend_9(true, 0), -256);
        assert_eq!(sign_extend_9(true, 1), -255);
        assert_eq!(sign_extend_9(true, 255), -1);
    }

    #[test]
    fn sign_extend_4_ranges() {
        assert_eq!(sign_extend_4(0), 0);
        assert_eq!(sign_extend_4(7), 7);
        assert_eq!(sign_extend_4(8), -8);
        assert_eq!(sign_extend_4(0x0F), -1);
    }

    /// Button flags pack the documented bits and round-trip through bits().
    #[test]
    fn button_flags_pack_correctly() {
        let all = MouseButtons::LEFT
            | MouseButtons::RIGHT
            | MouseButtons::MIDDLE
            | MouseButtons::BACK
            | MouseButtons::FORWARD;
        // Low three bits in byte 0, high two in byte 3 — combined value is the
        // union of all five masks.
        assert_eq!(
            all.bits(),
            BTN_LEFT_BIT | BTN_RIGHT_BIT | BTN_MIDDLE_BIT | BTN_BACK_BIT | BTN_FORWARD_BIT
        );
        assert!(all.contains(MouseButtons::FORWARD));
    }

    /// The default event is all-zero with no buttons, a sensible "no movement"
    /// baseline for consumers that diff consecutive samples.
    #[test]
    fn mouse_event_default_is_quiet() {
        let ev = MouseEvent::default();
        assert!(ev.buttons.is_empty());
        assert_eq!(ev.dx, 0);
        assert_eq!(ev.dy, 0);
        assert_eq!(ev.dz, 0);
    }
}
