//! PC speaker beeper driver (PIT channel 2 + port 0x61 gate).
//!
//! The PC speaker is the oldest audio device on the platform: a small
//! piezoelectric element wired to the output of PIT channel 2 through a
//! two-bit gate on I/O port 0x61. There is no envelope, no volume, and no
//! waveform selection beyond "square wave on / square wave off" — channel 2
//! is programmed in mode 3 (square wave generator) and the gate either passes
//! that square wave to the speaker or disconnects it.
//!
//! # Why channel 2
//!
//! The 8254 PIT exposes three counters. Channel 0 is the system tick (IRQ 0)
//! and channel 1 was the DRAM refresh strobe on the original PC (unused on
//! modern hardware). Channel 2 is the only channel whose output is routed to
//! something other than an interrupt line: it feeds the speaker gate. It is
//! also the only channel whose gate is software-controlled (via port 0x61
//! bit 0), which is what lets us start and stop a tone without reprogramming
//! the counter.
//!
//! # Programming sequence
//!
//! To play a tone of `f` Hz:
//!
//! 1. Compute the divider `PIT_FREQUENCY / f`, clamped to `1..=65535`. The
//!    PIT input clock is 1.193182 MHz, so a divider of 1193 gives a 1 kHz
//!    tone and the maximum divider of 65535 gives ~18.2 Hz (the lowest
//!    audible-ish frequency the speaker can produce).
//! 2. Write the mode/command byte to port 0x43 selecting channel 2,
//!    lobyte/hibyte access, mode 3 (square wave), binary counting.
//! 3. Write the low then high bytes of the divider to port 0x42 (channel 2
//!    data). The access-mode bits in the command byte fix the order.
//! 4. Read port 0x61, set bit 0 (channel 2 gate enable) and bit 1 (speaker
//!    enable), write it back. The speaker now emits a square wave at `f`.
//! 5. Spin until the requested duration has elapsed, then clear bits 0 and 1
//!    on port 0x61 to silence the speaker.
//!
//! # Duration
//!
//! The delay is measured against the kernel's monotonic clock
//! ([`crate::time::Instant`]) rather than PIT channel 0, so beeping does not
//! disturb the system tick. This means [`beep`] requires the monotonic clock
//! to be installed (i.e. it must be called after `time::init`). Before that,
//! the speaker is not armed anyway, and a zero-clock read short-circuits to
//! a no-op so an early caller cannot wedge the kernel in an infinite loop.
//!
//! # Safety
//!
//! Every access is 8-bit port I/O through [`Port8`] to the fixed PC platform
//! ports 0x42, 0x43, and 0x61. These are kernel-owned on all PC-compatible
//! hardware. Reprogramming channel 2 never touches channel 0 (the system
//! tick) — the two counters are independent and addressed by separate
//! channel-select bits in the command byte.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::{InterruptGuard, Port8};
use crate::time::pit::PIT_FREQUENCY;
use crate::time::Instant;

// ---------------------------------------------------------------------------
// Port and bit constants
// ---------------------------------------------------------------------------

/// PIT channel 2 data port: the counter read/write port for the speaker
/// channel. The low and high bytes of the divider are written here in the
/// order fixed by the access-mode bits in the command byte.
const PIT_CHANNEL_2: Port8 = Port8::new(0x42);

/// PIT mode/command register. A write selects the channel, access mode,
/// operating mode, and counting mode for the next counter programming.
const PIT_MODE: Port8 = Port8::new(0x43);

/// The keyboard controller B port at 0x61 doubles as the speaker gate. Its
/// low two bits route PIT channel 2's output to the speaker:
///
/// - bit 0: channel 2 gate enable (1 = let the counter run)
/// - bit 1: speaker enable (1 = connect channel 2 output to speaker)
///
/// The remaining bits control the keyboard controller and the A20 gate; we
/// preserve them across every read-modify-write so we never clobber A20 or
/// the keyboard lines while beeping.
const KBDC_PORT_B: Port8 = Port8::new(0x61);

/// Bit 0 of port 0x61: PIT channel 2 gate. When set, the channel 2 counter
/// counts down and reloads; when clear, the counter is held and its output
/// stays in its last state.
const GATE_ENABLE: u8 = 1 << 0;

/// Bit 1 of port 0x61: speaker enable. When set, the channel 2 output is
/// routed to the speaker amplifier; when clear, the speaker is disconnected
/// even if the counter is still running.
const SPEAKER_ENABLE: u8 = 1 << 1;

/// Command byte for channel 2, lobyte/hibyte access, mode 3 (square wave),
/// binary counting. The 8254 mode byte layout is `SC1 SC0 RW1 RW0 M2 M1 M0
/// BCD`:
/// - `10` select channel 2
/// - `11` lobyte then hibyte access
/// - `011` mode 3 (square wave generator)
/// - `0` binary (not BCD)
const CMD_CHAN2_MODE3: u8 = 0b1011_0110;

/// The smallest divider the PIT accepts is 1 (full input frequency, ~1.19
/// MHz, far above hearing). The largest is 65535 (~18.2 Hz, the lowest tone
/// the speaker can produce). We clamp requested frequencies into this band.
const MIN_DIVIDER: u16 = 1;
const MAX_DIVIDER: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

/// Whether a tone is currently sounding. Read by [`silence`] to avoid a
/// redundant port write when no tone is armed, and by callers that want to
/// poll the speaker state without touching hardware. An atomic suffices
/// because the gate bit is a single boolean and the only races are between
/// concurrent `beep` callers, which [`BEEP_LOCK`] already serialises.
static BEEPING: AtomicBool = AtomicBool::new(false);

/// Serialises all speaker programming. The port 0x61 read-modify-write and
/// the channel 2 divisor load are not atomic with respect to a second CPU
/// issuing the same sequence, so a spinlock guards the whole start/stop
/// critical section. We use the kernel's own [`SpinLock`](crate::sync::SpinLock)
/// rather than `spin::Mutex` so the device layer stays consistent with the
/// rest of the kernel's locking discipline.
///
/// The lock is a `()`-valued token: it carries no data, it only enforces
/// mutual exclusion. A dedicated lock (rather than reusing some broader
/// device lock) keeps beeping off the hot path of any other subsystem.
static BEEP_LOCK: crate::sync::SpinLock<()> = crate::sync::SpinLock::new(());

// ---------------------------------------------------------------------------
// Divider math
// ---------------------------------------------------------------------------

/// Convert a desired tone frequency in Hz to the nearest PIT channel 2
/// divider, clamped into the `1..=65535` range the 16-bit counter accepts.
///
/// Returns `(divider, achieved_hz)`. The achieved frequency differs from the
/// request whenever `freq_hz` does not evenly divide the PIT input clock, so
/// a caller that cares about exact pitch can read the realised value back.
/// `freq_hz == 0` is treated as "no tone": the divider collapses to zero and
/// the caller ([`beep`]) short-circuits without arming the hardware.
#[must_use]
pub fn freq_to_divider(freq_hz: u32) -> (u16, u32) {
    if freq_hz == 0 {
        return (0, 0);
    }
    let pit = PIT_FREQUENCY;
    let raw = pit / u64::from(freq_hz);
    // Clamp into the counter's 16-bit range. Saturating cast drops any
    // high bits from an absurdly low frequency request.
    let divider = if raw < u64::from(MIN_DIVIDER) {
        MIN_DIVIDER
    } else if raw > u64::from(MAX_DIVIDER) {
        MAX_DIVIDER
    } else {
        raw as u16
    };
    let achieved = pit / u64::from(divider);
    (divider, achieved as u32)
}

// ---------------------------------------------------------------------------
// Low-level hardware sequence
// ---------------------------------------------------------------------------

/// Load `divider` into PIT channel 2 and raise the speaker gate on port 0x61.
///
/// Interrupts are disabled across the command write, the two divisor byte
/// writes, and the port 0x61 read-modify-write so a context switch cannot
/// leave the counter half-programmed or the gate half-raised. The caller's
/// interrupt state is restored unconditionally on exit.
///
/// # Panics
///
/// Never, but a `divider` of `0` is a no-op (the caller is expected to have
/// checked via [`freq_to_divider`]).
fn arm(divider: u16) {
    if divider == 0 {
        return;
    }
    {
        // SAFETY: speaker programming runs in ring 0. The guard restores the
        // caller's exact interrupt state when the port transaction completes.
        let _interrupt_guard = unsafe { InterruptGuard::disable() };

        // Select channel 2, lobyte/hibyte, mode 3 (square wave), binary.
        PIT_MODE.write(CMD_CHAN2_MODE3);
        // Low byte then high byte — the order is fixed by the access-mode bits
        // above and must not be reordered.
        PIT_CHANNEL_2.write((divider & 0xFF) as u8);
        PIT_CHANNEL_2.write(((divider >> 8) & 0xFF) as u8);

        // Read-modify-write port 0x61: set the gate and speaker enable bits
        // while preserving the keyboard-controller and A20 bits.
        let prev = KBDC_PORT_B.read();
        KBDC_PORT_B.write(prev | GATE_ENABLE | SPEAKER_ENABLE);
    }

    BEEPING.store(true, Ordering::Release);
}

/// Clear the speaker gate on port 0x61, silencing the tone.
///
/// Reads port 0x61, clears bits 0 and 1, and writes the result back,
/// preserving the keyboard-controller and A20 bits. Interrupts are masked
/// across the read-modify-write so the gate state cannot be observed
/// half-cleared.
pub fn silence() {
    // The lock makes `silence` safe to call from any context (including a
    // panic handler) without racing an in-progress `beep` on another CPU.
    let _guard = BEEP_LOCK.lock();
    if !BEEPING.swap(false, Ordering::AcqRel) {
        // Already silent: avoid the port write so a panicked caller cannot
        // clobber A20 by racing with a concurrent arm.
        return;
    }
    // SAFETY: port 0x61 is accessed in ring 0. Saved RFLAGS are restored
    // after the read-modify-write, preserving an interrupt-off caller.
    let _interrupt_guard = unsafe { InterruptGuard::disable() };
    let prev = KBDC_PORT_B.read();
    KBDC_PORT_B.write(prev & !(GATE_ENABLE | SPEAKER_ENABLE));
}

// ---------------------------------------------------------------------------
// Public tone API
// ---------------------------------------------------------------------------

/// Play a tone at `freq_hz` for approximately `duration_ms` milliseconds.
///
/// Programs PIT channel 2 to a square wave at the nearest achievable
/// frequency to `freq_hz`, raises the speaker gate on port 0x61, spins until
/// `duration_ms` has elapsed on the monotonic clock, then silences the
/// speaker. The spin is a busy-wait: there is no sleep syscall at this layer,
/// and `hlt` would require an interrupt to wake (the PIT tick is fine, but
/// keeping the CPU spinning makes the function safe to call with interrupts
/// masked, e.g. from a panic path that wants an audible fault blip).
///
/// A `freq_hz` of `0` or a `duration_ms` of `0` is a no-op that never touches
/// the hardware — handy for callers that compute the frequency from data that
/// may legitimately be zero.
///
/// # Concurrency
///
/// The whole arm/spin/silence sequence runs under [`BEEP_LOCK`], so two
/// concurrent `beep` callers play their tones back-to-back rather than
/// fighting over the channel 2 divisor. A caller that holds the lock for a
/// long `duration_ms` blocks the other; that is acceptable for a single-voice
/// beeper and matches the historic single-tasking semantics of the device.
///
/// # Requirements
///
/// Requires the monotonic clock to be installed (`time::init` has run). If
/// `Instant::now()` reads zero (clock not yet up), the duration loop exits
/// immediately after arming and immediately silences — an early caller
/// produces at most a brief click rather than an infinite tone.
pub fn beep(freq_hz: u32, duration_ms: u64) {
    if freq_hz == 0 || duration_ms == 0 {
        return;
    }
    let (divider, achieved) = freq_to_divider(freq_hz);
    if divider == 0 {
        return;
    }

    // Serialise the whole tone so a second `beep` cannot reprogram channel 2
    // out from under this one's duration spin.
    let _guard = BEEP_LOCK.lock();

    arm(divider);
    ::log::trace!(
        "pcspk: tone {} Hz (achieved {} Hz, divider {}) for {} ms",
        freq_hz,
        achieved,
        divider,
        duration_ms
    );

    // Spin until the deadline. We poll the monotonic clock rather than
    // reprogramming PIT channel 0 (which carries the system tick) so the
    // beep never disturbs scheduling. A `0` reading means the clock is not
    // installed yet (`time::init` has not run); in that case we skip the
    // delay entirely so an early caller produces at most a brief click
    // rather than spinning forever against a stationary counter.
    let start = Instant::now().as_nanos();
    if start != 0 {
        let deadline_ns = start.saturating_add(duration_ms.saturating_mul(1_000_000));
        while Instant::now().as_nanos() < deadline_ns {
            core::hint::spin_loop();
        }
    }

    // Drop the gate without releasing the lock yet: silence() takes the
    // lock itself, so we clear the gate directly here to avoid a
    // recursive-lock deadlock. The `BEEPING` flag is the only shared state
    // `silence` would consult, and we know it is true.
    {
        // SAFETY: port 0x61 is accessed in ring 0. Scope the guard to the
        // hardware RMW so the duration spin is not part of the IRQ blackout.
        let _interrupt_guard = unsafe { InterruptGuard::disable() };
        let prev = KBDC_PORT_B.read();
        KBDC_PORT_B.write(prev & !(GATE_ENABLE | SPEAKER_ENABLE));
    }
    BEEPING.store(false, Ordering::Release);

    // `_guard` drops here, releasing BEEP_LOCK.
}

/// Whether a tone is currently armed on the speaker.
///
/// This is a best-effort snapshot of the [`BEEPING`] flag; it may change the
/// instant it is read and is intended only for diagnostics (e.g. a "is the
/// beeper doing something?" check in a panic shell).
#[must_use]
pub fn is_beeping() -> bool {
    BEEPING.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------

/// One-line bring-up: ensure the speaker starts silenced.
///
/// Called by `devices::init` after the PIT and time subsystems are up. The
/// gate is forced clear so a stale BIOS-set gate (some firmware leaves the
/// speaker enabled after its own beep) does not produce a tone on first
/// kernel boot. Safe to call any time after the IDT is loaded.
pub fn init() {
    {
        // SAFETY: port 0x61 is kernel-owned and init runs in ring 0. The
        // guard preserves the boot caller's IF=0 state across this RMW.
        let _interrupt_guard = unsafe { InterruptGuard::disable() };
        let prev = KBDC_PORT_B.read();
        KBDC_PORT_B.write(prev & !(GATE_ENABLE | SPEAKER_ENABLE));
    }
    BEEPING.store(false, Ordering::Release);
    ::log::debug!("pcspk: speaker gate cleared, channel 2 idle");
}
