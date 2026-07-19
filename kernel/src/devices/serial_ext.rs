//! Multiport 16550 UART extensions: COM2/COM3/COM4, configurable baud,
//! FIFO and modem-status access, and a [`SerialHub`] that owns all four
//! legacy COM ports.
//!
//! The base single-port driver in [`super::serial`] hard-wires COM1 to
//! 38400 baud and exposes only the two Line Status bits the polled console
//! needs. That is the right shape for the very first boot output, but the
//! kernel outgrows it once we want a *second* debug channel (e.g. a dedicated
//! crash-log port distinct from the interactive console) or want to talk to
//! real hardware at a non-default rate. This module fills that gap without
//! disturbing [`super::serial`]: it defines a richer [`SerialPortExt`] that
//! supports per-port baud selection, FIFO trigger-level programming, full
//! Line Status and Modem Status reads, and a scratch-register presence
//! probe, then aggregates four of them into a [`SerialHub`] behind a single
//! [`SpinLock`](crate::sync::SpinLock).
//!
//! # Why a second port?
//!
//! On dual-serial development rigs (and on QEMU with two `-serial` options)
//! COM1 is typically wired to the interactive console while COM2 captures a
//! clean kernel-only trace. Routing the panic sink and `log::debug!` traffic
//! to COM2 keeps the operator's console uncluttered. [`debug_write`] is the
//! one-call entry point for that path: it locks the hub once and emits to
//! COM2 if the port probed present, silently dropping the line otherwise so
//! single-port hosts are not punished.
//!
//! # I/O port access
//!
//! The 16550 is reached through `in`/`out` port I/O, not MMIO. The
//! `inb`/`outb` helpers are duplicated here rather than imported from
//! [`super::serial`] (where they are private) pending a shared
//! `arch::port` submodule; the swap is mechanical when that lands.

use core::arch::asm;
use core::fmt;

use xenith_bitflags::bitflags;

use crate::sync::SpinLock;

// --- I/O port primitives ---------------------------------------------------

/// Read one byte from an I/O port.
///
/// SAFETY: the caller must ensure `port` selects a device I/O port the
/// kernel is permitted to access. For the 16550 register file this is
/// satisfied by construction via the COM base constants below.
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: `in al, dx` reads a single byte from the port in dx into al.
    // No memory access, no EFLAGS effect (Intel SDM: IN/OUT touch no flags),
    // so `nomem`, `preserves_flags`, and `nostack` are correct.
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Write one byte to an I/O port.
///
/// SAFETY: the caller must ensure `port` selects a device I/O port the
/// kernel is permitted to write.
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: `out dx, al` writes al to the port in dx. Same constraints as
    // `inb`: no memory access, no flags.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// --- 16550 register layout -------------------------------------------------

// Register offsets from the base I/O port. Offsets 0 and 1 address the
// data / interrupt-enable registers when DLAB is clear and the baud-divisor
// latches when DLAB is set in the Line Control Register.
const DATA: u16 = 0; // RBR (read) / THR (write); DLL when DLAB = 1
const IER: u16 = 1; // Interrupt Enable; DLM when DLAB = 1
const IIR_FCR: u16 = 2; // Interrupt Identification (R) / FIFO Control (W)
const LCR: u16 = 3; // Line Control (holds DLAB)
const MCR: u16 = 4; // Modem Control
const LSR: u16 = 5; // Line Status (read-only)
const MSR: u16 = 6; // Modem Status (read-only)
const SCR: u16 = 7; // Scratchpad — unused by the chip, free for probe use

/// Line Control value for 8 data bits, no parity, one stop bit, DLAB clear.
const LCR_8N1: u8 = 0x03;
/// 8N1 with DLAB raised, for the divisor-latch access phase of init.
const LCR_DLAB: u8 = LCR_8N1 | 0x80;
/// Modem Control: assert DTR + RTS, leave OUT2 clear so IRQs stay masked.
const MCR_DTR_RTS: u8 = 0x03;

bitflags! {
    /// Line Status Register bits. Read at offset 5; consulted by the polling
    /// paths and by error-reporting code after a burst of traffic.
    pub struct LsrFlags: u64 {
        /// Receive buffer holds a byte ready to be read (RBR has data).
        const DATA_READY     = 1 << 0;
        /// Receive overrun: a byte arrived before the previous one was read
        /// and the previous byte was lost. Sticky until the LSR is read.
        const OVERRUN_ERROR  = 1 << 1;
        /// Parity mismatch between the stop and start bits of the last byte.
        const PARITY_ERROR   = 1 << 2;
        /// Stop bit was not detected — usually a baud mismatch or broken line.
        const FRAMING_ERROR  = 1 << 3;
        /// Break interrupt: the receive line held space (0) for longer than
        /// one full frame. Often a remote-reset or cable-pull signal.
        const BREAK_INTERRUPT = 1 << 4;
        /// Transmit Holding Register is empty: the THR can accept the next byte.
        const THR_EMPTY      = 1 << 5;
        /// Transmitter (shift register + holding) is fully idle — the last
        /// bit has cleared the wire. Stronger than `THR_EMPTY`.
        const TRANSMITTER_EMPTY = 1 << 6;
        /// At least one byte in the FIFO has a parity/framing/break error.
        /// Only meaningful on FIFO-enabled chips; 0 on the bare 16450.
        const FIFO_ERROR      = 1 << 7;
    }
}

bitflags! {
    /// Modem Status Register bits. Read at offset 6; the low four are
    /// sticky "delta" latches that record a change since the last MSR read,
    /// the high four are the live modem-line levels.
    pub struct MsrFlags: u64 {
        /// CTS changed since the last MSR read.
        const DELTA_CTS = 1 << 0;
        /// DSR changed since the last MSR read.
        const DELTA_DSR = 1 << 1;
        /// Ring Indicator trailing-edge detected (RI went high-to-low).
        const TRAILING_EDGE_RI = 1 << 2;
        /// DCD changed since the last MSR read.
        const DELTA_DCD = 1 << 3;
        /// Clear To Send — live level of the CTS modem line.
        const CTS = 1 << 4;
        /// Data Set Ready — live level of the DSR modem line.
        const DSR = 1 << 5;
        /// Ring Indicator — live level of the RI modem line.
        const RING_INDICATOR = 1 << 6;
        /// Data Carrier Detect — live level of the DCD modem line.
        const DATA_CARRIER_DETECT = 1 << 7;
    }
}

// --- Baud rate and FIFO trigger selection -----------------------------------

/// Common 16550 baud rates.
///
/// The UART divides its 1.8432 MHz reference clock by `divisor * 16` to
/// produce the bit clock, and the divisor is `115200 / baud`. We store the
/// precomputed divisor so [`SerialPortExt::set_baud`] never divides at
/// runtime — handy inside early-boot paths where even a `u64` divide is
/// mildly embarrassing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaudRate {
    Baud1200,
    Baud2400,
    Baud4800,
    Baud9600,
    Baud19200,
    Baud38400,
    Baud57600,
    Baud115200,
}

impl BaudRate {
    /// Divisor = 115200 / baud, expressed as a 16-bit latch value.
    pub const fn divisor(self) -> u16 {
        match self {
            BaudRate::Baud1200 => 96,
            BaudRate::Baud2400 => 48,
            BaudRate::Baud4800 => 24,
            BaudRate::Baud9600 => 12,
            BaudRate::Baud19200 => 6,
            BaudRate::Baud38400 => 3,
            BaudRate::Baud57600 => 2,
            BaudRate::Baud115200 => 1,
        }
    }
}

/// 16550 FIFO receive trigger level: how many bytes must accumulate in the
/// RX FIFO before the chip would raise an interrupt. We poll, so the level
/// only affects how `data_ready` behaves in practice — but programming it
/// correctly keeps a future interrupt-driven path honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FifoTrigger {
    /// Interrupt at 1 byte in the FIFO.
    Bytes1 = 0x00,
    /// Interrupt at 4 bytes.
    Bytes4 = 0x40,
    /// Interrupt at 8 bytes.
    Bytes8 = 0x80,
    /// Interrupt at 14 bytes (the maximum useful trigger).
    Bytes14 = 0xC0,
}

/// FIFO Control Register value to enable the FIFO, clear RX and TX, with a
/// given trigger level OR'd in by the caller.
const FCR_ENABLE_CLEAR: u8 = 0x07;

// --- COM port identities ----------------------------------------------------

/// I/O base of COM1 (primary console, also owned by [`super::serial`]).
pub const COM1_BASE: u16 = 0x3F8;
/// I/O base of COM2 (typical secondary debug channel).
pub const COM2_BASE: u16 = 0x2F8;
/// I/O base of COM3.
pub const COM3_BASE: u16 = 0x3E8;
/// I/O base of COM4.
pub const COM4_BASE: u16 = 0x2E8;

/// One of the four legacy COM port slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComPort {
    Com1,
    Com2,
    Com3,
    Com4,
}

impl ComPort {
    /// I/O port base for this COM slot.
    pub const fn base(self) -> u16 {
        match self {
            ComPort::Com1 => COM1_BASE,
            ComPort::Com2 => COM2_BASE,
            ComPort::Com3 => COM3_BASE,
            ComPort::Com4 => COM4_BASE,
        }
    }

    /// Zero-based index into [`SerialHub`]'s port array.
    pub const fn index(self) -> usize {
        match self {
            ComPort::Com1 => 0,
            ComPort::Com2 => 1,
            ComPort::Com3 => 2,
            ComPort::Com4 => 3,
        }
    }
}

// --- SerialPortExt ---------------------------------------------------------

/// A 16550-compatible serial port with configurable baud, FIFO control,
/// modem-status reads, and presence probing.
///
/// Distinct from [`super::serial::SerialPort`] because the latter's API is
/// deliberately minimal (fixed 38400 baud, no MSR access) and is already
/// wired into the console/log backends; this type serves the richer
/// multiport use cases without perturbing that contract.
///
/// The `present` flag is set by [`probe`](Self::probe) and gates every
/// transmit path so a missing COM2/COM3/COM4 on real hardware is silently
/// ignored rather than dumping bytes into an empty I/O decode.
#[derive(Debug, Clone, Copy)]
pub struct SerialPortExt {
    /// I/O port base, e.g. 0x3F8 for COM1.
    base: u16,
    /// Whether [`probe`](Self::probe) detected a UART at `base`.
    present: bool,
}

impl SerialPortExt {
    /// Create a handle to the UART at `base`, assumed absent until probed.
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            present: false,
        }
    }

    /// Whether a UART was detected at this port's base.
    pub fn is_present(&self) -> bool {
        self.present
    }

    /// Detect a UART via the scratch register round-trip.
    ///
    /// Writes two distinct patterns to SCR (offset 7, unused by the UART
    /// core) and reads them back; a real 16550 retains the value, while an
    /// empty I/O decode typically returns 0xFF. Sets `present` accordingly
    /// and returns the detected state. Safe to call before [`init`].
    ///
    /// [`init`]: Self::init
    pub fn probe(&mut self) -> bool {
        // Write 0x5A and read it back; then 0xA5 for a second opinion. Two
        // distinct patterns avoid mistaking a decode that always returns a
        // fixed value (e.g. 0xFF) for a live register.
        self.write_reg(SCR, 0x5A);
        let a = self.read_reg(SCR);
        self.write_reg(SCR, 0xA5);
        let b = self.read_reg(SCR);
        self.present = a == 0x5A && b == 0xA5;
        self.present
    }

    /// Programme the UART for `baud` 8N1, FIFO on at `trigger`, interrupts
    /// off, DTR+RTS asserted. Idempotent.
    pub fn init(&mut self, baud: BaudRate, trigger: FifoTrigger) {
        // 1. Disable all interrupt sources — we poll the Line Status Register.
        self.write_reg(IER, 0x00);
        // 2. Raise DLAB to reach the baud-divisor latches at offsets 0/1.
        self.write_reg(LCR, LCR_DLAB);
        let div = baud.divisor();
        self.write_reg(DATA, (div & 0xFF) as u8);
        self.write_reg(IER, ((div >> 8) & 0xFF) as u8);
        // 3. 8N1, clear DLAB back to the data / IER register file.
        self.write_reg(LCR, LCR_8N1);
        // 4. Enable + clear both FIFOs at the requested trigger level.
        self.write_reg(IIR_FCR, FCR_ENABLE_CLEAR | trigger as u8);
        // 5. DTR + RTS; OUT2 clear so the IRQ line stays disconnected.
        self.write_reg(MCR, MCR_DTR_RTS);
        self.present = true;
    }

    /// Re-programme only the baud divisor, leaving the FIFO and modem-control
    /// settings untouched. The frame format is restored to canonical 8N1.
    pub fn set_baud(&mut self, baud: BaudRate) {
        // Raise DLAB to expose the divisor latches at offsets 0/1, write the
        // 16-bit divisor low/high, then drop DLAB and re-fix 8N1 so the frame
        // format is deterministic regardless of what a caller did in between.
        self.write_reg(LCR, LCR_DLAB);
        let div = baud.divisor();
        self.write_reg(DATA, (div & 0xFF) as u8);
        self.write_reg(IER, ((div >> 8) & 0xFF) as u8);
        self.write_reg(LCR, LCR_8N1);
    }

    /// Enable the FIFO at `trigger` and clear both RX and TX queues.
    pub fn enable_fifo(&mut self, trigger: FifoTrigger) {
        self.write_reg(IIR_FCR, FCR_ENABLE_CLEAR | trigger as u8);
    }

    /// Disable the FIFO entirely (fall back to single-byte 16450 behaviour).
    pub fn disable_fifo(&mut self) {
        self.write_reg(IIR_FCR, 0x00);
    }

    /// Clear the RX and TX FIFOs without changing the trigger level.
    pub fn clear_fifos(&mut self) {
        // Bit 1 = clear RX FIFO, bit 2 = clear TX FIFO; bit 0 must remain set
        // so the FIFO stays enabled. Trigger bits (6:7) are re-read from LSR
        // context — safest to re-enable with the default 14-byte trigger.
        self.write_reg(IIR_FCR, FCR_ENABLE_CLEAR | FifoTrigger::Bytes14 as u8);
    }

    /// Full Line Status snapshot.
    pub fn line_status(&self) -> LsrFlags {
        LsrFlags::from_bits_truncate(self.read_reg(LSR) as u64)
    }

    /// Full Modem Status snapshot.
    pub fn modem_status(&self) -> MsrFlags {
        MsrFlags::from_bits_truncate(self.read_reg(MSR) as u64)
    }

    /// Whether a received byte is waiting in the receive buffer.
    pub fn data_ready(&self) -> bool {
        self.line_status().contains(LsrFlags::DATA_READY)
    }

    /// Whether the transmit holding register is empty (ready for a byte).
    pub fn thr_empty(&self) -> bool {
        self.line_status().contains(LsrFlags::THR_EMPTY)
    }

    /// Transmit one raw byte, spinning until the holding register is empty.
    /// Drops the byte silently if the port did not probe present.
    pub fn send(&mut self, byte: u8) {
        if !self.present {
            return;
        }
        while !self.thr_empty() {
            core::hint::spin_loop();
        }
        self.write_reg(DATA, byte);
    }

    /// Transmit a string, expanding `\n` to `\r\n` for serial terminals.
    pub fn send_str(&mut self, s: &str) {
        if !self.present {
            return;
        }
        for byte in s.bytes() {
            if byte == b'\n' {
                self.send(b'\r');
            }
            self.send(byte);
        }
    }

    /// Receive one byte, spinning until the receive buffer is non-empty.
    pub fn read_byte(&mut self) -> u8 {
        while !self.data_ready() {
            core::hint::spin_loop();
        }
        self.read_reg(DATA)
    }

    #[inline]
    fn read_reg(&self, offset: u16) -> u8 {
        // SAFETY: `base` is a valid 16550 I/O base and `offset` is one of
        // the 0..=7 register selects above, so the resulting port is a real
        // 16550 register (or a harmless empty decode on absent hardware).
        unsafe { inb(self.base.wrapping_add(offset)) }
    }

    #[inline]
    fn write_reg(&self, offset: u16, val: u8) {
        // SAFETY: see `read_reg`; the writes are idempotent 16550
        // configuration writes that never touch memory.
        unsafe { outb(self.base.wrapping_add(offset), val) }
    }
}

impl fmt::Write for SerialPortExt {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.send_str(s);
        Ok(())
    }
}

// --- SerialHub -------------------------------------------------------------

/// Owner of all four legacy COM ports.
///
/// One [`SerialHub`] lives in the [`SERIAL_HUB`] static behind a single
/// [`SpinLock`](crate::sync::SpinLock). Callers that need to emit to a
/// specific port lock once, grab the port, and write; callers that want
/// the canonical "second debug port" use [`debug_write`] which does the
/// locking internally.
pub struct SerialHub {
    /// COM1..COM4 in index order. `ports[i].is_present()` reflects the last
    /// [`probe`](SerialPortExt::probe) / [`init`](SerialPortExt::init) pass.
    ports: [SerialPortExt; 4],
}

impl SerialHub {
    /// Build a hub with all four ports at their canonical bases, all
    /// marked absent until probed.
    pub const fn new() -> Self {
        Self {
            ports: [
                SerialPortExt::new(COM1_BASE),
                SerialPortExt::new(COM2_BASE),
                SerialPortExt::new(COM3_BASE),
                SerialPortExt::new(COM4_BASE),
            ],
        }
    }

    /// Probe every port and initialise the ones that are present at
    /// `baud` / 8N1 / FIFO-on (14-byte trigger). Returns the count of ports
    /// that came up.
    pub fn init_all(&mut self, baud: BaudRate) -> usize {
        let mut up = 0;
        for port in self.ports.iter_mut() {
            if port.probe() {
                port.init(baud, FifoTrigger::Bytes14);
                up += 1;
            }
        }
        up
    }

    /// Probe and initialise a single port. Returns `true` if it came up.
    pub fn init_port(&mut self, port: ComPort, baud: BaudRate) -> bool {
        let p = &mut self.ports[port.index()];
        if p.probe() {
            p.init(baud, FifoTrigger::Bytes14);
            true
        } else {
            false
        }
    }

    /// Shared access to one port.
    pub fn port(&self, port: ComPort) -> &SerialPortExt {
        &self.ports[port.index()]
    }

    /// Exclusive access to one port for transmit / reconfigure paths.
    pub fn port_mut(&mut self, port: ComPort) -> &mut SerialPortExt {
        &mut self.ports[port.index()]
    }

    /// Per-port presence bitmap, COM1 first.
    pub fn present(&self) -> [bool; 4] {
        [
            self.ports[0].is_present(),
            self.ports[1].is_present(),
            self.ports[2].is_present(),
            self.ports[3].is_present(),
        ]
    }

    /// Send a string to one port; no-op if that port is absent.
    pub fn send_to(&mut self, port: ComPort, s: &str) {
        self.ports[port.index()].send_str(s);
    }

    /// Send a string to every present port simultaneously (in index order),
    /// so a single log line lands on the console, the debug port, and any
    /// auxiliary capture attached to COM3/COM4.
    pub fn broadcast(&mut self, s: &str) {
        for port in self.ports.iter_mut() {
            port.send_str(s);
        }
    }
}

impl fmt::Debug for SerialHub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerialHub")
            .field("com1", &self.ports[0].is_present())
            .field("com2", &self.ports[1].is_present())
            .field("com3", &self.ports[2].is_present())
            .field("com4", &self.ports[3].is_present())
            .finish()
    }
}

// --- Hub singleton and debug-port helper -----------------------------------

/// Global multiport serial hub.
///
/// Initialised lazily by whichever subsystem first needs a non-COM1 port
/// (typically the log backend wiring COM2 as a debug sink). Until
/// [`SerialHub::init_all`] is run every port reports absent and writes are
/// silently dropped, so the static is safe to reference at any boot stage.
impl Default for SerialHub {
    fn default() -> Self {
        Self::new()
    }
}

pub static SERIAL_HUB: SpinLock<SerialHub> = SpinLock::new(SerialHub::new());

/// COM port used as the kernel's secondary debug channel.
///
/// COM2 is the conventional choice: it is the second port on a dual-serial
/// rig and the second `-serial` target under QEMU, leaving COM1 for the
/// interactive console. [`debug_write`] emits here.
const DEBUG_PORT: ComPort = ComPort::Com2;

/// Write a string to the kernel debug port (COM2).
///
/// Acquires [`SERIAL_HUB`] once, emits to [`DEBUG_PORT`] if it probed
/// present, and returns. If COM2 is absent the line is silently dropped —
/// single-port hosts still get all output on COM1 via [`super::serial`].
/// Intended for `log::debug!`/`log::trace!` routing and panic-side crash
/// dumps that must not clutter the operator's console.
pub fn debug_write(s: &str) {
    let mut hub = SERIAL_HUB.lock();
    // If the hub has not been initialised yet, attempt a one-shot probe +
    // init of the debug port so the first debug line is not lost. Cheap on
    // subsequent calls: `init` is idempotent and a re-probe of a present
    // port is two SCR round-trips.
    if !hub.port(DEBUG_PORT).is_present() {
        hub.init_port(DEBUG_PORT, BaudRate::Baud38400);
    }
    hub.send_to(DEBUG_PORT, s);
}

/// Convenience wrapper around [`debug_write`] that appends a CRLF.
pub fn debug_writeln(s: &str) {
    let mut hub = SERIAL_HUB.lock();
    if !hub.port(DEBUG_PORT).is_present() {
        hub.init_port(DEBUG_PORT, BaudRate::Baud38400);
    }
    let p = hub.port_mut(DEBUG_PORT);
    p.send_str(s);
    p.send(b'\r');
    p.send(b'\n');
}
