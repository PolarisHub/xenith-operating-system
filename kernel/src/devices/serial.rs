//! 16550-compatible UART serial driver.
//!
//! Drives the PC's legacy 16550 UART (COM1/COM2) at I/O ports 0x3F8/0x2F8.
//! The UART is the kernel's earliest output channel: it works before the
//! framebuffer is mapped, before the heap is up, and before interrupts are
//! routed, so it is the backbone of early-boot diagnostics and the
//! `log` backend's panic sink.
//!
//! # Configuration
//!
//! [`SerialPort::init`] programmes the chip for 38400 baud, 8 data bits,
//! no parity, one stop bit (8N1), with the FIFO enabled and chip
//! interrupts disabled — the canonical "poll, never interrupt" console
//! configuration used through ring-0 bring-up. Interrupt-driven TX/RX is
//! wired up later by the interrupt-routing phase.
//!
//! # I/O port access
//!
//! The 16550 is a legacy ISA device reached through `in`/`out` port I/O
//! cycles, not memory-mapped registers. The port-IO primitives
//! ([`inb`]/[`outb`]) live here as private helpers until the `arch`
//! module grows a shared `port` submodule; they are trivial wrappers
//! around the `in al, dx` / `out dx, al` instructions and move wholesale
//! when that lands.

use core::arch::asm;
use core::fmt;

// --- I/O port primitives ---------------------------------------------------

/// Read one byte from an I/O port.
///
/// SAFETY: the caller must ensure `port` selects a device I/O port the
/// kernel is permitted to access. For the 16550 UART register file and
/// the E9 debug port this is satisfied by construction.
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: `in al, dx` reads a single byte from the port encoded in
    // dx into al. It performs no memory access and does not touch
    // EFLAGS (the Intel SDM lists IN/OUT as affecting no flags), so
    // `nomem`, `preserves_flags`, and `nostack` are correct.
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
    // SAFETY: `out dx, al` writes al to the port encoded in dx. As with
    // `in`, it performs no memory access and does not touch EFLAGS.
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

// Register offsets from the base I/O port. The Divisor Latch Access Bit
// (DLAB) in the Line Control Register selects between the data registers
// and the baud-divisor latches at offsets 0 and 1.
const DATA: u16 = 0; // RBR (read) / THR (write) when DLAB = 0
const IER: u16 = 1; // Interrupt Enable when DLAB = 0; divisor high when DLAB = 1
const IIR_FCR: u16 = 2; // Interrupt Identification (read) / FIFO Control (write)
const LCR: u16 = 3; // Line Control
const MCR: u16 = 4; // Modem Control
const LSR: u16 = 5; // Line Status

// Line Status Register bits consulted by the polling paths.
const LSR_DATA_READY: u8 = 1 << 0; // receive buffer holds a byte
const LSR_THR_EMPTY: u8 = 1 << 5; // transmit holding register is empty

/// Line Control value for 8 data bits, no parity, one stop bit, DLAB clear.
/// DLAB (0x80) is OR'd in separately during [`SerialPort::init`] to reach
/// the divisor latches without disturbing the programmed frame format.
const LCR_8N1: u8 = 0x03;
/// 8N1 word bits with DLAB raised, for the divisor-latch access phase.
const LCR_DLAB: u8 = LCR_8N1 | 0x80;
/// FIFO Control value: enable FIFO, clear RX and TX FIFOs, 14-byte trigger.
const FCR_ENABLE: u8 = 0xC7;
/// Modem Control value: assert DTR and RTS only. OUT2 (0x08) is left
/// clear so the UART's interrupt line stays disconnected — `init` runs
/// with IRQs off by design.
const MCR_DTR_RTS: u8 = 0x03;
/// Baud divisor for 38400 baud: 115200 / 38400 = 3.
const DIVISOR_38400: u8 = 0x03;

// --- SerialPort ------------------------------------------------------------

/// A 16550-compatible serial port identified by its I/O base.
///
/// One instance typically backs each COM port the kernel cares about;
/// the primary console lives in the [`COM1`] static. Every method polls
/// the chip — spinning until the relevant Line Status bit is set — so it
/// is safe to call before interrupts are routed, at the cost of blocking
/// the caller.
#[derive(Debug)]
pub struct SerialPort {
    /// I/O port base, e.g. 0x3F8 for COM1, 0x2F8 for COM2.
    base: u16,
}

impl SerialPort {
    /// Create a handle to the UART at `base`.
    ///
    /// Does not touch the hardware; call [`init`](Self::init) before use.
    pub const fn new(base: u16) -> Self {
        Self { base }
    }

    /// Programme the UART for 38400 baud, 8N1, FIFO on, interrupts off.
    ///
    /// Idempotent: re-running it simply rewrites the same register
    /// values. Safe to call from early boot before the heap or IDT is
    /// available — it only issues `out` cycles to legacy I/O ports.
    pub fn init(&mut self) {
        // 1. Disable all four UART interrupt sources. We poll the Line
        //    Status Register rather than take IRQs, which keeps the
        //    driver usable before the IOAPIC/PIC and IDT are configured.
        self.write_reg(IER, 0x00);
        // 2. Raise DLAB so offsets 0 and 1 address the baud-divisor
        //    latches instead of the data / interrupt-enable registers.
        self.write_reg(LCR, LCR_DLAB);
        // 3. Divisor low byte: 3 for 38400 baud (115200 / 38400).
        self.write_reg(DATA, DIVISOR_38400);
        // 4. Divisor high byte: 0. Offset 1 is DLM while DLAB is set.
        self.write_reg(IER, 0x00);
        // 5. 8 data bits, no parity, 1 stop bit; clear DLAB back to the
        //    data / IER register file.
        self.write_reg(LCR, LCR_8N1);
        // 6. Enable and clear both FIFOs; 14-byte receive trigger level.
        self.write_reg(IIR_FCR, FCR_ENABLE);
        // 7. Assert DTR + RTS so a connected terminal or modem sees
        //    carrier. OUT2 stays clear so the IRQ line is disconnected,
        //    matching the "interrupts off" contract.
        self.write_reg(MCR, MCR_DTR_RTS);
    }

    /// Transmit one raw byte, spinning until the holding register is empty.
    ///
    /// No newline translation is performed — `\n` is sent as `\n`. Use
    /// [`send_str`](Self::send_str) for terminal-friendly CRLF expansion.
    pub fn send(&mut self, byte: u8) {
        while !self.thr_empty() {
            core::hint::spin_loop();
        }
        self.write_reg(DATA, byte);
    }

    /// Transmit a string, expanding `\n` to `\r\n` for serial terminals.
    ///
    /// A bare `\n` moves the cursor down without returning to column 0 on
    /// a classic terminal, so each LF is preceded by a CR. Callers that
    /// already emit CRLF should drive [`send`](Self::send) per byte
    /// instead to avoid double carriage returns.
    pub fn send_str(&mut self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.send(b'\r');
            }
            self.send(byte);
        }
    }

    /// Receive one byte, spinning until the receive buffer is non-empty.
    ///
    /// Blocks indefinitely if no data arrives — appropriate for a polled
    /// console read, but latency-sensitive callers should check
    /// [`data_ready`](Self::data_ready) first and only read when true.
    pub fn read_byte(&mut self) -> u8 {
        while !self.data_ready() {
            core::hint::spin_loop();
        }
        self.read_reg(DATA)
    }

    /// Whether a received byte is waiting in the receive buffer.
    pub fn data_ready(&self) -> bool {
        self.read_reg(LSR) & LSR_DATA_READY != 0
    }

    /// Whether the transmit holding register is empty (ready for a byte).
    pub fn thr_empty(&self) -> bool {
        self.read_reg(LSR) & LSR_THR_EMPTY != 0
    }

    /// Read a 16550 register at `offset` from this port's base.
    #[inline]
    fn read_reg(&self, offset: u16) -> u8 {
        // SAFETY: `base` is a valid 16550 I/O base supplied by the caller
        // and `offset` is one of the 0..=5 register selects above, so the
        // resulting port address is a real 16550 register.
        unsafe { inb(self.base.wrapping_add(offset)) }
    }

    /// Write a 16550 register at `offset` from this port's base.
    #[inline]
    fn write_reg(&self, offset: u16, val: u8) {
        // SAFETY: see `read_reg`; the writes are idempotent 16550
        // configuration writes that never touch memory.
        unsafe { outb(self.base.wrapping_add(offset), val) }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.send_str(s);
        Ok(())
    }
}

// --- E9 debug port ---------------------------------------------------------

/// Write one byte to the QEMU/Bochs E9 debug port.
///
/// Port 0xE9 is a virtual debug console honoured by QEMU (with
/// `-debugcon stdio`) and Bochs: each `out` byte appears on the host's
/// debug channel. It is available before the 16550 is initialised and
/// before any memory or paging setup, making it the lowest-friction
/// very-early-debug path. On real hardware the port is typically a
/// no-op scratch, so emitting to it is always safe.
pub fn e9_write_char(byte: u8) {
    // SAFETY: writing to the E9 debug port has no side effect beyond
    // forwarding the byte to the host debug console (QEMU/Bochs) or
    // dropping it (real hardware). It never accesses memory.
    unsafe { outb(0xE9, byte) }
}

// --- COM1 singleton --------------------------------------------------------

/// Primary serial port (COM1 at I/O base 0x3F8).
///
/// Guarded by a spinlock because the UART is shared between the early
/// console, the `log` backend, and any ring-0 diagnostic path. Locking
/// serialises output so interleaved bytes from multiple CPUs form
/// coherent lines rather than an interleaved soup.
///
/// Uses `spin::Mutex` directly until the `sync` module re-exports its
/// own `SpinLock` wrapper; the swap is a one-line type change here.
pub static COM1: spin::Mutex<SerialPort> = spin::Mutex::new(SerialPort::new(0x3F8));
