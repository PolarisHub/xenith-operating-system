//! Kernel panic handler.
//!
//! Invoked via the binary's `#[panic_handler]`, which delegates to
//! [`handle`]. The handler prints a banner with the panic message and
//! location, dumps the current stack pointer and a best-effort snapshot of
//! the general-purpose registers, then masks interrupts and parks the core
//! permanently.
//!
//! # Output path
//!
//! Panic output goes straight to the COM1 serial port via a self-contained,
//! lock-free emergency writer. We deliberately do **not** route through the
//! `log` facade or [`crate::log::logger`]: a panic can fire while the logger
//! mutex is already held (for example inside `KernelLogger::log`), and taking
//! the same lock again would deadlock the only core that can report the
//! fault. The framebuffer console is skipped for the same reason — it may be
//! wedged. Serial-only panic output is the standard bare-metal trade-off.
//!
//! Later phases will extend this to capture a full exception frame from the
//! IDT, switch to a known-good fault stack, and shut the other CPUs down
//! before halting; the register snapshot here is the best we can do without
//! that infrastructure.

use core::fmt::{self, Write};
use core::panic::PanicInfo;

/// Lower bound of the kernel's canonical higher-half virtual addresses
/// (Limine's HHDM base). Used to sanity-check `RSP` before dumping stack
/// memory, so a bogus stack pointer cannot trigger a recursive fault.
const HHDM_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Base I/O port of COM1, the serial line the emergency writer targets.
const COM1: u16 = 0x3F8;

/// Handle an unrecoverable panic.
///
/// Never returns: after logging, the CPU is halted with interrupts disabled
/// so no further code runs on this core.
pub fn handle(info: &PanicInfo) -> ! {
    // Initialise the UART once up front so the banner comes out whole rather
    // than with the first byte dropped by an unconfigured transmitter.
    emergency_init_serial();

    emit_banner(info);
    dump_registers();
    dump_stack();

    park();
}

// --- Panic banner ----------------------------------------------------------

/// Print the `*** XENITH PANIC ***` banner with the message and location.
fn emit_banner(info: &PanicInfo) {
    let mut w = EmergencyWriter;
    let _ = w.write_str("\n\n*** XENITH PANIC ***\n");

    if let Some(loc) = info.location() {
        let _ = writeln!(w, "  at {}:{}:{}", loc.file(), loc.line(), loc.column());
    }

    let _ = w.write_str("  msg: ");
    let _ = write!(w, "{}", info.message());
    let _ = w.write_str("\n");
}

// --- Register dump ---------------------------------------------------------

/// Snapshot of the general-purpose registers captured at the dump point.
///
/// These are the register values *as observed inside this function*, not the
/// state at the original panic site — recovering that requires an exception
/// frame from the arch layer, which is not available yet. `RSP` and `RBP`
/// below are captured with explicit `mov` instructions and are reliable; the
/// caller-saved GPRs are best-effort and may reflect compiler scratch state.
struct Gprs {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

/// Dump `RSP`, `RBP`, `CR2`, and the GPR snapshot to the serial line.
fn dump_registers() {
    // Reliable frame pointers: read with explicit `mov` so the compiler
    // cannot repurpose the source register before the snapshot.
    //
    // SAFETY: each `mov` reads a control/register value into a chosen
    // scratch register; none of them touch memory, the stack, or flags.
    // `RSP` and `RBP` are ABI-stable across the call, and reading `CR2` is a
    // privileged but non-faulting operation in ring 0.
    let (rsp, rbp, cr2): (u64, u64, u64);
    unsafe {
        core::arch::asm!(
            "mov {rsp}, rsp",
            "mov {rbp}, rbp",
            "mov {cr2}, cr2",
            rsp = out(reg) rsp,
            rbp = out(reg) rbp,
            cr2 = out(reg) cr2,
            options(nostack, preserves_flags),
        );
    }

    // Best-effort GPR snapshot: each `out("reg")` with an empty asm body
    // captures whatever that register held at this program point. The values
    // are not the fault's original register state.
    //
    // SAFETY: the asm body is empty and only declares register outputs; it
    // performs no memory or stack access and does not modify flags.
    let (rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15);
    let rbx: u64;
    unsafe {
        core::arch::asm!("mov {}, rbx", out(reg) rbx, options(nostack, nomem, preserves_flags));
        core::arch::asm!(
            "",
            out("rax") rax,
            out("rcx") rcx,
            out("rdx") rdx,
            out("rsi") rsi,
            out("rdi") rdi,
            out("r8") r8,
            out("r9") r9,
            out("r10") r10,
            out("r11") r11,
            out("r12") r12,
            out("r13") r13,
            out("r14") r14,
            out("r15") r15,
            options(nostack, preserves_flags),
        );
    }
    let g = Gprs {
        rax,
        rbx,
        rcx,
        rdx,
        rsi,
        rdi,
        r8,
        r9,
        r10,
        r11,
        r12,
        r13,
        r14,
        r15,
    };

    let mut w = EmergencyWriter;
    let _ = writeln!(
        w,
        "  cpu: rsp={:#018x} rbp={:#018x} cr2={:#018x}",
        rsp, rbp, cr2
    );
    let _ = write!(
        w,
        "  gprs: rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}\n  rsi={:#018x} rdi={:#018x} r8 ={:#018x} r9 ={:#018x}\n  r10={:#018x} r11={:#018x} r12={:#018x} r13={:#018x}\n  r14={:#018x} r15={:#018x}\n",
        g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.r8, g.r9, g.r10, g.r11,
        g.r12, g.r13, g.r14, g.r15,
    );
}

// --- Stack dump ------------------------------------------------------------

/// Print a hex dump of the 16 u64 words above `RSP`.
///
/// The dump is skipped if `RSP` does not point into the kernel's higher-half
/// canonical range, so a corrupted stack pointer cannot cause a recursive
/// fault while we are already panicking.
fn dump_stack() {
    let rsp: u64;
    // SAFETY: `mov {tmp}, rsp` copies the stack pointer into a scratch
    // register; no memory or stack access, no flag change.
    unsafe {
        core::arch::asm!(
            "mov {tmp}, rsp",
            tmp = out(reg) rsp,
            options(nostack, preserves_flags),
        );
    }

    let mut w = EmergencyWriter;
    let _ = writeln!(w, "  stack @ rsp={:#018x}:", rsp);

    if rsp < HHDM_BASE {
        let _ = w.write_str("    <rsp below kernel higher-half range; dump skipped>\n");
        return;
    }

    let aligned = rsp & !0x7u64;
    for i in 0..16u64 {
        let addr = aligned.wrapping_add(i * 8);
        // SAFETY: `addr` is in the kernel's mapped higher-half range (it
        // passed the `HHDM_BASE` check) and is 8-byte aligned, so a u64
        // load cannot cross a page boundary into unmapped memory that the
        // stack itself does not already cover. `read_volatile` prevents
        // the compiler from eliding or coalescing the loads.
        let val = unsafe { (addr as *const u64).read_volatile() };
        let _ = writeln!(w, "    {:#018x}: {:#018x}", addr, val);
    }
}

// --- Halt ------------------------------------------------------------------

/// Disable interrupts and halt this core permanently.
fn park() -> ! {
    // SAFETY: `cli` clears EFLAGS.IF. It touches no memory and uses no
    // stack; the only effect is masking external interrupts so the `hlt`
    // loop below cannot be woken. We deliberately do NOT mark this
    // `preserves_flags` because `cli` modifies EFLAGS.IF.
    unsafe {
        core::arch::asm!("cli", options(nostack, nomem));
    }
    loop {
        // SAFETY: with interrupts disabled above, `hlt` is a permanent park.
        // It performs no memory or stack access, so `nostack` and `nomem`
        // are sound.
        unsafe {
            core::arch::asm!("hlt", options(nostack, nomem));
        }
    }
}

// --- Emergency serial writer -----------------------------------------------

/// `fmt::Write` sink that pushes bytes straight to COM1, lock-free.
///
/// Zero-sized: the port address is the `COM1` constant, so there is no
/// per-instance state to carry.
struct EmergencyWriter;

impl fmt::Write for EmergencyWriter {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        emergency_write_str(s);
        Ok(())
    }
}

/// Configure the COM1 UART for 115200 8N1 with the FIFO on.
fn emergency_init_serial() {
    // SAFETY: see `logger::SerialPort::init`; same fixed-port configuration
    // sequence, duplicated here so the panic path never touches the logger
    // mutex.
    outb(COM1 + 1, 0x00); // disable interrupts
    outb(COM1 + 3, 0x80); // enable DLAB
    outb(COM1, 0x01); // divisor low: 115200 baud
    outb(COM1 + 1, 0x00); // divisor high
    outb(COM1 + 3, 0x03); // 8N1, clear DLAB
    outb(COM1 + 2, 0xC7); // enable FIFO, 14-byte threshold
    outb(COM1 + 4, 0x0B); // drive RTS/DSR, enable OUT2
}

/// Write a string to COM1, expanding `\n` to `\r\n` for raw terminals.
fn emergency_write_str(s: &str) {
    for &byte in s.as_bytes() {
        if byte == b'\n' {
            emergency_write_byte(b'\r');
        }
        emergency_write_byte(byte);
    }
}

/// Send one byte to COM1, spinning until the transmit holding register is
/// empty first.
fn emergency_write_byte(byte: u8) {
    // SAFETY: `inb` reads the line status register; `outb` writes the data
    // byte. No memory or stack access; the spin only waits for the UART.
    while inb(COM1 + 5) & 0x20 == 0 {
        core::hint::spin_loop();
    }
    outb(COM1, byte);
}

/// Write `val` to the 8-bit I/O port `port`.
#[inline]
fn outb(port: u16, val: u8) {
    // SAFETY: `out dx, al` writes AL to the port named by DX. No memory or
    // stack access; flags unchanged. `nomem` is omitted so the call is an
    // ordered side effect.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, preserves_flags),
        );
    }
}

/// Read one byte from the 8-bit I/O port `port`.
#[inline]
fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: `in al, dx` reads one byte from the port named by DX into AL.
    // No memory or stack access; flags unchanged.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nostack, preserves_flags),
        );
    }
    val
}
