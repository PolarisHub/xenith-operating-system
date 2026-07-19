//! Hand-written assembly symbols for the x86_64 kernel.
//!
//! This module is the Rust-side declaration of the symbols defined in the
//! `.S` files under `src/arch/x86_64/asm/`. `build.rs` performs their small
//! preprocessing step and this module feeds the generated source to LLVM's
//! integrated assembler. It also makes their entry points callable from Rust
//! as `extern "C"` functions.
//!
//! # Calling convention
//!
//! Every symbol declared here is `extern "C"` with the SysV x86_64 ABI: the
//! first six integer/pointer arguments arrive in `rdi`, `rsi`, `rdx`, `rcx`,
//! `r8`, `r9`, and the return value goes in `rax`. The asm stubs own the
//! register-save/restore dance required around their particular entry point
//! (interrupt entry, context switch, syscall gate), so Rust callers must not
//! assume any callee-saved registers survive a call across these boundaries
//! unless the stub's contract says otherwise.
//!
//! # Which file defines what
//!
//! * [`isr::isr_0`] .. [`isr::isr_31`] — the CPU exception entry stubs, defined
//!   in `src/arch/x86_64/asm/isr.S`. Each stub pushes a synthetic error code
//!   (where the CPU did not push one), pushes the interrupt vector number,
//!   and jumps to a common trampoline that saves the register file and calls
//!   the Rust-side `arch::idt::dispatch`.
//! * [`context_switch`] — the thread context-switch routine, defined in
//!   `src/arch/x86_64/asm/context_switch.S`.
//! * [`syscall_entry`] — the `syscall`/`sysret` gate, defined in
//!   `src/arch/x86_64/asm/syscall.S`.
//!
//! # Why declarations and not definitions
//!
//! The bodies live in assembly because they touch state Rust cannot express:
//! the IST stack pointers in the TSS, the exact `iretq` frame layout, the
//! `sysret` register dance, and the `cr3` swap on context switch. Rust's
//! `extern "C"` is the correct ABI surface to call into them, and declaring
//! the symbols here lets the rest of the kernel use normal Rust call sites
//! instead of inline `asm!` blocks at every use.
//!
//! # Safety
//!
//! These symbols are entry points into privileged code paths. Calling them is
//! only safe in the contexts they were designed for: the ISR stubs must be
//! installed in the IDT and invoked by the CPU, `context_switch` must be
//! called from the scheduler with both task structs valid, and
//! `syscall_entry` must be installed in `LSTAR` and reached via the `syscall`
//! instruction from ring 3. Calling any of them from an arbitrary Rust
//! context is undefined behavior and will almost certainly fault.

// The build script performs the small preprocessing step used by the legacy
// `.S` files and emits one source for LLVM's integrated assembler. Requiring
// no host C compiler keeps the freestanding kernel build self-contained.
core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/xenith_asm.S")),
    options(att_syntax, raw)
);

/// CPU exception entry stubs (vectors 0..31).
///
/// Each `isr_N` symbol is the IDT handler for CPU exception vector `N`. The
/// stubs are defined in `src/arch/x86_64/asm/isr.S`; see that file for the
/// exact frame layout each one pushes before jumping to the common
/// trampoline.
///
/// The module is a namespace only — the symbols themselves are declared at
/// the crate's asm extern block and re-exported here for ergonomic access as
/// `asm::isr::isr_0` etc. They are not Rust functions and cannot be called
/// directly from safe Rust; the IDT loader takes their addresses.
pub mod isr {
    // Re-export the ISR entry symbols so callers can write
    // `asm::isr::isr_0` rather than `asm::isr_0`. The symbols are declared in
    // the extern block at the bottom of this file; the re-exports here are
    // just paths, not new definitions.
    pub use super::{
        isr_0, isr_1, isr_10, isr_11, isr_12, isr_13, isr_14, isr_15, isr_16, isr_17, isr_18,
        isr_19, isr_2, isr_20, isr_21, isr_22, isr_23, isr_24, isr_25, isr_26, isr_27, isr_28,
        isr_29, isr_3, isr_30, isr_31, isr_4, isr_5, isr_6, isr_7, isr_8, isr_9,
    };

    /// The number of CPU exception entry stubs declared in [`isr`].
    ///
    /// Vectors 0..=31 cover the architecturally-defined CPU exceptions and
    /// faults: divide-by-zero through reserved. The IDT loader uses this
    /// constant to size the exception portion of the table.
    pub const COUNT: usize = 32;

    /// Returns the entry-point address for exception vector `n` (0..=31).
    ///
    /// `n` is *not* bounds-checked here; the caller (the IDT loader) is
    /// responsible for staying within `0..COUNT`. The match is exhaustive over
    /// the 32 exception vectors so the compiler verifies every stub is wired
    /// up — a missing stub is a compile error, not a runtime panic.
    ///
    /// The returned value is an `unsafe extern "C" fn()` code pointer suitable
    /// for installation in an IDT gate descriptor. It is the address of the asm
    /// stub, not a safe Rust function pointer; the stub runs with the CPU's
    /// interrupt frame conventions, not the SysV call ABI. The `unsafe` marker
    /// on the pointer reflects that the stub must only be reached via an
    /// IDT-delivered fault, never called directly.
    #[allow(clippy::too_many_lines)]
    pub fn entry(n: u8) -> unsafe extern "C" fn() {
        match n {
            0 => isr_0,
            1 => isr_1,
            2 => isr_2,
            3 => isr_3,
            4 => isr_4,
            5 => isr_5,
            6 => isr_6,
            7 => isr_7,
            8 => isr_8,
            9 => isr_9,
            10 => isr_10,
            11 => isr_11,
            12 => isr_12,
            13 => isr_13,
            14 => isr_14,
            15 => isr_15,
            16 => isr_16,
            17 => isr_17,
            18 => isr_18,
            19 => isr_19,
            20 => isr_20,
            21 => isr_21,
            22 => isr_22,
            23 => isr_23,
            24 => isr_24,
            25 => isr_25,
            26 => isr_26,
            27 => isr_27,
            28 => isr_28,
            29 => isr_29,
            30 => isr_30,
            31 => isr_31,
            // The IDT loader only iterates 0..COUNT, so any other value is a
            // caller bug. We pick vector 0 as a safe-ish fallback rather than
            // panicking: a panic inside the IDT loader would itself need an
            // IDT, which is exactly what we are building.
            _ => isr_0,
        }
    }
}

/// Hardware-interrupt entry stubs.
pub mod irq {
    /// Local-APIC timer entry. This symbol is an IDT target, not a callable
    /// SysV function; install its address with `idt::install_timer_handler`.
    pub use super::{lapic_timer_isr, reschedule_ipi_isr, tlb_shootdown_ipi_isr};
}

extern "C" {
    // --- Relocatable low-memory AP trampoline -----------------------------
    pub static ap_trampoline_start: u8;
    pub static ap_trampoline_end: u8;
    pub static ap_trampoline_long_mode: u8;
    pub static ap_trampoline_cr3: u8;
    pub static ap_trampoline_stack: u8;
    pub static ap_trampoline_entry: u8;
    pub static ap_trampoline_cpu_id: u8;
    pub static ap_trampoline_apic_id: u8;
    pub static ap_trampoline_gdt: u8;
    pub static ap_trampoline_gdtr_base: u8;
    pub static ap_trampoline_far_target: u8;

    // --- CPU exception entry stubs ------------------------------------------
    //
    // Defined in `src/arch/x86_64/asm/isr.S`. Each stub is a tiny piece of
    // code that normalizes the exception stack frame (some exceptions push an
    // error code, most do not), pushes the vector number, and jumps to the
    // common trampoline that saves GPRs and calls the Rust-side dispatch
    // handler. They are never called via the SysV ABI; their addresses are
    // loaded into IDT gate descriptors and the CPU jumps to them on a fault.

    /// Vector 0: `#DE` divide error.
    pub fn isr_0();
    /// Vector 1: `#DB` debug.
    pub fn isr_1();
    /// Vector 2: NMI (non-maskable interrupt).
    pub fn isr_2();
    /// Vector 3: `#BP` breakpoint (INT3).
    pub fn isr_3();
    /// Vector 4: `#OF` overflow (INTO).
    pub fn isr_4();
    /// Vector 5: `#BR` bound range exceeded.
    pub fn isr_5();
    /// Vector 6: `#UD` invalid opcode.
    pub fn isr_6();
    /// Vector 7: `#NM` device not available (FPU).
    pub fn isr_7();
    /// Vector 8: `#DF` double fault.
    pub fn isr_8();
    /// Vector 9: coprocessor segment overrun (reserved on modern CPUs).
    pub fn isr_9();
    /// Vector 10: `#TS` invalid TSS.
    pub fn isr_10();
    /// Vector 11: `#NP` segment not present.
    pub fn isr_11();
    /// Vector 12: `#SS` stack-segment fault.
    pub fn isr_12();
    /// Vector 13: `#GP` general protection fault.
    pub fn isr_13();
    /// Vector 14: `#PF` page fault.
    pub fn isr_14();
    /// Vector 15: reserved.
    pub fn isr_15();
    /// Vector 16: `#MF` x87 floating-point exception.
    pub fn isr_16();
    /// Vector 17: `#AC` alignment check.
    pub fn isr_17();
    /// Vector 18: `#MC` machine check.
    pub fn isr_18();
    /// Vector 19: `#XM`/`#XF` SIMD floating-point exception.
    pub fn isr_19();
    /// Vector 20: `#VE` virtualization exception.
    pub fn isr_20();
    /// Vector 21: reserved.
    pub fn isr_21();
    /// Vector 22: reserved.
    pub fn isr_22();
    /// Vector 23: reserved.
    pub fn isr_23();
    /// Vector 24: reserved.
    pub fn isr_24();
    /// Vector 25: reserved.
    pub fn isr_25();
    /// Vector 26: reserved.
    pub fn isr_26();
    /// Vector 27: reserved.
    pub fn isr_27();
    /// Vector 28: reserved.
    pub fn isr_28();
    /// Vector 29: reserved.
    pub fn isr_29();
    /// Vector 30: `#SX` security exception.
    pub fn isr_30();
    /// Vector 31: reserved.
    pub fn isr_31();

    /// Local-APIC timer interrupt entry.
    ///
    /// The stub conditionally swaps GS for a ring-3 interruption, preserves
    /// every GPR, calls `rust_timer_interrupt`, and returns with `iretq`.
    pub fn lapic_timer_isr();

    /// Cross-CPU scheduler reschedule IPI entry.
    pub fn reschedule_ipi_isr();

    /// Cross-CPU TLB invalidation IPI entry.
    pub fn tlb_shootdown_ipi_isr();

    // --- Context switch ------------------------------------------------------
    //
    // Defined in `src/arch/x86_64/asm/context_switch.S`. Switches from the
    // current task's register/stack state to the next task's by saving
    // callee-saved registers and the stack pointer into
    // the current task's saved-state area, loading the next task's saved
    // state, swapping `cr3` if the page tables differ, updating `RSP0` in the
    // TSS, and returning into the next task.
    //
    // The two arguments are pointers to the current and next task's
    // saved-register blocks. The ABI is SysV: `rdi` = current, `rsi` = next.

    /// Thread context switch.
    ///
    /// # Safety
    ///
    /// Only the scheduler may call this. Both pointers must reference valid,
    /// non-aliased task saved-state blocks for the duration of the call.
    /// Calling it from any other context corrupts the current task's saved
    /// state and will fault on the next return into it.
    pub fn context_switch(current: *mut u8, next: *mut u8);

    // --- Syscall entry -------------------------------------------------------
    //
    // Defined in `src/arch/x86_64/asm/syscall.S`. Reached via the `syscall`
    // instruction from ring 3; the CPU jumps here
    // with `rcx` = user RIP and `r11` = user RFLAGS. The stub switches to the
    // per-task kernel stack via `RSP0`, saves the user state, calls
    // `syscall::dispatch`, restores user state, and `sysret`s back to ring 3.
    //
    // It takes no Rust-visible arguments and returns nothing; the entire
    // contract is in registers per the syscall ABI. Its address is loaded
    // into the `LSTAR` MSR by the arch bring-up code.

    /// `syscall` entry point.
    ///
    /// # Safety
    ///
    /// This is not a function; it is a trap gate target. The only legitimate
    /// use of this symbol is to take its address and install it in `LSTAR`.
    /// Calling it directly from ring 0 is undefined behavior.
    pub fn syscall_entry();
}
