//! x86_64-specific kernel primitives.
//!
//! This is the home of every instruction, CPU table, and register layout that
//! is genuinely specific to the x86_64 architecture. The submodule tree is:
//!
//! ```text
//!   x86_64/
//!     port.rs        — typed Port<IoWidth> for 8/16/32-bit PIO
//!     instructions.rs— raw insn wrappers (hlt, cli, lgdt, invlpg, wrmsr ...)
//!     msr.rs         — Msr(u32) handle + IA32_* named constants
//!     registers.rs   — Cr0 / Cr3 / Cr4 bitflag types
//!     gdt.rs         — Global Descriptor Table + segment selectors
//!     idt.rs         — Interrupt Descriptor Table + gate encoders
//!     cpu.rs         — CPUID feature detection + per-CPU topology helpers
//!     percpu.rs      — per-CPU control block reached via GS_BASE
//!     tss.rs         — Task State Segment(s) for IST + ring 3 stacks
//!     fpu.rs         — CR0/CR4 EM/MP/OSFXSR enablement + xsave area size
//!     interrupts.rs  — interrupt controller surface (8259PIC / LAPIC stubs)
//!     asm/           — hand-written .S entry trampolines (built by cc::Build)
//! ```
//!
//! Several of these files are filled in by later phases (`gdt`, `idt`, `tss`,
//! `percpu`, `fpu`, `interrupts`, `asm`). This phase lands the leaf primitives
//! (`port`, `instructions`, `msr`, `registers`) and the module root that wires
//! them together. The not-yet-written modules are declared here so the public
//! surface is fixed; their bodies grow over subsequent phases without callers
//! changing their `use` paths.
//!
//! # Safety posture
//!
//! Every function in this tree that executes a privileged instruction is
//! `unsafe` and carries a `# Safety` doc explaining the invariant the caller
//! must uphold (typically: run only in ring 0, on a CPU whose tables the
//! kernel owns). The safe wrappers above them — `early_init`, the `Port`
//! read/write methods, the `Cr0::read` helpers — establish those invariants
//! once at boot and then present a safe API to the rest of the kernel.

pub mod asm;
pub mod cpu;
pub mod fpu;
pub mod gdt;
pub mod idt;
pub mod instructions;
pub mod interrupts;
pub mod msr;
pub mod percpu;
pub mod port;
pub mod registers;
pub mod smp;
pub mod tss;
pub mod usercopy;

// Re-export the leaf types the rest of the kernel reaches for most often.
// Keeping these at the `x86_64` root means downstream `use` lines stay short
// (`use crate::arch::x86_64::Port8`) and do not have to track which submodule
// a primitive happens to live in.
pub use instructions::{
    cli, cpuid, hlt, invlpg, lgdt, lidt, ltr, pause, rdmsr, rdrand, rdseed, read_cr0, read_cr2,
    read_cr3, read_cr4, sgdt, sidt, sti, tlb_flush_all, write_cr0, write_cr3, write_cr4, wrmsr,
    InterruptGuard,
};
pub use msr::{
    Msr, IA32_EFER, IA32_FMASK, IA32_GS_BASE, IA32_KERNEL_GS_BASE, IA32_LAPIC_BASE, IA32_LSTAR,
    IA32_STAR, IA32_TSC_AUX,
};
pub use port::{Port, Port16, Port32, Port8};
pub use registers::{Cr0, Cr3, Cr4};

/// Very early, allocation-free CPU setup.
///
/// Runs before the console, the log backend, or any allocator is available —
/// in the binary `_start` prologue, before [`crate::init`] is called. The
/// work done here is restricted to what *must* happen before any Rust code
/// can safely touch CPU state:
///
/// * Confirm we are in long mode (EFER.LME), enable EFER.NXE, and confirm
///   that paging is on (CR0.PG). Limine performs the transition for the BSP,
///   but Xenith owns NX because its page tables use the no-execute bit.
/// * Enable global pages and, when CPUID advertises them, SMEP/SMAP. User-copy
///   assembly opens tightly bounded SMAP windows with STAC/CLAC.
/// * Clear CR0.EM and set CR0.MP so x87/MMX/SSE instructions do not trap, and
///   set CR4.OSFXSR + CR4.OSXMMEXCPT so SSE/SSE2 are usable in ring 0 and
///   SIMD exceptions go to a dedicated vector rather than #GP.
/// * Enable the `rdrand` / `rdseed` CPU feature bits if present (no-op on
///   parts that lack them) so the entropy pool can use them later.
///
/// Everything that needs tables (GDT, IDT, TSS) or a per-CPU area is deferred
/// to [`init`], which runs after the console is up and can report failures.
///
/// # Safety
///
/// Must be called exactly once on the BSP, in ring 0, before any other code
/// in this module touches control registers or MSRs. Calling it on an AP
/// before the BSP has run it is harmless (the bits are idempotent) but the
/// AP bring-up path in a later phase will invoke it again under its own
/// per-CPU state.
pub fn early_init() {
    // All work is done through the safe wrappers in `instructions` and
    // `registers`; each of those encapsulates its own unsafe asm. We keep
    // `early_init` itself safe because the invariants (ring 0, single BSP
    // call, post-Limine handoff) are established by the boot contract, not
    // by something the caller can check at runtime.

    // Long-mode + paging sanity. EFER.LME bit 8 is "IA-32e mode enable";
    // CR0.PG bit 31 is "paging enable". Limine sets both before jumping to
    // us, but a misconfigured boot (wrong Limine request, stale image) is
    // worth catching now rather than as a mysterious #GP later.
    //
    // SAFETY: IA32_EFER is a valid MSR on every x86_64 part; reading it in
    // ring 0 is always permitted.
    let mut efer = unsafe { IA32_EFER.read() };
    debug_assert!(
        (efer >> 8) & 1 == 1,
        "xenith: EFER.LME not set — Limine did not enable long mode"
    );
    let cr0 = Cr0::read();
    debug_assert!(
        cr0.contains(Cr0::PAGING),
        "xenith: CR0.PG not set — paging is off at early_init"
    );

    // Every address-space builder below relies on the page-table NX bit for
    // W^X. Do not silently boot a CPU that would interpret that bit as
    // reserved: fail at the architectural boundary instead of much later as
    // an opaque page fault. Extended leaf 8000_0001H:EDX[20] advertises NX.
    let max_extended = unsafe { cpuid(0x8000_0000) }.eax;
    let has_nx = max_extended >= 0x8000_0001 && unsafe { cpuid(0x8000_0001) }.edx & (1 << 20) != 0;
    assert!(has_nx, "xenith: CPU does not support execute-disable pages");
    efer |= 1 << 11;
    // SAFETY: CPUID advertised NX, IA32_EFER exists on every x86_64 CPU, and
    // preserving the other bits keeps the bootloader's LME setting intact.
    unsafe { IA32_EFER.write(efer) };

    // CR0: clear EM (emulate x87), set MP (monitor coprocessor), set NE
    // (native x87 error reporting via #MF rather than IRQ 13). With EM clear
    // and MP set, SSE/SSE2 instructions execute natively instead of trapping
    // to an emulator that does not exist in the kernel.
    let mut cr0 = Cr0::read();
    cr0.remove(Cr0::EMULATION);
    cr0.insert(Cr0::MONITOR_COPROCESSOR | Cr0::NUMERIC_ERROR);
    unsafe { cr0.write() };

    // CR4: enable OSFXSR (full SSE save/restore state) and OSXMMEXCPT
    // (#XF for SIMD exceptions instead of #GP). Both are required for any
    // SSE usage in the kernel; without OSFXSR, `fxsave` would skip the
    // XMM/YMM state and corrupt register state across context switches.
    let mut cr4 = Cr4::read();
    cr4.insert(Cr4::OSFXSR | Cr4::OSXMMEXCPT_ENABLE);
    unsafe { cr4.write() };

    // CR4.PGE: enable global pages so the HHDM direct map and kernel code
    // segments can be marked global, evading TLB flushes on context switch.
    // We only set the bit; populating global PTEs is the mm phase's job.
    // Re-reading CR4 rather than chaining onto the insert above keeps each
    // architectural change in its own statement, which is easier to audit.
    let mut cr4 = Cr4::read();
    cr4.insert(Cr4::PAGE_GLOBAL);
    unsafe { cr4.write() };

    // Structured CPUID leaf 7 reports SMEP in EBX[7] and SMAP in EBX[20].
    // Set only advertised bits: writing an unsupported CR4 bit raises #GP.
    // SMEP prevents ring 0 from executing user mappings. SMAP additionally
    // blocks supervisor data access unless the user-copy assembly brackets
    // the exact REP MOVSB window with STAC/CLAC.
    // SAFETY: CPUID is non-privileged and leaves memory untouched.
    let structured = unsafe { cpuid(0) }.eax >= 7;
    let leaf7 = if structured {
        // SAFETY: leaf 7 exists by the maximum-leaf check above.
        Some(unsafe { cpuid(7) })
    } else {
        None
    };
    let has_smep = leaf7.is_some_and(|features| features.ebx & (1 << 7) != 0);
    let has_smap = leaf7.is_some_and(|features| features.ebx & (1 << 20) != 0);
    if has_smep || has_smap {
        let mut cr4 = Cr4::read();
        if has_smep {
            cr4.insert(Cr4::SMEP);
        }
        if has_smap {
            cr4.insert(Cr4::SMAP);
        }
        // SAFETY: every inserted bit was advertised by CPUID.7.0:EBX.
        unsafe { cr4.write() };
    }
    usercopy::set_smap_enabled(has_smap);

    // Best-effort CPUID probe for RDRAND / RDSEED. Unlike SSE these are CPUID
    // features, not CR bits; there is no "enable" bit — the instructions are
    // either present or they #UD. We probe once here so the entropy path
    // later can short-circuit without re-running CPUID on every draw. The
    // result is intentionally discarded at this phase; the entropy module
    // will re-probe when it is wired up.
    //
    // SAFETY: cpuid is a non-privileged instruction; leaf 1 is defined on
    // every x86_64 part. The `unsafe` here is surface-uniformity only.
    let feat = unsafe { cpuid(1) };
    // ECX bit 30 = RDRAND, EBX bit 18 = RDSEED (leaf 1, subleaf 0). RDSEED
    // is actually reported in EBX bit 18 only on leaf 7 subleaf 0; we read
    // leaf 1 here for the RDRAND bit and treat RDSEED as "probe later".
    let _has_rdrand = (feat.ecx >> 30) & 1 == 1;
}

/// Full architecture bring-up.
///
/// Called by [`arch::init`](crate::arch::init) after the early console and
/// log facade are registered. Builds the GDT, IDT, TSS, and per-CPU area,
/// then loads them via `lgdt` / `lidt` / `ltr` and installs the per-CPU
/// GS_BASE. After this returns, interrupts can be safely enabled and the
/// scheduler may take its first timer tick.
///
/// The heavy lifting lives in the `gdt`, `idt`, `tss`, `percpu`, and `fpu`
/// submodules; this function only sequences them. Each submodule's `init`
/// is responsible for its own error reporting through the `log` facade.
pub fn init(_boot_info: &'static limine::BootInfo) {
    // Re-run the early register manipulation. On the BSP this is redundant
    // with early_init() but harmless; on APs (future phase) init() is the
    // first arch call, so the bits must be set here too. Idempotent by design.
    early_init();

    // The real bring-up steps are stubs for now — later phases fill them in:
    //   gdt::init();        // load the GDT + kernel/user segment selectors
    //   tss::init();        // allocate a TSS + IST stacks for the BSP
    //   idt::init();        // build the IDT + install handlers
    //   percpu::init_bsp(); // set up the BSP's per-CPU block + GS_BASE
    //   fpu::init();        // finalize FPU/SSE + measure xsave area
    //
    // Each is gated behind its own submodule so this function stays a flat
    // sequence; we deliberately do not bury init logic inside early_init.
    ::log::debug!("xenith.arch: early_init done, full init pending later phases");
}
