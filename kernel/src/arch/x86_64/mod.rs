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
//!     interrupts.rs  — exception and interrupt-controller integration
//!     asm/           — hand-written .S entry trampolines (built by cc::Build)
//! ```
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
use core::sync::atomic::{AtomicBool, Ordering};

pub use instructions::{
    cli, cpuid, hlt, interrupts_enabled, invlpg, lgdt, lidt, ltr, pause, rdmsr, rdrand, rdseed,
    read_cr0, read_cr2, read_cr3, read_cr4, sfence, sgdt, sidt, sti, tlb_flush_all, wbinvd,
    write_cr0, write_cr3, write_cr4, wrmsr, InterruptGuard,
};
pub use msr::{
    Msr, IA32_EFER, IA32_FMASK, IA32_GS_BASE, IA32_KERNEL_GS_BASE, IA32_LAPIC_BASE, IA32_LSTAR,
    IA32_PAT, IA32_STAR, IA32_TSC_AUX,
};
pub use port::{Port, Port16, Port32, Port8};
pub use registers::{Cr0, Cr3, Cr4};

/// Whether initialized CPUs interpret PAT entry 4 as write-combining.
static FRAMEBUFFER_WC_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Return whether framebuffer write-combining is available on this machine.
#[inline]
#[must_use]
pub fn framebuffer_write_combining_available() -> bool {
    FRAMEBUFFER_WC_AVAILABLE.load(Ordering::Acquire)
}

/// Very early, allocation-free CPU setup.
///
/// Runs at the start of architecture bring-up, before descriptor tables and
/// the per-CPU area are installed. The work here is allocation-free so the AP
/// bootstrap can apply the same register policy before joining normal kernel
/// execution:
///
/// * Confirm we are in long mode (EFER.LME), enable EFER.NXE, and confirm
///   that paging is on (CR0.PG). Limine performs the transition for the BSP,
///   but Xenith owns NX because its page tables use the no-execute bit.
/// * Clear inherited CR4.CET and CR4.PKS state. Xenith does not provision
///   shadow stacks, indirect-branch tracking, or a supervisor protection-key
///   policy, so retaining firmware enablement would be unsafe after handoff.
/// * Enable global pages and, when CPUID advertises them, SMEP/SMAP. User-copy
///   assembly opens tightly bounded SMAP windows with STAC/CLAC.
/// * Clear CR0.EM and set CR0.MP so x87/MMX/SSE instructions do not trap, and
///   set CR4.OSFXSR + CR4.OSXMMEXCPT so SSE/SSE2 are usable in ring 0 and
///   SIMD exceptions go to a dedicated vector rather than #GP.
///
/// Everything that needs tables (GDT, IDT, TSS) or a per-CPU area is sequenced
/// by [`init`] after this register setup.
///
/// # Safety
///
/// Must be called in ring 0 once on each CPU before that CPU enables the FPU,
/// user execution, or interrupts. The BSP reaches it through [`init`]; the AP
/// bootstrap invokes it before installing CPU-local state. Its register
/// updates are idempotent.
pub fn early_init() {
    // All work is done through the safe wrappers in `instructions` and
    // `registers`; each of those encapsulates its own unsafe asm. We keep
    // `early_init` itself safe because the invariants (ring 0, one bring-up
    // call per CPU, post-loader handoff) are established by the boot contract, not
    // by something the caller can check at runtime.

    // CET and supervisor protection keys are OS-owned facilities. Firmware
    // may have used them before handoff, but Xenith does not initialise their
    // MSRs or shadow-stack mappings. Disable both before any later CR4 feature
    // write can accidentally preserve inherited policy. Clearing an
    // unsupported/reserved CR4 bit is safe because such a bit reads as zero.
    let mut cr4 = Cr4::read();
    cr4.remove(Cr4::CET | Cr4::PKS);
    // SAFETY: this write only clears the unsupported CET/PKS enables and
    // preserves every other architecturally named bit read from CR4.
    unsafe { cr4.write() };

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

    // PAT is present when CPUID.01H:EDX[16] is set. Entry 4 is selected by a
    // 4 KiB leaf PTE with PAT=1, PCD=0, PWT=0. Install one canonical table on
    // every CPU instead of preserving firmware-provided per-CPU values: PAT
    // is a per-logical-processor MSR and inconsistent AP tables would make
    // the same framebuffer PTE mean different things on different cores.
    // Entries 0..3 retain the architectural reset policy (WB, WT, UC-, UC),
    // entry 4 is WC, and entries 5..7 mirror WT, UC-, UC.
    let has_pat = unsafe { cpuid(1) }.edx & (1 << 16) != 0;
    if has_pat {
        const XENITH_PAT: u64 = 0x0007_0401_0007_0406;
        // SAFETY: CPUID advertised PAT, IA32_PAT is therefore a valid MSR,
        // and every byte contains an architecturally-defined memory type.
        unsafe { IA32_PAT.write(XENITH_PAT) };
        FRAMEBUFFER_WC_AVAILABLE.store(true, Ordering::Release);
    }

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
    // Establish the architectural register prerequisites before loading any
    // CPU table that depends on them. APs use their dedicated SMP sequence.
    early_init();

    // Configure the BSP's critical-fault IST before loading TR. RSP0 remains
    // zero until the scheduler selects a task with a real kernel stack.
    tss::init_bsp(0);
    percpu::init_for_bsp();
    fpu::init();
    idt::install_exception_handlers();
    // The SVR is enabled later during controller bring-up. Publish its 0xFF
    // gate now so the BSP and every AP that loads this shared IDT always have
    // a valid target before their local APIC can deliver a spurious vector.
    idt::install_lapic_spurious_handler();
    idt::load();

    ::log::info!("arch: descriptor tables and CPU state ready");
}
