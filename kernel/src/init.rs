//! Dependency-ordered bootstrap for the boot processor.

use core::arch::asm;

use xenith_types::PhysAddr;

/// Bring every boot-critical subsystem online and dispatch the first task.
pub fn init(boot_info: &'static limine::BootInfo) {
    // COM1 is the only diagnostic surface available before the logger and
    // allocator exist. Reinitialising it later in `devices::init` is safe.
    crate::devices::serial::COM1.lock().init();
    crate::log::init(::log::LevelFilter::Info);
    ::log::info!("xenith: init");

    crate::console::init(boot_info);
    ::log::info!("console: ready");
    crate::devices::framebuffer::splash_progress(70);

    crate::arch::init(boot_info);
    crate::devices::framebuffer::splash_progress(74);

    crate::mm::init(boot_info);
    ::log::info!("mm: ready");
    crate::devices::framebuffer::splash_progress(80);

    if let Some(rsdp) = PhysAddr::new(boot_info.rsdp).filter(|address| address.as_u64() != 0) {
        crate::acpi::init(rsdp);
        ::log::info!("acpi: tables ready");
    } else {
        ::log::warn!("acpi: boot source supplied no RSDP");
    }
    crate::devices::framebuffer::splash_progress(84);

    // Controller discovery follows ACPI, while exceptions were installed
    // earlier so faults during allocator bring-up remain diagnosable.
    crate::arch::x86_64::interrupts::pic::init();
    crate::arch::x86_64::interrupts::apic::init();
    crate::arch::x86_64::interrupts::ioapic::init();
    crate::time::init();
    crate::devices::framebuffer::splash_progress(88);

    crate::sched::init(boot_info);
    crate::syscall::init();
    crate::arch::x86_64::smp::init(xenith_boot::BootInfo::new(boot_info));
    ::log::info!("scheduler: ready");
    crate::devices::framebuffer::splash_progress(92);

    crate::devices::init(boot_info);
    crate::net::init();
    crate::fs::init(boot_info);
    crate::devices::framebuffer::splash_progress(96);
    if crate::devices::framebuffer::upgrade_terminal() {
        ::log::info!("xenith.term: framebuffer VT100 renderer ready");
    }
    crate::devices::framebuffer::splash_progress(98);
    if crate::user::init(boot_info) {
        ::log::info!("user: init spawned");
        crate::devices::framebuffer::splash_progress(100);
    } else {
        ::log::error!("user: init launch failed");
        crate::devices::framebuffer::dismiss_splash();
        crate::kprintln!("xenith: failed to launch /init");
    }

    // Interrupts must be live before the first user task is dispatched: its
    // timeslicing and blocking I/O depend on the timer and device IRQs.
    // SAFETY: the IDT, interrupt controllers, scheduler, and per-CPU state
    // were all published above; STI only changes RFLAGS.IF.
    unsafe { asm!("sti", options(nomem, nostack)) };
    crate::sched::schedule_next();
    ::log::info!("xenith: boot task resumed");
}
