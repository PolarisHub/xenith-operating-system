#![cfg(windows)]

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use xenith_emu::{Machine, MachineConfig};
use xenith_vmm::{WhpPartition, WhpRunReason};

static WHP_ARTIFACT_LOCK: Mutex<()> = Mutex::new(());

#[test]
#[ignore = "requires fresh build/kernel.elf, build/initramfs.cpio, and WHP"]
fn whp_boots_built_kernel_to_userspace_shell() {
    let _guard = WHP_ARTIFACT_LOCK.lock().expect("lock WHP artifact gates");
    assert!(
        WhpPartition::is_available(),
        "Windows Hypervisor Platform is required for this artifact gate"
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel = fs::read(root.join("build/kernel.elf")).expect("read fresh built kernel");
    let initrd = fs::read(root.join("build/initramfs.cpio")).expect("read fresh built initramfs");
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 128 * 1024 * 1024,
        instruction_limit: 1_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    machine
        .load_kernel(&kernel, Some(&initrd))
        .expect("load Xenith kernel handoff");
    let mut partition = WhpPartition::create_machine(1).expect("create accelerated partition");
    let summary = partition
        .run_machine(&mut machine, Duration::from_secs(10), 1_000_000)
        .expect("run Xenith through WHP");
    assert_eq!(summary.reason, WhpRunReason::ShellReady);
    let serial_bytes = machine.serial_output();
    let serial = String::from_utf8_lossy(&serial_bytes);
    for marker in [
        "xenith: init",
        "mm: ready",
        "scheduler: ready",
        "user: init spawned",
        "Xenith userspace init",
        "xenith$ ",
    ] {
        assert!(serial.contains(marker), "missing serial marker {marker:?}");
    }
}

#[test]
#[ignore = "requires fresh build/kernel.elf, build/initramfs.cpio, and WHP with two VPs"]
fn whp_brings_second_processor_online_and_reaches_userspace_shell() {
    let _guard = WHP_ARTIFACT_LOCK.lock().expect("lock WHP artifact gates");
    assert!(
        WhpPartition::is_available(),
        "Windows Hypervisor Platform is required for this artifact gate"
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel = fs::read(root.join("build/kernel.elf")).expect("read fresh built kernel");
    let initrd = fs::read(root.join("build/initramfs.cpio")).expect("read fresh built initramfs");
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 256 * 1024 * 1024,
        cpu_count: 2,
        instruction_limit: 2_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    machine
        .load_kernel(&kernel, Some(&initrd))
        .expect("load two-processor Xenith handoff");
    let mut partition = WhpPartition::create_machine(2).expect("create two-VP partition");
    let summary = partition
        .run_machine(&mut machine, Duration::from_secs(20), 2_000_000)
        .expect("run two-processor Xenith through WHP");
    assert_eq!(summary.reason, WhpRunReason::ShellReady);
    assert_eq!(summary.active_processor_mask & 0b11, 0b11);
    let serial_bytes = machine.serial_output();
    let serial = String::from_utf8_lossy(&serial_bytes);
    for marker in [
        "xenith.acpi: 2 LAPIC(s), 1 IOAPIC(s) enumerated",
        "xenith.smp: CPU 1 online (x2APIC 1",
        "xenith.smp: 2 CPU(s) online, 2 discovered",
        "user: init spawned",
        "xenith$ ",
    ] {
        assert!(serial.contains(marker), "missing serial marker {marker:?}");
    }
}
