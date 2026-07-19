use std::fs;
use std::path::{Path, PathBuf};

use xenith_emu::{ExitReason, Machine, MachineConfig, MAX_EMULATED_CPUS};

fn workspace_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
#[ignore = "requires a fresh `xenith-build all`; runs two interpreted CPUs for 240M cycles"]
fn two_processor_kernel_brings_ap_online_and_reaches_shell() {
    let kernel_path = workspace_file("build/kernel.elf");
    let initrd_path = workspace_file("build/initramfs.cpio");
    let kernel = fs::read(&kernel_path).expect("read build/kernel.elf; run `xenith-build all`");
    let initrd = fs::read(&initrd_path).expect("read build/initramfs.cpio; run `xenith-build all`");
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 512 * 1024 * 1024,
        cpu_count: 2,
        instruction_limit: 240_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    machine
        .load_kernel(&kernel, Some(&initrd))
        .expect("load freshly built kernel and initramfs");

    let summary = machine.run();
    let serial = String::from_utf8_lossy(&summary.serial);
    assert_eq!(summary.reason, ExitReason::InstructionLimit, "{serial}");
    for marker in [
        "xenith.acpi: 2 LAPIC(s), 1 IOAPIC(s) enumerated",
        "xenith.smp: CPU 1 online (x2APIC 1",
        "xenith.smp: 2 CPU(s) online, 2 discovered",
        "user: init spawned",
        "Xenith shell 0.1",
        "xenith$ ",
    ] {
        assert!(serial.contains(marker), "missing {marker:?}\n{serial}");
    }
    assert_eq!(machine.cpu_count(), 2);
    assert!(machine.cpu_state(1).is_some_and(|state| state.cycles != 0));
}

#[test]
#[ignore = "requires a fresh `xenith-build all`; runs three interpreted CPUs until the shell is ready"]
fn three_processor_kernel_brings_every_ap_online_and_reaches_shell() {
    let kernel_path = workspace_file("build/kernel.elf");
    let initrd_path = workspace_file("build/initramfs.cpio");
    let kernel = fs::read(&kernel_path).expect("read build/kernel.elf; run `xenith-build all`");
    let initrd = fs::read(&initrd_path).expect("read build/initramfs.cpio; run `xenith-build all`");
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 512 * 1024 * 1024,
        cpu_count: 3,
        instruction_limit: 420_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    machine
        .load_kernel(&kernel, Some(&initrd))
        .expect("load freshly built kernel and initramfs");

    let mut remaining = 420_000_000;
    let serial = loop {
        let step = remaining.min(10_000_000);
        let summary = machine.run_for(step);
        let serial = String::from_utf8_lossy(&summary.serial).into_owned();
        if serial.contains("xenith$ ") {
            break serial;
        }
        assert_eq!(summary.reason, ExitReason::InstructionLimit, "{serial}");
        remaining -= step;
        assert!(
            remaining != 0,
            "three-CPU boot did not reach the shell\n{serial}"
        );
    };

    for marker in [
        "xenith.acpi: 3 LAPIC(s), 1 IOAPIC(s) enumerated",
        "xenith.smp: CPU 1 online (x2APIC 1",
        "xenith.smp: CPU 2 online (x2APIC 2",
        "xenith.smp: 3 CPU(s) online, 3 discovered",
        "user: init spawned",
        "Xenith shell 0.1",
        "xenith$ ",
    ] {
        assert!(serial.contains(marker), "missing {marker:?}\n{serial}");
    }
    assert_eq!(machine.cpu_count(), 3);
    for processor in 0..3 {
        assert!(
            machine
                .cpu_state(processor)
                .is_some_and(|state| state.cycles != 0),
            "CPU {processor} never executed"
        );
    }
}

#[test]
fn machine_constructs_supported_cpu_count_boundaries() {
    for cpu_count in [1, 3, MAX_EMULATED_CPUS] {
        let machine = Machine::new(MachineConfig {
            memory_bytes: 2 * 1024 * 1024,
            cpu_count,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        assert_eq!(machine.cpu_count(), cpu_count);
        assert!((0..cpu_count).all(|processor| machine.cpu_state(processor).is_some()));
        assert!(machine.cpu_state(cpu_count).is_none());
    }
}
