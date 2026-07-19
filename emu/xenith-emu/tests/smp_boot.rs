use std::fs;
use std::path::{Path, PathBuf};

use xenith_emu::{ExitReason, Machine, MachineConfig};

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
