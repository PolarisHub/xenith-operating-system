use xenith_emu::{ExitReason, Machine, MachineConfig};

#[test]
fn interpreter_executes_real_port_io() {
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 1024 * 1024,
        instruction_limit: 100,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    machine
        .load_flat(
            0x1000,
            &[0xba, 0xf8, 0x03, 0, 0, 0xb0, b'X', 0xee, 0xf4],
            0x8_0000,
        )
        .unwrap();
    let result = machine.run();
    assert_eq!(result.reason, ExitReason::Halted);
    assert_eq!(result.serial, b"X");
}

#[test]
#[ignore = "requires `xenith-build all`; CI invokes this test explicitly"]
fn kernel_reaches_userspace_shell() {
    let result = xenith_integration::boot_built_kernel(100_000_000).unwrap();
    let serial = String::from_utf8_lossy(&result.serial);
    for marker in [
        "xenith: init",
        "mm: ready",
        "scheduler: ready",
        "user: init spawned",
        "Xenith userspace init",
        "xenith$ ",
    ] {
        assert!(
            serial.contains(marker),
            "missing {marker:?}; serial:\n{serial}"
        );
    }
}
