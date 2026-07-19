use std::fs;
use std::path::{Path, PathBuf};

use xenith_emu::{ExitReason, Machine, MachineConfig};

fn workspace_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn hex_field(value: u32) -> [u8; 8] {
    let mut result = [b'0'; 8];
    for (index, slot) in result.iter_mut().enumerate() {
        let shift = (7 - index) * 4;
        *slot = b"0123456789abcdef"[((value >> shift) & 0xf) as usize];
    }
    result
}

fn append_newc(output: &mut Vec<u8>, inode: u32, name: &str, mode: u32, data: &[u8]) {
    let mut header = [b'0'; 110];
    header[..6].copy_from_slice(b"070701");
    let fields = [
        inode,
        mode,
        0,
        0,
        1,
        0,
        u32::try_from(data.len()).expect("fixture exceeds newc size"),
        0,
        0,
        0,
        0,
        u32::try_from(name.len() + 1).expect("fixture name exceeds newc size"),
        0,
    ];
    for (index, field) in fields.into_iter().enumerate() {
        let start = 6 + index * 8;
        header[start..start + 8].copy_from_slice(&hex_field(field));
    }
    output.extend_from_slice(&header);
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
    output.extend_from_slice(data);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
}

fn c_program_as_init(program: &[u8]) -> Vec<u8> {
    let mut archive = Vec::new();
    append_newc(&mut archive, 1, ".", 0o040755, &[]);
    append_newc(&mut archive, 2, "init", 0o100755, program);
    append_newc(&mut archive, 3, "TRAILER!!!", 0, &[]);
    archive
}

#[test]
#[ignore = "requires `xenith-build all`; boots the Xenith-built C ELF as /init"]
fn xenith_built_c_utility_executes_in_ring3() {
    let kernel_path = workspace_file("build/kernel.elf");
    let program_path = workspace_file("build/user/xenith-c-demo");
    assert!(
        kernel_path.is_file(),
        "missing {}; run xenith-build all",
        kernel_path.display()
    );
    assert!(
        program_path.is_file(),
        "missing {}; run xenith-build all",
        program_path.display()
    );
    let kernel = fs::read(kernel_path).unwrap();
    let initrd = c_program_as_init(&fs::read(program_path).unwrap());
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 512 * 1024 * 1024,
        instruction_limit: 100_000_000,
        mirror_serial: false,
        ..MachineConfig::default()
    });
    machine.load_kernel(&kernel, Some(&initrd)).unwrap();

    let mut reached_launch = false;
    for _ in 0..1_000 {
        let summary = machine.run_for(100_000);
        if String::from_utf8_lossy(&machine.serial_output()).contains("user: init spawned") {
            reached_launch = true;
            break;
        }
        assert_eq!(summary.reason, ExitReason::InstructionLimit, "{summary:?}");
    }
    assert!(reached_launch, "kernel did not launch the C /init image");

    let mut observed = false;
    for _ in 0..1_000_000 {
        let summary = machine.run_for(10);
        let serial = machine.serial_output();
        if String::from_utf8_lossy(&serial).contains("XENITH_C_TOOLCHAIN_OK") {
            observed = true;
            break;
        }
        assert_eq!(summary.reason, ExitReason::InstructionLimit, "{summary:?}");
    }
    assert!(
        observed,
        "C utility produced no marker:\n{}",
        String::from_utf8_lossy(&machine.serial_output())
    );
}
