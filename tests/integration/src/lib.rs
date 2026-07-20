//! Emulator-driven integration-test helpers.

use std::path::{Path, PathBuf};

use xenith_emu::{FramebufferConfig, Machine, MachineConfig, RunSummary};

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("integration crate is nested under tests/")
        .to_path_buf()
}

pub fn boot_built_kernel(instruction_limit: u64) -> Result<RunSummary, String> {
    let mut machine = load_built_kernel(instruction_limit)?;
    Ok(machine.run())
}

pub fn load_built_kernel(instruction_limit: u64) -> Result<Machine, String> {
    load_built_kernel_with_framebuffer(instruction_limit, None)
}

pub fn load_built_kernel_with_framebuffer(
    instruction_limit: u64,
    framebuffer: Option<FramebufferConfig>,
) -> Result<Machine, String> {
    let root = workspace_root();
    let kernel_path = root.join("build/kernel.elf");
    let initrd_path = root.join("build/initramfs.cpio");
    let kernel = std::fs::read(&kernel_path)
        .map_err(|error| format!("{}: {error}", kernel_path.display()))?;
    let initrd = std::fs::read(&initrd_path)
        .map_err(|error| format!("{}: {error}", initrd_path.display()))?;
    let mut machine = Machine::new(MachineConfig {
        memory_bytes: 512 * 1024 * 1024,
        instruction_limit,
        mirror_serial: false,
        framebuffer,
        ..MachineConfig::default()
    });
    machine
        .load_kernel(&kernel, Some(&initrd))
        .map_err(|error| error.to_string())?;
    Ok(machine)
}
