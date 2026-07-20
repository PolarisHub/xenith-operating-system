//! Emulator-driven integration-test helpers.

use std::path::{Path, PathBuf};

use xenith_emu::{ExitReason, FramebufferConfig, Machine, MachineConfig, RunSummary};

const PROGRESS_SLICE: u64 = 2_000_000;

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

/// Run bounded emulator slices until cumulative serial output contains a
/// marker the requested number of times.
pub fn run_until_serial(
    machine: &mut Machine,
    marker: &str,
    occurrences: usize,
    instruction_limit: u64,
) -> Result<String, String> {
    if occurrences == 0 {
        return Err("serial marker occurrence count must be nonzero".to_owned());
    }
    for _ in 0..instruction_limit.div_ceil(PROGRESS_SLICE) {
        let result = machine.run_for(PROGRESS_SLICE);
        if !matches!(result.reason, ExitReason::InstructionLimit) {
            return Err(format!(
                "guest stopped while waiting for {marker:?}: {:?}",
                result.reason
            ));
        }
        let output = String::from_utf8_lossy(&machine.serial_output()).into_owned();
        if output.matches(marker).count() >= occurrences {
            return Ok(output);
        }
    }

    Err(format!(
        "guest did not emit {marker:?} {occurrences} time(s) in {instruction_limit} emulator-loop iterations; rip={:#x}, cs={:#x}, halted={}; output:\n{}",
        machine.cpu.state.rip,
        machine.cpu.state.cs,
        machine.cpu.state.halted,
        String::from_utf8_lossy(&machine.serial_output())
    ))
}

/// Ask the graphical session to exit through its deterministic recovery
/// gesture: left Control + left Alt + Backspace (set-1 scancodes).
pub fn request_desktop_exit(machine: &mut Machine) -> Result<(), String> {
    machine
        .inject_keyboard_scancodes(&[0x1d, 0x38, 0x0e, 0x8e, 0xb8, 0x9d])
        .map_err(|error| error.to_string())
}

/// Toggle the launcher through the left Super key, including its extended
/// set-1 make and break prefixes.
pub fn toggle_desktop_launcher(machine: &mut Machine) -> Result<(), String> {
    machine
        .inject_keyboard_scancodes(&[0xe0, 0x5b, 0xe0, 0xdb])
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_wait_rejects_a_zero_occurrence_target() {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 2 * 1024 * 1024,
            mirror_serial: false,
            ..MachineConfig::default()
        });

        assert_eq!(
            run_until_serial(&mut machine, "unused", 0, 1),
            Err("serial marker occurrence count must be nonzero".to_owned())
        );
    }
}
