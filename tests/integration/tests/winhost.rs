use xenith_emu::{ExitReason, FramebufferConfig, Machine};

const BOOT_LIMIT: u64 = 100_000_000;
const SHELL_LIMIT: u64 = 40_000_000;
const COMMAND_LIMIT: u64 = 160_000_000;
const COMMAND_SLICE: u64 = 2_000_000;
const PROMPT: &str = "xenith$ ";
const FIXTURE_LINE: &str = "Xenith Win64 fixture";

fn run_until_prompt(machine: &mut Machine, start: usize) -> Result<String, String> {
    for _ in 0..COMMAND_LIMIT.div_ceil(COMMAND_SLICE) {
        let result = machine.run_for(COMMAND_SLICE);
        if !matches!(result.reason, ExitReason::InstructionLimit) {
            return Err(format!(
                "guest stopped while running the Win64 fixture: {:?}",
                result.reason
            ));
        }
        let output = machine.serial_output();
        let command_output = String::from_utf8_lossy(&output[start..]).replace('\r', "");
        if command_output.ends_with(PROMPT) {
            return Ok(command_output);
        }
    }

    let output = machine.serial_output();
    Err(format!(
        "Win64 fixture did not return to the shell prompt; rip={:#x}, cs={:#x}, halted={}; output:\n{}",
        machine.cpu.state.rip,
        machine.cpu.state.cs,
        machine.cpu.state.halted,
        String::from_utf8_lossy(&output[start..])
    ))
}

fn run_fixture(machine: &mut Machine, command: &str) {
    let start = machine.serial_output().len();
    machine.inject_keyboard_ascii(command).unwrap();
    let output = run_until_prompt(machine, start).unwrap();

    assert_eq!(
        output.lines().filter(|line| *line == FIXTURE_LINE).count(),
        1,
        "fixture output was not exactly one complete line:\n{output}"
    );
    assert!(
        output.contains("\nXenith Win64 fixture\nxenith$ "),
        "fixture output was not immediately followed by a restored prompt:\n{output}"
    );
    assert!(
        !output.contains("xenith-winhost:"),
        "loader error:\n{output}"
    );
    assert!(!output.contains("NTSTATUS"), "loader error:\n{output}");
    assert!(
        !output.contains("sh: tcsetpgrp:"),
        "foreground process-group transfer failed:\n{output}"
    );
    assert!(!output.contains("panic"), "guest panic:\n{output}");
}

#[test]
#[ignore = "requires `xenith-build all`; explicit booted Win64 console-host gate"]
fn win64_console_fixture_executes_through_booted_host() {
    let mut machine = xenith_integration::load_built_kernel_with_framebuffer(
        BOOT_LIMIT,
        Some(FramebufferConfig {
            width: 320,
            height: 200,
        }),
    )
    .unwrap();
    let desktop =
        xenith_integration::run_until_serial(&mut machine, "XENITH_DESKTOP_READY", 1, BOOT_LIMIT)
            .unwrap();
    assert!(!desktop.contains("XENITH_DESKTOP_FAIL"));

    xenith_integration::request_desktop_exit(&mut machine).unwrap();
    let shell = xenith_integration::run_until_serial(&mut machine, PROMPT, 1, SHELL_LIMIT).unwrap();
    assert!(shell.ends_with(PROMPT));

    run_fixture(
        &mut machine,
        "/bin/xenith-winhost /tests/win64-console.exe\n",
    );
    run_fixture(
        &mut machine,
        "/bin/xenith-winhost 'C:\\Users\\Xenith\\Downloads\\win64-console.exe'\n",
    );
}
