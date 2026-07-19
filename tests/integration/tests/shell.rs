use xenith_emu::{ExitReason, Machine};

const BOOT_LIMIT: u64 = 100_000_000;
const COMMAND_SLICE: u64 = 2_000_000;
const COMMAND_LIMIT: u64 = 30_000_000;

fn serial(machine: &Machine) -> String {
    String::from_utf8_lossy(&machine.serial_output()).into_owned()
}

fn run_command(
    machine: &mut Machine,
    command: &str,
    marker: &str,
    occurrences: usize,
) -> Result<String, String> {
    let start = machine.serial_output().len();
    machine.inject_keyboard_ascii(command).unwrap();

    let slices = COMMAND_LIMIT.div_ceil(COMMAND_SLICE);
    let mut interrupts = 0;
    for _ in 0..slices {
        let result = machine.run_for(COMMAND_SLICE);
        assert!(
            matches!(result.reason, ExitReason::InstructionLimit),
            "guest stopped while running {command:?}: {:?}\n{}",
            result.reason,
            serial(machine)
        );
        interrupts += result.interrupts;

        let output = machine.serial_output();
        let command_output = String::from_utf8_lossy(&output[start..]);
        let normalized = command_output.replace("\r\n", "\n");
        if normalized.matches(marker).count() >= occurrences && normalized.ends_with("xenith$ ") {
            return Ok(normalized);
        }
    }
    let output = machine.serial_output();
    let command_output = String::from_utf8_lossy(&output[start..]);
    Err(format!(
        "command {command:?} did not produce {marker:?} and a new prompt in {COMMAND_LIMIT} emulator-loop iterations; interrupts={interrupts}, rip={:#x}, cs={:#x}, rflags={:#x}, halted={}; output:\n{command_output}",
        machine.cpu.state.rip,
        machine.cpu.state.cs,
        machine.cpu.state.rflags,
        machine.cpu.state.halted,
    ))
}

#[test]
#[ignore = "requires `xenith-build all`; run explicitly after the 100M shell gate"]
fn shell_executes_builtins_and_coreutils_via_ps2() {
    let mut machine = xenith_integration::load_built_kernel(BOOT_LIMIT).unwrap();
    let boot = machine.run();
    assert_eq!(boot.reason, ExitReason::InstructionLimit);
    let boot_serial = String::from_utf8_lossy(&boot.serial);
    assert!(
        boot_serial.contains("Xenith shell 0.1 (type 'help')") && boot_serial.ends_with("xenith$ "),
        "100M gate did not reach an idle userspace shell:\n{boot_serial}"
    );

    let help = run_command(
        &mut machine,
        "help\n",
        "builtins: bg cd echo exit fg help jobs pid pwd",
        1,
    )
    .unwrap();
    assert!(help.contains("syntax: |, <, >, >>, trailing &, quotes"));

    let echo = run_command(&mut machine, "echo BUILTIN_OK\n", "BUILTIN_OK", 2).unwrap();
    assert!(
        echo.contains("BUILTIN_OK\n"),
        "builtin echo output: {echo:?}"
    );

    let pwd = run_command(&mut machine, "pwd\n", "\n/\n", 1).unwrap();
    assert!(pwd.contains("\n/\n"));

    let external_echo = run_command(
        &mut machine,
        "/bin/echo COREUTIL_ECHO_OK\n",
        "COREUTIL_ECHO_OK",
        2,
    )
    .unwrap();
    assert!(external_echo.contains("COREUTIL_ECHO_OK\n"));

    let uname = run_command(&mut machine, "uname\n", "\nXenith\n", 1).unwrap();
    assert!(uname.contains("\nXenith\n"));

    let ps = run_command(&mut machine, "ps\n", " PID  PPID COMMAND", 1).unwrap();
    assert!(ps.contains(" ps\n"));

    let ls = run_command(&mut machine, "ls /bin\n", "\ncoreutils\n", 1).unwrap();
    assert!(ls.contains("\ncoreutils\n"));

    let cat = run_command(
        &mut machine,
        "cat /bin/hello\n",
        "hello from Xenith ring 3",
        1,
    )
    .unwrap();
    assert!(cat.contains("hello from Xenith ring 3"));

    let memory = run_command(&mut machine, "/bin/hello\n", "XENITH_RING3_SIGNAL_OK", 1).unwrap();
    assert!(
        memory.contains("XENITH_VM_RANDOM_OK")
            && !memory.contains("XENITH_VM_RANDOM_FAIL")
            && !memory.contains("XENITH_RING3_SIGNAL_FAIL"),
        "userspace VM/RNG/signal smoke failed: {memory:?}"
    );

    let mkdir = run_command(&mut machine, "mkdir /smoke\n", "mkdir /smoke", 1).unwrap();
    assert!(!mkdir.contains("errno"), "mkdir failed: {mkdir:?}");
    let root = run_command(&mut machine, "ls /\n", "\nsmoke\n", 1).unwrap();
    assert!(root.contains("\nsmoke\n"));

    let cp = run_command(
        &mut machine,
        "cp /bin/hello /hello-copy\n",
        "cp /bin/hello /hello-copy",
        1,
    )
    .unwrap();
    assert!(!cp.contains("errno"), "cp failed: {cp:?}");
    let copied = run_command(&mut machine, "ls /\n", "\nhello-copy\n", 1).unwrap();
    assert!(copied.contains("\nhello-copy\n"));

    let mv = run_command(
        &mut machine,
        "mv /hello-copy /hello-moved\n",
        "mv /hello-copy /hello-moved",
        1,
    )
    .unwrap();
    assert!(!mv.contains("errno"), "mv failed: {mv:?}");
    let moved = run_command(&mut machine, "ls /\n", "\nhello-moved\n", 1).unwrap();
    assert!(moved.contains("\nhello-moved\n"));
    assert!(!moved.contains("\nhello-copy\n"));

    let rm = run_command(&mut machine, "rm /hello-moved\n", "rm /hello-moved", 1).unwrap();
    assert!(!rm.contains("errno"), "rm failed: {rm:?}");
    let removed = run_command(&mut machine, "ls /\n", "\nbin\n", 1).unwrap();
    assert!(!removed.contains("\nhello-moved\n"));

    let date = run_command(&mut machine, "date\n", " UTC (Unix)", 1).unwrap();
    assert!(date.contains(" UTC (Unix)"));
}
