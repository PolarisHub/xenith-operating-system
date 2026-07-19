use std::process::Command;

#[test]
fn help_exposes_watch_backtrace_and_pie_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_xenith-debug"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("watch/unwatch/watchpoints"));
    assert!(stdout.contains("backtrace/bt"));
    assert!(stdout.contains("--load-bias ADDRESS"));
}

#[test]
fn load_bias_requires_a_symbol_image() {
    let output = Command::new(env!("CARGO_BIN_EXE_xenith-debug"))
        .args(["--load-bias", "0x400000", "--offline", "--command", "info"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("--load-bias requires --symbols"));
}
