use std::net::TcpListener;
use std::thread;

use xenith_debug::DebugClient;
use xenith_emu::{serve_debug_listener, Machine, MachineConfig};

#[test]
fn client_controls_a_live_emulator_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            instruction_limit: 100,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        machine
            .load_flat(0x1000, &[0x90, 0x90, 0xf4], 0x80000)
            .unwrap();
        serve_debug_listener(&mut machine, &listener, 100).unwrap();
    });

    let mut client = DebugClient::connect(address).unwrap();
    assert_eq!(
        client.command("break 0x1001").unwrap(),
        "ok added 0x0000000000001001"
    );
    assert_eq!(
        client.command("continue").unwrap(),
        "stop breakpoint 0x0000000000001001"
    );
    assert_eq!(
        client.command("step").unwrap(),
        "stop step 0x0000000000001002"
    );
    assert_eq!(client.command("read-memory 0x1000 3").unwrap(), "ok 9090f4");
    assert_eq!(client.command("write-memory 0x1002 90").unwrap(), "ok");
    assert_eq!(client.command("read-memory 0x1000 3").unwrap(), "ok 909090");
    assert_eq!(client.command("quit").unwrap(), "ok bye");
    server.join().unwrap();
}

#[test]
fn client_uses_watchpoints_and_frame_pointer_backtraces() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            instruction_limit: 100,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        let mut program = vec![0x48, 0xbb];
        program.extend_from_slice(&0x2000_u64.to_le_bytes());
        program.extend_from_slice(&[0x48, 0xb8]);
        program.extend_from_slice(&0xaabb_ccdd_eeff_0011_u64.to_le_bytes());
        program.extend_from_slice(&[0x48, 0x89, 0x03, 0xf4]);
        machine.load_flat(0x1000, &program, 0x80000).unwrap();
        serve_debug_listener(&mut machine, &listener, 100).unwrap();
    });

    let mut client = DebugClient::connect(address).unwrap();
    assert_eq!(client.command("write-register rbp 0x70000").unwrap(), "ok");
    assert_eq!(
        client
            .command("write-memory 0x70000 00000000000000000020000000000000")
            .unwrap(),
        "ok"
    );
    assert_eq!(
        client.command("backtrace 4").unwrap(),
        "ok backtrace 0x0000000000001000 0x0000000000002000"
    );
    assert_eq!(
        client.command("watch 0x2000 8").unwrap(),
        "ok added 0x0000000000002000 8"
    );
    assert_eq!(
        client.command("continue").unwrap(),
        "stop watchpoint 0x0000000000002000 8 0x0000000000001017"
    );
    assert_eq!(client.command("quit").unwrap(), "ok bye");
    server.join().unwrap();
}
