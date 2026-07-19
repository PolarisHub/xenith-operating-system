use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use xenith_debug::{rsp, DebugClient};
use xenith_emu::{serve_debug_listener, Machine, MachineConfig};

#[test]
fn gdb_rsp_tcp_bridge_controls_a_live_emulator() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let backend_server = thread::spawn(move || {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            instruction_limit: 100,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        machine
            .load_flat(0x1000, &[0x90, 0x90, 0xf4], 0x80000)
            .unwrap();
        serve_debug_listener(&mut machine, &backend_listener, 100).unwrap();
    });

    let backend = DebugClient::connect(backend_address).unwrap();
    let rsp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rsp_address = rsp_listener.local_addr().unwrap();
    let rsp_server = thread::spawn(move || rsp::serve_listener(backend, &rsp_listener).unwrap());

    let mut gdb = TcpStream::connect(rsp_address).unwrap();
    gdb.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert!(request(&mut gdb, "qSupported:multiprocess+", true)
        .starts_with("PacketSize=4000;QStartNoAckMode+"));
    assert_eq!(request(&mut gdb, "QStartNoAckMode", true), "OK");
    assert_eq!(request(&mut gdb, "?", false), "S05");

    assert_eq!(request(&mut gdb, "P0=2a00000000000000", false), "OK");
    assert_eq!(request(&mut gdb, "p0", false), "2a00000000000000");
    assert_eq!(request(&mut gdb, "m1000,3", false), "9090f4");
    assert_eq!(request(&mut gdb, "M1002,1:90", false), "OK");
    assert_eq!(request(&mut gdb, "m1000,3", false), "909090");

    assert_eq!(request(&mut gdb, "Z0,1001,1", false), "OK");
    assert_eq!(
        request(&mut gdb, "c", false),
        "T05thread:1;swbreak:;10:0110000000000000;"
    );
    assert_eq!(request(&mut gdb, "z0,1001,1", false), "OK");
    assert_eq!(
        request(&mut gdb, "s", false),
        "T05thread:1;10:0210000000000000;"
    );
    assert_eq!(request(&mut gdb, "D", false), "OK");

    rsp_server.join().unwrap();
    backend_server.join().unwrap();
}

fn request(stream: &mut TcpStream, payload: &str, expect_ack: bool) -> String {
    stream.write_all(&packet(payload)).unwrap();
    stream.flush().unwrap();
    if expect_ack {
        assert_eq!(read_byte(stream), b'+');
    }
    assert_eq!(read_byte(stream), b'$');
    let mut encoded = Vec::new();
    loop {
        let byte = read_byte(stream);
        if byte == b'#' {
            break;
        }
        encoded.push(byte);
    }
    let expected = (hex(read_byte(stream)).unwrap() << 4) | hex(read_byte(stream)).unwrap();
    let actual = encoded
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    assert_eq!(actual, expected);
    let mut decoded = Vec::new();
    let mut bytes = encoded.into_iter();
    while let Some(byte) = bytes.next() {
        if byte == b'}' {
            decoded.push(bytes.next().unwrap() ^ 0x20);
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).unwrap()
}

fn packet(payload: &str) -> Vec<u8> {
    let checksum = payload
        .bytes()
        .fold(0u8, |sum, byte| sum.wrapping_add(byte));
    format!("${payload}#{checksum:02x}").into_bytes()
}

fn read_byte(stream: &mut TcpStream) -> u8 {
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).unwrap();
    byte[0]
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
