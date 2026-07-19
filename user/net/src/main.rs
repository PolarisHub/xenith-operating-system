#![no_std]
#![no_main]

use core::fmt::Write;
use core::panic::PanicInfo;

use libuser::args::Startup;
use libuser::{Error, Result};
use xenith_abi::{
    Errno, SockAddrV4, Timespec, AF_INET, IPPROTO_ICMP, IPPROTO_UDP, NET_IF_CONFIGURED,
    NET_IF_DHCP, NET_IF_LINK_UP, SOCK_DGRAM, SOCK_RAW,
};

const CONNECT_ATTEMPTS: usize = 101;
const REPLY_ATTEMPTS: usize = 200;
const POLL_INTERVAL_MS: usize = 10;
const POLL_INTERVAL_NS: i64 = (POLL_INTERVAL_MS as i64) * 1_000_000;
const REPLY_WAIT_MS: usize = REPLY_ATTEMPTS * POLL_INTERVAL_MS;
const ICMP_PACKET_LEN: usize = 32;
const DNS_PACKET_LEN: usize = 512;
const DNS_PORT: u16 = 53;

#[no_mangle]
/// # Safety
/// `startup` must point to a loader-created startup block.
pub unsafe extern "C" fn _start(startup: *const Startup) -> ! {
    // SAFETY: required by the entry contract above.
    let startup = unsafe { startup.as_ref() };
    let name = startup
        .and_then(|args| unsafe { args.argument(0) })
        .unwrap_or(b"xenith-net");
    let command = name.rsplit(|byte| *byte == b'/').next().unwrap_or(name);
    let status = match command {
        b"ifconfig" => run_ifconfig(),
        b"ping" => startup
            .and_then(|args| unsafe { args.argument(1) })
            .map_or_else(
                || {
                    libuser::println!("usage: ping <IPv4-address>");
                    2
                },
                run_ping,
            ),
        b"nslookup" => startup
            .and_then(|args| unsafe { args.argument(1) })
            .map_or_else(
                || {
                    libuser::println!("usage: nslookup <name> [DNS-server]");
                    2
                },
                |name| {
                    let server = startup
                        .and_then(|args| unsafe { args.argument(2) })
                        .and_then(parse_ipv4);
                    run_nslookup(name, server)
                },
            ),
        b"httpget" => startup
            .and_then(|args| unsafe { args.argument(1) })
            .map_or_else(
                || {
                    libuser::println!("usage: httpget <IPv4-address> [path]");
                    2
                },
                |address| {
                    let path = startup
                        .and_then(|args| unsafe { args.argument(2) })
                        .unwrap_or(b"/");
                    run_httpget(address, path)
                },
            ),
        b"telnet" => {
            let address = startup.and_then(|args| unsafe { args.argument(1) });
            let port = startup.and_then(|args| unsafe { args.argument(2) });
            match (address, port) {
                (Some(address), Some(port)) => {
                    let message = startup.and_then(|args| unsafe { args.argument(3) });
                    run_telnet(address, port, message)
                },
                _ => {
                    libuser::println!("usage: telnet <IPv4-address> <port> [message]");
                    2
                },
            }
        },
        _ => {
            libuser::println!("usage: ifconfig | ping | nslookup | httpget | telnet");
            2
        },
    };
    libuser::syscall::exit(status)
}

fn run_ifconfig() -> i32 {
    libuser::println!("lo: flags=UP,LOOPBACK mtu 65535");
    libuser::println!("    inet 127.0.0.1 netmask 255.0.0.0");
    let mut status = match udp_loopback_probe() {
        Ok(()) => {
            libuser::println!("    loopback datagram path: ok");
            0
        },
        Err(error) => {
            report_error("ifconfig loopback probe", error);
            1
        },
    };
    for index in 0..32 {
        let info = match libuser::syscall::net_info(index) {
            Ok(info) => info,
            Err(error) if error.0 == Errno::Enodev as i32 => break,
            Err(error) => {
                report_error("ifconfig interface query", error);
                status = 1;
                break;
            },
        };
        let number = info.interface.saturating_sub(1);
        libuser::println!(
            "eth{}: flags={}{}{} mtu {}",
            number,
            if info.flags & NET_IF_LINK_UP != 0 {
                "UP"
            } else {
                "DOWN"
            },
            if info.flags & NET_IF_CONFIGURED != 0 {
                ",RUNNING"
            } else {
                ""
            },
            if info.flags & NET_IF_DHCP != 0 {
                ",DHCP"
            } else {
                ""
            },
            info.mtu
        );
        libuser::println!(
            "    ether {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            info.mac[0],
            info.mac[1],
            info.mac[2],
            info.mac[3],
            info.mac[4],
            info.mac[5]
        );
        if info.flags & NET_IF_CONFIGURED != 0 {
            print_ipv4_line("inet", info.address, Some(info.prefix_len));
            if info.gateway != [0; 4] {
                print_ipv4_line("gateway", info.gateway, None);
            }
            for dns in info.dns_servers {
                if dns != [0; 4] {
                    print_ipv4_line("dns", dns, None);
                }
            }
            if info.flags & NET_IF_DHCP != 0 {
                libuser::println!(
                    "    lease {} seconds remaining",
                    info.lease_remaining_seconds
                );
            }
        } else {
            libuser::println!("    inet pending DHCP lease");
        }
    }
    status
}

fn print_ipv4_line(label: &str, address: [u8; 4], prefix: Option<u8>) {
    if let Some(prefix) = prefix {
        libuser::println!(
            "    {} {}.{}.{}.{}/{}",
            label,
            address[0],
            address[1],
            address[2],
            address[3],
            prefix
        );
    } else {
        libuser::println!(
            "    {} {}.{}.{}.{}",
            label,
            address[0],
            address[1],
            address[2],
            address[3]
        );
    }
}

struct StackWriter<'a> {
    bytes: &'a mut [u8],
    length: usize,
}

impl core::fmt::Write for StackWriter<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self
            .length
            .checked_add(text.len())
            .ok_or(core::fmt::Error)?;
        let target = self
            .bytes
            .get_mut(self.length..end)
            .ok_or(core::fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.length = end;
        Ok(())
    }
}

fn run_httpget(address_text: &[u8], path_bytes: &[u8]) -> i32 {
    let Some(address) = parse_ipv4(address_text) else {
        libuser::println!("httpget: invalid IPv4 address");
        return 2;
    };
    let Ok(path) = core::str::from_utf8(path_bytes) else {
        libuser::println!("httpget: path is not UTF-8");
        return 2;
    };
    if !path.starts_with('/') || path.bytes().any(|byte| byte.is_ascii_control()) {
        libuser::println!("httpget: path must begin with '/' and contain no control bytes");
        return 2;
    }
    let socket = match tcp_connect(address, 80) {
        Ok(socket) => socket,
        Err(error) => {
            report_error("httpget connect", error);
            return 1;
        },
    };
    let mut request = [0u8; 768];
    let mut writer = StackWriter {
        bytes: &mut request,
        length: 0,
    };
    let formatted = write!(
        &mut writer,
        "GET {} HTTP/1.0\r\nHost: {}.{}.{}.{}\r\nUser-Agent: xenith-net/1\r\nConnection: close\r\n\r\n",
        path,
        address[0],
        address[1],
        address[2],
        address[3]
    );
    let length = writer.length;
    if formatted.is_err() {
        libuser::println!("httpget: request is too large");
        let _ = libuser::syscall::close(socket);
        return 2;
    }
    let status = match libuser::syscall::send(socket, &request[..length]) {
        Ok(written) if written == length => match receive_to_stdout(socket, 200) {
            Ok(received) if received != 0 => 0,
            Ok(_) => {
                libuser::println!("httpget: peer closed without a response");
                1
            },
            Err(error) => {
                report_error("httpget receive", error);
                1
            },
        },
        Ok(_) => 1,
        Err(error) => {
            report_error("httpget send", error);
            1
        },
    };
    let _ = libuser::syscall::close(socket);
    status
}

fn run_telnet(address_text: &[u8], port_text: &[u8], message: Option<&[u8]>) -> i32 {
    let Some(address) = parse_ipv4(address_text) else {
        libuser::println!("telnet: invalid IPv4 address");
        return 2;
    };
    let Some(port) = parse_port(port_text) else {
        libuser::println!("telnet: invalid port");
        return 2;
    };
    let socket = match tcp_connect(address, port) {
        Ok(socket) => socket,
        Err(error) => {
            report_error("telnet connect", error);
            return 1;
        },
    };
    let result = if let Some(message) = message {
        send_telnet_line(socket, message).and_then(|()| receive_to_stdout(socket, 100).map(|_| ()))
    } else {
        let _ = receive_to_stdout(socket, 20);
        let mut line = [0u8; 512];
        loop {
            let length = match libuser::syscall::read(libuser::io::STDIN, &mut line) {
                Ok(0) => break Ok(()),
                Ok(length) => length,
                Err(error) => break Err(error),
            };
            if let Err(error) = libuser::syscall::send(socket, &line[..length]) {
                break Err(error);
            }
            if let Err(error) = receive_to_stdout(socket, 20) {
                break Err(error);
            }
        }
    };
    let _ = libuser::syscall::close(socket);
    match result {
        Ok(()) => 0,
        Err(error) => {
            report_error("telnet", error);
            1
        },
    }
}

fn send_telnet_line(socket: i32, message: &[u8]) -> Result<()> {
    if message.len() > 1_398 {
        return Err(Error(Errno::Emsgsize as i32));
    }
    let mut line = [0u8; 1_400];
    line[..message.len()].copy_from_slice(message);
    let mut length = message.len();
    if !message.ends_with(b"\n") {
        line[length] = b'\r';
        line[length + 1] = b'\n';
        length += 2;
    }
    match libuser::syscall::send(socket, &line[..length])? {
        written if written == length => Ok(()),
        _ => Err(Error(Errno::Eio as i32)),
    }
}

fn parse_port(text: &[u8]) -> Option<u16> {
    let mut value = 0u32;
    if text.is_empty() {
        return None;
    }
    for byte in text {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(*byte - b'0'))?;
    }
    u16::try_from(value).ok().filter(|port| *port != 0)
}

fn tcp_connect(address: [u8; 4], port: u16) -> Result<i32> {
    let socket =
        libuser::syscall::socket(AF_INET, xenith_abi::SOCK_STREAM, xenith_abi::IPPROTO_TCP)?;
    let peer = SockAddrV4::new(address, port);
    for _ in 0..CONNECT_ATTEMPTS * 5 {
        match libuser::syscall::connect(socket, &peer) {
            Ok(()) => return Ok(socket),
            Err(error)
                if matches!(
                    error.0,
                    value if value == Errno::Eagain as i32 || value == Errno::Einprogress as i32
                ) =>
            {
                poll_delay();
            },
            Err(error) if error.0 == Errno::Eisconn as i32 => return Ok(socket),
            Err(error) => {
                let _ = libuser::syscall::close(socket);
                return Err(error);
            },
        }
    }
    let _ = libuser::syscall::close(socket);
    Err(Error(Errno::Eagain as i32))
}

fn receive_to_stdout(socket: i32, idle_attempts: usize) -> Result<usize> {
    let mut total = 0usize;
    let mut idle = 0usize;
    let mut bytes = [0u8; xenith_abi::MAX_SOCKET_IO];
    while idle < idle_attempts {
        match libuser::syscall::recv(socket, &mut bytes) {
            Ok(0) => break,
            Ok(length) => {
                libuser::io::write_all(libuser::io::STDOUT, &bytes[..length])?;
                total = total.saturating_add(length);
                idle = 0;
            },
            Err(error) if error.0 == Errno::Eagain as i32 => {
                idle += 1;
                poll_delay();
            },
            Err(error) if error.0 == Errno::Econnreset as i32 && total != 0 => break,
            Err(error) => return Err(error),
        }
    }
    Ok(total)
}

fn udp_loopback_probe() -> Result<()> {
    let server = libuser::syscall::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)?;
    let result = udp_loopback_probe_with_server(server);
    let _ = libuser::syscall::close(server);
    result
}

fn udp_loopback_probe_with_server(server: i32) -> Result<()> {
    let process = libuser::syscall::getpid().unwrap_or(1);
    let port = 49_152 + u16::try_from(process % 10_000).unwrap_or(0);
    let address = SockAddrV4::new([127, 0, 0, 1], port);
    libuser::syscall::bind(server, &address)?;

    let client = libuser::syscall::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)?;
    let result = udp_loopback_probe_with_pair(server, client, &address);
    let _ = libuser::syscall::close(client);
    result
}

fn udp_loopback_probe_with_pair(server: i32, client: i32, address: &SockAddrV4) -> Result<()> {
    const PROBE: &[u8] = b"xenith-loopback";
    libuser::syscall::connect(client, address)?;
    if libuser::syscall::send(client, PROBE)? != PROBE.len() {
        return Err(Error(Errno::Eio as i32));
    }
    let mut reply = [0u8; 32];
    let length = libuser::syscall::recv(server, &mut reply)?;
    if length != PROBE.len() || reply[..length] != *PROBE {
        return Err(Error(Errno::Eio as i32));
    }
    Ok(())
}

fn run_ping(text: &[u8]) -> i32 {
    let Some(destination) = parse_ipv4(text) else {
        libuser::println!("ping: invalid IPv4 address");
        return 2;
    };
    let identifier = ping_identifier();
    let socket = match libuser::syscall::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) {
        Ok(socket) => socket,
        Err(error) => {
            report_error("ping socket", error);
            return 1;
        },
    };
    let local = SockAddrV4::new([0, 0, 0, 0], identifier);
    if let Err(error) = libuser::syscall::bind(socket, &local) {
        report_error("ping bind", error);
        let _ = libuser::syscall::close(socket);
        return 1;
    }
    let peer = SockAddrV4::new(destination, identifier);
    if let Err(error) = connect_with_arp_retry(socket, &peer) {
        report_error("ping connect", error);
        let _ = libuser::syscall::close(socket);
        return 1;
    }
    libuser::println!(
        "PING {}.{}.{}.{}: {} data bytes",
        destination[0],
        destination[1],
        destination[2],
        destination[3],
        ICMP_PACKET_LEN - 8
    );
    let status = ping_once(socket, destination, identifier);
    let _ = libuser::syscall::close(socket);
    status
}

fn connect_with_arp_retry(socket: i32, peer: &SockAddrV4) -> Result<()> {
    for attempt in 0..CONNECT_ATTEMPTS {
        match libuser::syscall::connect(socket, peer) {
            Ok(()) => return Ok(()),
            Err(error) if error.0 == Errno::Eagain as i32 && attempt + 1 < CONNECT_ATTEMPTS => {
                poll_delay();
            },
            Err(error) => return Err(error),
        }
    }
    Err(Error(Errno::Eagain as i32))
}

fn run_nslookup(name: &[u8], explicit_server: Option<[u8; 4]>) -> i32 {
    let server = match explicit_server.or_else(configured_dns_server) {
        Some(server) => server,
        None => {
            libuser::println!("nslookup: no DHCP DNS server is configured");
            return 1;
        },
    };
    let transaction_id = (libuser::syscall::getpid().unwrap_or(1) as u16) ^ 0x584e;
    let mut query = [0u8; DNS_PACKET_LEN];
    let query_length = match write_dns_query(&mut query, transaction_id, name) {
        Some(length) => length,
        None => {
            libuser::println!("nslookup: invalid DNS name");
            return 2;
        },
    };
    let socket = match libuser::syscall::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) {
        Ok(socket) => socket,
        Err(error) => {
            report_error("nslookup socket", error);
            return 1;
        },
    };
    let peer = SockAddrV4::new(server, DNS_PORT);
    let result = nslookup_with_socket(socket, &peer, name, transaction_id, &query[..query_length]);
    let _ = libuser::syscall::close(socket);
    match result {
        Ok(address) => {
            libuser::println!(
                "Name: {}",
                core::str::from_utf8(name).unwrap_or("<invalid>")
            );
            print_ipv4_line("Address:", address, None);
            0
        },
        Err(error) => {
            report_error("nslookup", error);
            1
        },
    }
}

fn configured_dns_server() -> Option<[u8; 4]> {
    for index in 0..32 {
        let info = libuser::syscall::net_info(index).ok()?;
        if let Some(server) = info
            .dns_servers
            .into_iter()
            .find(|address| *address != [0; 4])
        {
            return Some(server);
        }
    }
    None
}

fn nslookup_with_socket(
    socket: i32,
    peer: &SockAddrV4,
    _name: &[u8],
    transaction_id: u16,
    query: &[u8],
) -> Result<[u8; 4]> {
    connect_with_arp_retry(socket, peer)?;
    if libuser::syscall::send(socket, query)? != query.len() {
        return Err(Error(Errno::Eio as i32));
    }
    let mut response = [0u8; DNS_PACKET_LEN];
    for _ in 0..REPLY_ATTEMPTS {
        match libuser::syscall::recv(socket, &mut response) {
            Ok(length) => {
                return parse_dns_a(&response[..length], transaction_id)
                    .ok_or(Error(Errno::Enoent as i32));
            },
            Err(error) if error.0 == Errno::Eagain as i32 => poll_delay(),
            Err(error) => return Err(error),
        }
    }
    Err(Error(Errno::Eagain as i32))
}

fn write_dns_query(output: &mut [u8], transaction_id: u16, name: &[u8]) -> Option<usize> {
    if output.len() < 17 || name.is_empty() || name.len() > 253 {
        return None;
    }
    output.fill(0);
    output[..2].copy_from_slice(&transaction_id.to_be_bytes());
    output[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    output[4..6].copy_from_slice(&1u16.to_be_bytes());
    let name = name.strip_suffix(b".").unwrap_or(name);
    let mut offset = 12usize;
    for label in name.split(|byte| *byte == b'.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
        {
            return None;
        }
        let end = offset.checked_add(label.len() + 1)?;
        if end + 5 > output.len() {
            return None;
        }
        output[offset] = label.len() as u8;
        output[offset + 1..end].copy_from_slice(label);
        offset = end;
    }
    output[offset] = 0;
    output[offset + 1..offset + 3].copy_from_slice(&1u16.to_be_bytes());
    output[offset + 3..offset + 5].copy_from_slice(&1u16.to_be_bytes());
    Some(offset + 5)
}

fn parse_dns_a(bytes: &[u8], transaction_id: u16) -> Option<[u8; 4]> {
    if bytes.len() < 12 || u16::from_be_bytes([bytes[0], bytes[1]]) != transaction_id {
        return None;
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    if flags & 0x8000 == 0 || flags & 0x7a0f != 0 {
        return None;
    }
    let questions = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    let answers = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
    if questions > 16 || answers > 128 {
        return None;
    }
    let mut offset = 12usize;
    for _ in 0..questions {
        offset = skip_dns_name(bytes, offset)?.checked_add(4)?;
        if offset > bytes.len() {
            return None;
        }
    }
    for _ in 0..answers {
        offset = skip_dns_name(bytes, offset)?;
        let fixed = bytes.get(offset..offset.checked_add(10)?)?;
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let length = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let data_start = offset + 10;
        let data_end = data_start.checked_add(length)?;
        let data = bytes.get(data_start..data_end)?;
        if record_type == 1 && class == 1 && data.len() == 4 {
            return data.try_into().ok();
        }
        offset = data_end;
    }
    None
}

fn skip_dns_name(bytes: &[u8], mut offset: usize) -> Option<usize> {
    let original = offset;
    let mut consumed = 0usize;
    let mut jumped = false;
    let mut depth = 0usize;
    loop {
        let length = *bytes.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let low = *bytes.get(offset + 1)?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            if pointer >= offset || depth >= 16 {
                return None;
            }
            if !jumped {
                consumed = offset + 2 - original;
            }
            offset = pointer;
            jumped = true;
            depth += 1;
        } else if length == 0 {
            return Some(if jumped {
                original + consumed
            } else {
                offset + 1
            });
        } else if length <= 63 {
            offset = offset.checked_add(usize::from(length) + 1)?;
            if offset > bytes.len() {
                return None;
            }
        } else {
            return None;
        }
    }
}

fn ping_once(socket: i32, destination: [u8; 4], identifier: u16) -> i32 {
    let sequence = 1u16;
    let request = echo_request(identifier, sequence);
    let started = match libuser::syscall::clock_gettime() {
        Ok(time) => time,
        Err(error) => {
            report_error("ping clock", error);
            return 1;
        },
    };
    match libuser::syscall::send(socket, &request) {
        Ok(written) if written == request.len() => {},
        Ok(_) => {
            report_error("ping send", Error(Errno::Eio as i32));
            return 1;
        },
        Err(error) => {
            report_error("ping send", error);
            return 1;
        },
    }

    let mut reply = [0u8; 128];
    for _ in 0..REPLY_ATTEMPTS {
        match libuser::syscall::recv(socket, &mut reply) {
            Ok(length) if valid_echo_reply(&reply[..length], identifier, sequence) => {
                let finished = libuser::syscall::clock_gettime().unwrap_or(started);
                let micros = elapsed_micros(started, finished);
                libuser::println!(
                    "{} bytes from {}.{}.{}.{}: icmp_seq={} time={}.{:03} ms",
                    length,
                    destination[0],
                    destination[1],
                    destination[2],
                    destination[3],
                    sequence,
                    micros / 1_000,
                    micros % 1_000
                );
                return 0;
            },
            Ok(_) => {},
            Err(error) if error.0 == Errno::Eagain as i32 => {},
            Err(error) => {
                report_error("ping receive", error);
                return 1;
            },
        }
        poll_delay();
    }
    libuser::println!("ping: timeout after {} ms", REPLY_WAIT_MS);
    1
}

fn echo_request(identifier: u16, sequence: u16) -> [u8; ICMP_PACKET_LEN] {
    let mut packet = [0u8; ICMP_PACKET_LEN];
    packet[0] = 8;
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..].copy_from_slice(b"xenith-icmp-echo-payload");
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn valid_echo_reply(packet: &[u8], identifier: u16, sequence: u16) -> bool {
    packet.len() >= 8
        && packet[0] == 0
        && packet[1] == 0
        && u16::from_be_bytes([packet[4], packet[5]]) == identifier
        && u16::from_be_bytes([packet[6], packet[7]]) == sequence
        && internet_checksum(packet) == 0
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        sum += u32::from(u16::from_be_bytes([bytes[index], bytes[index + 1]]));
        index += 2;
    }
    if let Some(last) = bytes.get(index) {
        sum += u32::from(*last) << 8;
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

fn parse_ipv4(text: &[u8]) -> Option<[u8; 4]> {
    let mut output = [0u8; 4];
    let mut part = 0usize;
    let mut value = 0u16;
    let mut digits = 0usize;
    for byte in text.iter().copied().chain(core::iter::once(b'.')) {
        if byte == b'.' {
            if digits == 0 || part >= output.len() || value > u16::from(u8::MAX) {
                return None;
            }
            output[part] = value as u8;
            part += 1;
            value = 0;
            digits = 0;
        } else if byte.is_ascii_digit() {
            value = value.checked_mul(10)?.checked_add(u16::from(byte - b'0'))?;
            digits += 1;
            if digits > 3 {
                return None;
            }
        } else {
            return None;
        }
    }
    (part == output.len()).then_some(output)
}

fn ping_identifier() -> u16 {
    let value = libuser::syscall::getpid().unwrap_or(1) as u16;
    value.max(1)
}

fn poll_delay() {
    let _ = libuser::syscall::nanosleep(Timespec {
        seconds: 0,
        nanoseconds: POLL_INTERVAL_NS,
    });
}

fn elapsed_micros(start: Timespec, end: Timespec) -> u64 {
    let seconds = i128::from(end.seconds) - i128::from(start.seconds);
    let nanoseconds = i128::from(end.nanoseconds) - i128::from(start.nanoseconds);
    let total = seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanoseconds);
    u64::try_from(total.max(0) / 1_000).unwrap_or(u64::MAX)
}

fn report_error(operation: &str, error: Error) {
    libuser::println!("{}: {} ({})", operation, errno_name(error.0), error.0);
}

fn errno_name(errno: i32) -> &'static str {
    match errno {
        value if value == Errno::Eio as i32 => "EIO",
        value if value == Errno::Ebadf as i32 => "EBADF",
        value if value == Errno::Eagain as i32 => "EAGAIN",
        value if value == Errno::Efault as i32 => "EFAULT",
        value if value == Errno::Einval as i32 => "EINVAL",
        value if value == Errno::Emfile as i32 => "EMFILE",
        value if value == Errno::Enodev as i32 => "ENODEV",
        value if value == Errno::Enotsock as i32 => "ENOTSOCK",
        value if value == Errno::Emsgsize as i32 => "EMSGSIZE",
        value if value == Errno::Eprotonosupport as i32 => "EPROTONOSUPPORT",
        value if value == Errno::Esocktnosupport as i32 => "ESOCKTNOSUPPORT",
        value if value == Errno::Eopnotsupp as i32 => "EOPNOTSUPP",
        value if value == Errno::Eafnosupport as i32 => "EAFNOSUPPORT",
        value if value == Errno::Eaddrinuse as i32 => "EADDRINUSE",
        value if value == Errno::Eaddrnotavail as i32 => "EADDRNOTAVAIL",
        value if value == Errno::Enetunreach as i32 => "ENETUNREACH",
        value if value == Errno::Econnreset as i32 => "ECONNRESET",
        value if value == Errno::Enobufs as i32 => "ENOBUFS",
        value if value == Errno::Eisconn as i32 => "EISCONN",
        value if value == Errno::Enotconn as i32 => "ENOTCONN",
        value if value == Errno::Ehostunreach as i32 => "EHOSTUNREACH",
        value if value == Errno::Einprogress as i32 => "EINPROGRESS",
        _ => "EUNKNOWN",
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::syscall::exit(127)
}
