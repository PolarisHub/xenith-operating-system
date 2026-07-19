//! Kernel IPv4 networking foundation.
//!
//! The stack is deliberately polling-capable: drivers can feed received
//! Ethernet frames into [`ingest_frame`] and transmit frames returned by it.
//! No path reports a successful network send until a route, interface, and
//! ARP neighbour are all known.

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod eth;
pub mod icmp;
pub mod ip;
pub mod loopback;
pub mod routing;
pub mod socket;
pub mod tcp;
pub mod udp;

use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use self::arp::{ArpCache, ArpOperation, ArpPacket, Neighbor, NeighborState, ProbeDecision};
use self::eth::{EtherType, EthernetFrame, MacAddress};
use self::icmp::{IcmpKind, IcmpPacket};
use self::ip::{IpProtocol, Ipv4Addr, Ipv4Header, Ipv4Packet};
use self::routing::{Route, RouteError, RouteTable, LOOPBACK_INTERFACE};
use self::socket::{Endpoint, SocketError, SocketTx};
use self::tcp::{TcpAction, TcpHeader, TcpReply, TcpSegment};
use self::udp::UdpDatagram;
use crate::mm::KVec;
use crate::sync::SpinLock;

const DEFAULT_TTL: u8 = 64;
const ARP_CACHE_CAPACITY: usize = 256;
const WORKER_POLL_MS: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    Truncated,
    Malformed,
    UnsupportedVersion,
    UnsupportedProtocol,
    BadChecksum,
    BufferTooSmall,
    Oversized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    Packet(PacketError),
    Socket(SocketError),
    Route(RouteError),
    InterfaceNotFound,
    AddressNotConfigured,
    NoRoute,
    NeighborUnresolved(Ipv4Addr),
    NeighborProbeExhausted(Ipv4Addr),
    FragmentationUnsupported,
    UnsupportedProtocol,
    LoopbackStalled,
}

impl From<PacketError> for NetError {
    fn from(error: PacketError) -> Self {
        Self::Packet(error)
    }
}

impl From<SocketError> for NetError {
    fn from(error: SocketError) -> Self {
        Self::Socket(error)
    }
}

impl From<RouteError> for NetError {
    fn from(error: RouteError) -> Self {
        Self::Route(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub id: u16,
    pub mac: MacAddress,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
}

impl InterfaceConfig {
    #[must_use]
    pub fn subnet_broadcast(self) -> Ipv4Addr {
        self.address.subnet_broadcast(self.prefix_len)
    }
}

#[derive(Clone, Debug)]
pub struct OutboundFrame {
    pub interface: u16,
    pub bytes: KVec<u8>,
}

#[derive(Clone, Debug)]
pub enum SocketDispatch {
    Loopback { segments: usize },
    Network(OutboundFrame),
}

#[derive(Clone, Debug)]
pub enum IngressOutcome {
    Ignored,
    Delivered,
    PortUnreachable(Endpoint),
    Reply(OutboundFrame),
}

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static NEXT_IDENTIFICATION: AtomicU16 = AtomicU16::new(1);
static INTERFACES: SpinLock<KVec<InterfaceConfig>> = SpinLock::new(KVec::new());
static DHCP_CLIENTS: SpinLock<KVec<dhcp::Client>> = SpinLock::new(KVec::new());
pub static ROUTES: SpinLock<RouteTable> = SpinLock::new(RouteTable::new());
pub static ARP_CACHE: SpinLock<ArpCache> = SpinLock::new(ArpCache::new(ARP_CACHE_CAPACITY));

/// Install loopback, register every discovered link, and launch the bounded
/// polling/DHCP/maintenance worker.
pub fn init() {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = ROUTES.lock().add(Route {
        network: Ipv4Addr::new(127, 0, 0, 0),
        prefix_len: 8,
        gateway: None,
        interface: LOOPBACK_INTERFACE,
        metric: 0,
    });
    for index in 0..crate::devices::net::adapter_count() {
        let Some(info) = crate::devices::net::adapter_info(index) else {
            continue;
        };
        if let Err(error) = register_link(info.interface, info.mac, info.mtu) {
            ::log::warn!(
                "net: interface {} registration failed: {:?}",
                info.interface,
                error
            );
        } else {
            ::log::info!(
                "net: {} interface {} registered, DHCPv4 starting",
                info.driver,
                info.interface
            );
        }
    }
    if !WORKER_STARTED.swap(true, Ordering::AcqRel) {
        let task = crate::sched::kthread::spawn_kernel_thread("net-worker", network_worker, 0);
        crate::devices::net::register_worker_task(task);
    }
    ::log::info!("net: IPv4 stack online (loopback and autonomous service ready)");
}

fn register_link(id: u16, mac: MacAddress, mtu: usize) -> Result<(), NetError> {
    let mtu = u16::try_from(mtu).map_err(|_| NetError::AddressNotConfigured)?;
    if id == LOOPBACK_INTERFACE
        || !(576..=1500).contains(&mtu)
        || mac.is_zero()
        || mac.is_multicast()
    {
        return Err(NetError::AddressNotConfigured);
    }
    let config = InterfaceConfig {
        id,
        mac,
        address: Ipv4Addr::UNSPECIFIED,
        prefix_len: 0,
        mtu,
    };
    let mut interfaces = INTERFACES.lock();
    if let Some(existing) = interfaces.iter_mut().find(|entry| entry.id == id) {
        *existing = config;
    } else {
        interfaces.push(config);
    }
    drop(interfaces);
    let mut clients = DHCP_CLIENTS.lock();
    if !clients.iter().any(|client| client.interface == id) {
        clients.push(dhcp::Client::new(id, mac));
    }
    Ok(())
}

pub fn configure_interface(config: InterfaceConfig) -> Result<(), NetError> {
    if config.id == LOOPBACK_INTERFACE
        || config.prefix_len > 32
        || config.mtu < 576
        || config.mtu > 1500
        || config.mac.is_zero()
        || config.mac.is_multicast()
        || config.address.is_unspecified()
    {
        return Err(NetError::AddressNotConfigured);
    }
    {
        let mut interfaces = INTERFACES.lock();
        if let Some(existing) = interfaces.iter_mut().find(|entry| entry.id == config.id) {
            *existing = config;
        } else {
            interfaces.push(config);
        }
    }
    let route = Route {
        network: config.address.masked(config.prefix_len),
        prefix_len: config.prefix_len,
        gateway: None,
        interface: config.id,
        metric: 0,
    };
    let mut routes = ROUTES.lock();
    routes.remove_interface(config.id);
    match routes.add(route) {
        Ok(()) | Err(RouteError::Duplicate) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn configure_dhcp_lease(interface_id: u16, lease: dhcp::Lease) -> Result<(), NetError> {
    let link = interface(interface_id).ok_or(NetError::InterfaceNotFound)?;
    configure_interface(InterfaceConfig {
        address: lease.address,
        prefix_len: lease.prefix_len,
        ..link
    })?;
    if let Some(gateway) = lease.gateway {
        add_route(Route {
            network: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
            gateway: Some(gateway),
            interface: interface_id,
            metric: 100,
        })?;
    }
    ::log::info!(
        "net: interface {} leased {}/{} via {} for {}s",
        interface_id,
        lease.address,
        lease.prefix_len,
        lease.server,
        lease.lease_seconds
    );
    Ok(())
}

fn deconfigure_interface(interface_id: u16) {
    {
        let mut interfaces = INTERFACES.lock();
        if let Some(config) = interfaces
            .iter_mut()
            .find(|config| config.id == interface_id)
        {
            config.address = Ipv4Addr::UNSPECIFIED;
            config.prefix_len = 0;
        }
    }
    ROUTES.lock().remove_interface(interface_id);
    ::log::warn!("net: DHCP lease expired on interface {}", interface_id);
}

pub fn add_route(route: Route) -> Result<(), NetError> {
    ROUTES.lock().add(route).map_err(NetError::from)
}

#[must_use]
pub fn interface(id: u16) -> Option<InterfaceConfig> {
    INTERFACES
        .lock()
        .iter()
        .find(|config| config.id == id)
        .copied()
}

#[must_use]
pub fn interface_info(index: usize, now: u64) -> Option<xenith_abi::NetInterfaceInfo> {
    let config = INTERFACES.lock().get(index).copied()?;
    let adapter_index = usize::from(config.id.checked_sub(1)?);
    let adapter = crate::devices::net::adapter_info(adapter_index)?;
    let (lease, lease_remaining_seconds) = DHCP_CLIENTS
        .lock()
        .iter()
        .find(|client| client.interface == config.id)
        .map_or((None, 0), |client| {
            (client.lease(), client.lease_remaining_seconds(now))
        });
    let mut flags = 0u16;
    if adapter.link_up {
        flags |= xenith_abi::NET_IF_LINK_UP;
    }
    if !config.address.is_unspecified() {
        flags |= xenith_abi::NET_IF_CONFIGURED;
    }
    if lease.is_some() {
        flags |= xenith_abi::NET_IF_DHCP;
    }
    let gateway = ROUTES
        .lock()
        .entries()
        .iter()
        .find(|route| route.interface == config.id && route.prefix_len == 0)
        .and_then(|route| route.gateway)
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let dns_servers = lease.map_or([[0; 4]; 2], |lease| {
        lease
            .dns_servers
            .map(|server| server.unwrap_or(Ipv4Addr::UNSPECIFIED).octets())
    });
    Some(xenith_abi::NetInterfaceInfo {
        interface: config.id,
        flags,
        mtu: config.mtu,
        prefix_len: config.prefix_len,
        reserved: 0,
        mac: config.mac.0,
        address: config.address.octets(),
        gateway: gateway.octets(),
        dns_servers,
        lease_remaining_seconds,
    })
}

#[must_use]
pub fn source_address_for(destination: Ipv4Addr) -> Option<Ipv4Addr> {
    if destination.is_loopback() {
        return Some(Ipv4Addr::LOOPBACK);
    }
    let route = ROUTES.lock().lookup(destination)?;
    interface(route.interface)
        .map(|config| config.address)
        .filter(|address| !address.is_unspecified())
}

pub fn ingest_frame(interface_id: u16, bytes: &[u8], now: u64) -> Result<IngressOutcome, NetError> {
    let config = interface(interface_id).ok_or(NetError::InterfaceNotFound)?;
    let frame = EthernetFrame::parse(bytes)?;
    if frame.destination != config.mac && !frame.destination.is_broadcast() {
        return Ok(IngressOutcome::Ignored);
    }
    match frame.ethertype {
        EtherType::Arp => ingest_arp(config, frame.source, frame.payload, now),
        EtherType::Ipv4 => ingest_ipv4(config, frame.source, frame.payload, now),
        _ => Ok(IngressOutcome::Ignored),
    }
}

fn ingest_arp(
    config: InterfaceConfig,
    source_mac: MacAddress,
    bytes: &[u8],
    now: u64,
) -> Result<IngressOutcome, NetError> {
    let packet = ArpPacket::parse(bytes)?;
    if packet.sender_hardware != source_mac
        || packet.sender_hardware.is_zero()
        || packet.sender_hardware.is_multicast()
    {
        return Err(PacketError::Malformed.into());
    }
    if !packet.sender_protocol.is_unspecified() {
        ARP_CACHE.lock().update(Neighbor {
            protocol: packet.sender_protocol,
            hardware: packet.sender_hardware,
            state: NeighborState::Reachable,
            updated_at: now,
            probes: 0,
        });
    }
    if packet.operation != ArpOperation::Request || packet.target_protocol != config.address {
        return Ok(IngressOutcome::Delivered);
    }
    let reply = packet.reply(config.mac).ok_or(PacketError::Malformed)?;
    let mut arp_bytes = [0u8; arp::PACKET_LEN];
    reply.write(&mut arp_bytes)?;
    Ok(IngressOutcome::Reply(ethernet_frame(
        config.id,
        packet.sender_hardware,
        config.mac,
        EtherType::Arp,
        &arp_bytes,
    )?))
}

fn ingest_ipv4(
    config: InterfaceConfig,
    source_mac: MacAddress,
    bytes: &[u8],
    now: u64,
) -> Result<IngressOutcome, NetError> {
    let packet = Ipv4Packet::parse(bytes)?;
    if packet.is_fragmented() {
        return Err(NetError::FragmentationUnsupported);
    }
    let accepts_dhcp = packet.protocol == IpProtocol::Udp
        && packet.payload.len() >= 4
        && u16::from_be_bytes([packet.payload[0], packet.payload[1]]) == dhcp::SERVER_PORT
        && u16::from_be_bytes([packet.payload[2], packet.payload[3]]) == dhcp::CLIENT_PORT;
    if !accepts_dhcp
        && packet.destination != config.address
        && packet.destination != Ipv4Addr::BROADCAST
        && packet.destination != config.subnet_broadcast()
    {
        return Ok(IngressOutcome::Ignored);
    }
    if !packet.source.is_unspecified()
        && !packet.source.is_multicast()
        && packet.source != Ipv4Addr::BROADCAST
        && !source_mac.is_zero()
        && !source_mac.is_multicast()
    {
        if let Some(route) = ROUTES.lock().lookup(packet.source) {
            if route.interface == config.id {
                ARP_CACHE.lock().update(Neighbor {
                    protocol: route.destination(packet.source),
                    hardware: source_mac,
                    state: NeighborState::Reachable,
                    updated_at: now,
                    probes: 0,
                });
            }
        }
    }
    match packet.protocol {
        IpProtocol::Icmp => ingest_icmp(config, source_mac, packet),
        IpProtocol::Udp => {
            let datagram =
                UdpDatagram::parse_ipv4(packet.payload, packet.source, packet.destination)?;
            if datagram.source_port == dhcp::SERVER_PORT
                && datagram.destination_port == dhcp::CLIENT_PORT
            {
                return ingest_dhcp(config, datagram.payload, now);
            }
            let source = Endpoint::new(packet.source, datagram.source_port);
            let destination = Endpoint::new(packet.destination, datagram.destination_port);
            match socket::SOCKETS
                .lock()
                .deliver_udp(destination, source, datagram.payload)
            {
                Ok(_) => Ok(IngressOutcome::Delivered),
                Err(SocketError::NotBound) => Ok(IngressOutcome::PortUnreachable(destination)),
                Err(error) => Err(error.into()),
            }
        },
        IpProtocol::Tcp => ingest_tcp(config, source_mac, packet, now),
        _ => Err(NetError::UnsupportedProtocol),
    }
}

fn ingest_dhcp(
    config: InterfaceConfig,
    payload: &[u8],
    now: u64,
) -> Result<IngressOutcome, NetError> {
    let event = {
        let mut clients = DHCP_CLIENTS.lock();
        let Some(client) = clients
            .iter_mut()
            .find(|client| client.interface == config.id)
        else {
            return Ok(IngressOutcome::Ignored);
        };
        client.receive(payload, now)?
    };
    let Some(event) = event else {
        return Ok(IngressOutcome::Ignored);
    };
    match handle_dhcp_event(config.id, event)? {
        Some(frame) => Ok(IngressOutcome::Reply(frame)),
        None => Ok(IngressOutcome::Delivered),
    }
}

fn handle_dhcp_event(
    interface_id: u16,
    event: dhcp::ClientEvent,
) -> Result<Option<OutboundFrame>, NetError> {
    match event {
        dhcp::ClientEvent::Transmit {
            length,
            bytes,
            source,
            destination,
            ..
        } => build_dhcp_frame(interface_id, source, destination, &bytes[..length]).map(Some),
        dhcp::ClientEvent::LeaseAcquired(lease) => {
            configure_dhcp_lease(interface_id, lease)?;
            Ok(None)
        },
        dhcp::ClientEvent::LeaseExpired => {
            deconfigure_interface(interface_id);
            Ok(None)
        },
    }
}

fn build_dhcp_frame(
    interface_id: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: &[u8],
) -> Result<OutboundFrame, NetError> {
    let config = interface(interface_id).ok_or(NetError::InterfaceNotFound)?;
    let mut datagram = alloc::vec![0; udp::HEADER_LEN + payload.len()];
    let length = udp::write_ipv4(
        &mut datagram,
        (source, dhcp::CLIENT_PORT),
        (destination, dhcp::SERVER_PORT),
        payload,
    )?;
    datagram.truncate(length);
    ipv4_ethernet_frame(
        config,
        MacAddress::BROADCAST,
        source,
        destination,
        IpProtocol::Udp,
        &datagram,
    )
}

extern "C" fn network_worker(_argument: usize) -> usize {
    loop {
        let now = crate::time::uptime_ns();
        let _ = crate::devices::net::poll_stack(now, 64);
        for frame in maintenance_frames(now) {
            match crate::devices::net::transmit_outbound(&frame) {
                Ok(()) | Err(crate::devices::net::DriverError::WouldBlock) => {},
                Err(error) => ::log::debug!("net: maintenance transmit failed: {:?}", error),
            }
        }
        if crate::devices::net::interrupt_work_pending() {
            crate::yield_point!();
            continue;
        }
        crate::sched::sleep_until(
            crate::time::Instant::now() + crate::time::Duration::from_millis(WORKER_POLL_MS),
        );
    }
}

fn maintenance_frames(now: u64) -> KVec<OutboundFrame> {
    let mut frames = KVec::new();
    let retries = ARP_CACHE.lock().maintain(now);
    for address in retries {
        if let Ok(frame) = build_arp_request_for_destination(address) {
            frames.push(frame);
        }
    }
    let mut events = KVec::new();
    {
        let mut clients = DHCP_CLIENTS.lock();
        for client in clients.iter_mut() {
            match client.poll(now) {
                Ok(Some(event)) => events.push((client.interface, event)),
                Ok(None) => {},
                Err(error) => ::log::warn!(
                    "net: DHCP client {} failed to build packet: {:?}",
                    client.interface,
                    error
                ),
            }
        }
    }
    for (interface_id, event) in events {
        match handle_dhcp_event(interface_id, event) {
            Ok(Some(frame)) => frames.push(frame),
            Ok(None) => {},
            Err(error) => ::log::warn!(
                "net: DHCP event on interface {} failed: {:?}",
                interface_id,
                error
            ),
        }
    }
    for packet in socket::poll_retransmissions(now) {
        match dispatch_socket_tx(packet) {
            Ok(SocketDispatch::Network(frame)) => frames.push(frame),
            Ok(SocketDispatch::Loopback { .. }) => {},
            Err(NetError::NeighborUnresolved(_)) => {},
            Err(error) => ::log::debug!("net: TCP retransmission deferred: {:?}", error),
        }
    }
    frames
}

fn ingest_icmp(
    config: InterfaceConfig,
    source_mac: MacAddress,
    packet: Ipv4Packet<'_>,
) -> Result<IngressOutcome, NetError> {
    let message = IcmpPacket::parse(packet.payload)?;
    if matches!(message.kind, IcmpKind::EchoReply) {
        if let Some((identifier, _)) = message.echo_id_sequence() {
            match socket::SOCKETS.lock().deliver_icmp(
                packet.destination,
                packet.source,
                identifier,
                packet.payload,
            ) {
                Ok(_) => return Ok(IngressOutcome::Delivered),
                Err(SocketError::NotBound) => return Ok(IngressOutcome::Ignored),
                Err(error) => return Err(error.into()),
            }
        }
    }
    if packet.destination != config.address
        || !matches!(message.kind, IcmpKind::EchoRequest)
        || message.code != 0
    {
        return Ok(IngressOutcome::Delivered);
    }
    let mut body = alloc::vec![0; icmp::HEADER_LEN + message.payload.len()];
    let body_len = icmp::write_echo_reply(&mut body, message)?;
    body.truncate(body_len);
    ipv4_ethernet_frame(
        config,
        source_mac,
        packet.destination,
        packet.source,
        IpProtocol::Icmp,
        &body,
    )
    .map(IngressOutcome::Reply)
}

fn ingest_tcp(
    config: InterfaceConfig,
    source_mac: MacAddress,
    packet: Ipv4Packet<'_>,
    now: u64,
) -> Result<IngressOutcome, NetError> {
    let segment = TcpSegment::parse_ipv4(packet.payload, packet.source, packet.destination)?;
    let source = Endpoint::new(packet.source, segment.source_port);
    let destination = Endpoint::new(packet.destination, segment.destination_port);
    let ingress = socket::SOCKETS
        .lock()
        .deliver_tcp(source, destination, &segment)?;
    let reply = match ingress.action {
        TcpAction::Send(reply)
        | TcpAction::PeerClosed(reply)
        | TcpAction::Connected(Some(reply))
        | TcpAction::Deliver {
            reply: Some(reply), ..
        } => Some(reply),
        _ => None,
    };
    let Some(reply) = reply else {
        return Ok(IngressOutcome::Delivered);
    };
    if let Some(handle) = ingress.handle {
        let tracked = SocketTx {
            protocol: IpProtocol::Tcp,
            source: destination,
            destination: source,
            payload: KVec::new(),
            tcp: Some(TcpHeader {
                source_port: destination.port,
                destination_port: source.port,
                sequence: reply.sequence,
                acknowledgement: reply.acknowledgement,
                flags: reply.flags,
                window: 65_535,
                urgent_pointer: 0,
            }),
        };
        socket::track_transmission(handle, tracked, now)?;
    }
    tcp_reply_frame(config, source_mac, destination, source, reply).map(IngressOutcome::Reply)
}

fn tcp_reply_frame(
    config: InterfaceConfig,
    destination_mac: MacAddress,
    source: Endpoint,
    destination: Endpoint,
    reply: TcpReply,
) -> Result<OutboundFrame, NetError> {
    let header = TcpHeader {
        source_port: source.port,
        destination_port: destination.port,
        sequence: reply.sequence,
        acknowledgement: reply.acknowledgement,
        flags: reply.flags,
        window: 65_535,
        urgent_pointer: 0,
    };
    let mut body = [0u8; tcp::MIN_HEADER_LEN];
    let body_len = header.write_ipv4(&mut body, source.address, destination.address, &[], &[])?;
    ipv4_ethernet_frame(
        config,
        destination_mac,
        source.address,
        destination.address,
        IpProtocol::Tcp,
        &body[..body_len],
    )
}

pub fn encode_socket_tx(tx: SocketTx) -> Result<OutboundFrame, NetError> {
    let route = ROUTES
        .lock()
        .lookup(tx.destination.address)
        .ok_or(NetError::NoRoute)?;
    if route.interface == LOOPBACK_INTERFACE {
        return Err(NetError::UnsupportedProtocol);
    }
    let config = interface(route.interface).ok_or(NetError::InterfaceNotFound)?;
    if tx.source.address != config.address {
        return Err(NetError::AddressNotConfigured);
    }
    let next_hop = route.destination(tx.destination.address);
    let neighbor = ARP_CACHE
        .lock()
        .lookup(next_hop)
        .ok_or(NetError::NeighborUnresolved(next_hop))?;
    let transport = match tx.protocol {
        IpProtocol::Udp => {
            let mut transport = alloc::vec![0; udp::HEADER_LEN + tx.payload.len()];
            let length = udp::write_ipv4(
                &mut transport,
                (tx.source.address, tx.source.port),
                (tx.destination.address, tx.destination.port),
                &tx.payload,
            )?;
            transport.truncate(length);
            transport
        },
        IpProtocol::Tcp => {
            let header = tx.tcp.ok_or(NetError::UnsupportedProtocol)?;
            let mut transport = alloc::vec![0; tcp::MIN_HEADER_LEN + tx.payload.len()];
            let length = header.write_ipv4(
                &mut transport,
                tx.source.address,
                tx.destination.address,
                &[],
                &tx.payload,
            )?;
            transport.truncate(length);
            transport
        },
        IpProtocol::Icmp => tx.payload,
        _ => return Err(NetError::UnsupportedProtocol),
    };
    ipv4_ethernet_frame(
        config,
        neighbor.hardware,
        tx.source.address,
        tx.destination.address,
        tx.protocol,
        &transport,
    )
}

/// Deliver a socket packet locally when it targets 127/8, otherwise encode
/// it for the routed Ethernet interface. TCP replies are pumped through both
/// endpoints until the handshake/data acknowledgement exchange quiesces.
pub fn dispatch_socket_tx(tx: SocketTx) -> Result<SocketDispatch, NetError> {
    if tx.destination.address.is_loopback() {
        if !tx.source.address.is_loopback() {
            return Err(NetError::AddressNotConfigured);
        }
        return deliver_loopback_tx(tx).map(|segments| SocketDispatch::Loopback { segments });
    }
    encode_socket_tx(tx).map(SocketDispatch::Network)
}

fn deliver_loopback_tx(tx: SocketTx) -> Result<usize, NetError> {
    match tx.protocol {
        IpProtocol::Udp => {
            socket::SOCKETS
                .lock()
                .deliver_udp(tx.destination, tx.source, &tx.payload)?;
            Ok(1)
        },
        IpProtocol::Tcp => {
            let mut header = tx.tcp.ok_or(NetError::UnsupportedProtocol)?;
            let mut source = tx.source;
            let mut destination = tx.destination;
            let mut payload = tx.payload;
            for count in 1..=8 {
                let segment = TcpSegment {
                    source_port: header.source_port,
                    destination_port: header.destination_port,
                    sequence: header.sequence,
                    acknowledgement: header.acknowledgement,
                    flags: header.flags,
                    window: header.window,
                    urgent_pointer: header.urgent_pointer,
                    options: &[],
                    payload: &payload,
                };
                let ingress = socket::SOCKETS
                    .lock()
                    .deliver_tcp(source, destination, &segment)?;
                let reply = match ingress.action {
                    TcpAction::Send(reply)
                    | TcpAction::PeerClosed(reply)
                    | TcpAction::Connected(Some(reply))
                    | TcpAction::Deliver {
                        reply: Some(reply), ..
                    } => reply,
                    _ => return Ok(count),
                };
                core::mem::swap(&mut source, &mut destination);
                header = TcpHeader {
                    source_port: source.port,
                    destination_port: destination.port,
                    sequence: reply.sequence,
                    acknowledgement: reply.acknowledgement,
                    flags: reply.flags,
                    window: 65_535,
                    urgent_pointer: 0,
                };
                payload.clear();
            }
            Err(NetError::LoopbackStalled)
        },
        IpProtocol::Icmp => {
            let message = IcmpPacket::parse(&tx.payload)?;
            let (identifier, _) = message
                .echo_id_sequence()
                .ok_or(NetError::UnsupportedProtocol)?;
            match message.kind {
                IcmpKind::EchoRequest => {
                    let mut reply = alloc::vec![0; icmp::HEADER_LEN + message.payload.len()];
                    let length = icmp::write_echo_reply(&mut reply, message)?;
                    reply.truncate(length);
                    socket::SOCKETS.lock().deliver_icmp(
                        tx.source.address,
                        tx.destination.address,
                        identifier,
                        &reply,
                    )?;
                    Ok(2)
                },
                IcmpKind::EchoReply => {
                    socket::SOCKETS.lock().deliver_icmp(
                        tx.destination.address,
                        tx.source.address,
                        identifier,
                        &tx.payload,
                    )?;
                    Ok(1)
                },
                _ => Err(NetError::UnsupportedProtocol),
            }
        },
        _ => Err(NetError::UnsupportedProtocol),
    }
}

/// Resolve the source address and neighbour required before a socket mutates
/// TCP sequence state. Missing ARP entries are reported without consuming a
/// segment so the caller can send a request and safely retry.
pub fn prepare_socket_egress(destination: Ipv4Addr) -> Result<Ipv4Addr, NetError> {
    if destination.is_loopback() {
        return Ok(Ipv4Addr::LOOPBACK);
    }
    let route = ROUTES.lock().lookup(destination).ok_or(NetError::NoRoute)?;
    let config = interface(route.interface).ok_or(NetError::InterfaceNotFound)?;
    if config.address.is_unspecified() {
        return Err(NetError::AddressNotConfigured);
    }
    let next_hop = route.destination(destination);
    if ARP_CACHE.lock().lookup(next_hop).is_none() {
        return Err(NetError::NeighborUnresolved(next_hop));
    }
    Ok(config.address)
}

pub fn build_arp_request_for_destination(destination: Ipv4Addr) -> Result<OutboundFrame, NetError> {
    let route = ROUTES.lock().lookup(destination).ok_or(NetError::NoRoute)?;
    build_arp_request(route.interface, route.destination(destination))
}

/// Start or advance a rate-limited, bounded ARP resolution. `Ok(None)` means
/// a prior probe is still within its retry interval; exhaustion is explicit.
pub fn probe_neighbor_for_destination(
    destination: Ipv4Addr,
    now: u64,
) -> Result<Option<OutboundFrame>, NetError> {
    let route = ROUTES.lock().lookup(destination).ok_or(NetError::NoRoute)?;
    let next_hop = route.destination(destination);
    match ARP_CACHE.lock().probe(next_hop, now) {
        ProbeDecision::Send => build_arp_request(route.interface, next_hop).map(Some),
        ProbeDecision::Wait | ProbeDecision::Resolved => Ok(None),
        ProbeDecision::Exhausted => Err(NetError::NeighborProbeExhausted(next_hop)),
    }
}

pub fn build_arp_request(interface_id: u16, target: Ipv4Addr) -> Result<OutboundFrame, NetError> {
    let config = interface(interface_id).ok_or(NetError::InterfaceNotFound)?;
    let request = ArpPacket {
        operation: ArpOperation::Request,
        sender_hardware: config.mac,
        sender_protocol: config.address,
        target_hardware: MacAddress::ZERO,
        target_protocol: target,
    };
    let mut body = [0u8; arp::PACKET_LEN];
    request.write(&mut body)?;
    ethernet_frame(
        config.id,
        MacAddress::BROADCAST,
        config.mac,
        EtherType::Arp,
        &body,
    )
}

fn ipv4_ethernet_frame(
    config: InterfaceConfig,
    destination_mac: MacAddress,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: IpProtocol,
    payload: &[u8],
) -> Result<OutboundFrame, NetError> {
    if ip::MIN_HEADER_LEN + payload.len() > usize::from(config.mtu) {
        return Err(PacketError::Oversized.into());
    }
    let mut ipv4 = alloc::vec![0; ip::MIN_HEADER_LEN + payload.len()];
    Ipv4Header {
        dscp_ecn: 0,
        identification: NEXT_IDENTIFICATION.fetch_add(1, Ordering::Relaxed),
        flags_fragment: 0x4000,
        ttl: DEFAULT_TTL,
        protocol,
        source,
        destination,
    }
    .write(&mut ipv4, payload.len())?;
    ipv4[ip::MIN_HEADER_LEN..].copy_from_slice(payload);
    ethernet_frame(
        config.id,
        destination_mac,
        config.mac,
        EtherType::Ipv4,
        &ipv4,
    )
}

fn ethernet_frame(
    interface: u16,
    destination: MacAddress,
    source: MacAddress,
    ethertype: EtherType,
    payload: &[u8],
) -> Result<OutboundFrame, NetError> {
    let used = eth::HEADER_LEN
        .checked_add(payload.len())
        .ok_or(PacketError::Oversized)?;
    let frame_len = used.max(eth::MIN_FRAME_LEN);
    let mut bytes = alloc::vec![0; frame_len];
    EthernetFrame::write(&mut bytes, destination, source, ethertype, payload)?;
    Ok(OutboundFrame { interface, bytes })
}
