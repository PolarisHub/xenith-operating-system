//! Kernel socket table for UDP datagrams and stateful TCP endpoints.

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, Ordering};

use super::ip::{IpProtocol, Ipv4Addr};
use super::tcp::{
    TcpAction, TcpControlBlock, TcpFlags, TcpHeader, TcpReply, TcpSegment, TcpState, TcpStateError,
};
use crate::mm::KVec;
use crate::sync::SpinLock;

const MAX_SOCKETS: usize = 1024;
const MAX_RX_PACKETS: usize = 128;
pub const MAX_LISTEN_BACKLOG: usize = 32;
const EPHEMERAL_FIRST: u16 = 49_152;
const TCP_MSS: u32 = 1_400;
const TCP_INITIAL_CWND: u32 = TCP_MSS * 4;
const TCP_INITIAL_SSTHRESH: u32 = 65_535;
const TCP_INITIAL_RTO_NS: u64 = 300_000_000;
const TCP_MAX_RTO_NS: u64 = 4_800_000_000;
const TCP_MAX_RETRIES: u8 = 6;
const MAX_TCP_OUTSTANDING: usize = 32;
const MAX_OUT_OF_ORDER_SEGMENTS: usize = 32;
const MAX_OUT_OF_ORDER_BYTES: usize = 65_535;
const TCP_DETACHED_TIMEOUT_NS: u64 = 60_000_000_000;

static ISN_COUNTER: AtomicU32 = AtomicU32::new(0x4a7d_1281);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub address: Ipv4Addr,
    pub port: u16,
}

impl Endpoint {
    #[must_use]
    pub const fn new(address: Ipv4Addr, port: u16) -> Self {
        Self { address, port }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketKind {
    Udp,
    Tcp,
    RawIcmp,
}

impl SocketKind {
    #[must_use]
    pub const fn protocol(self) -> IpProtocol {
        match self {
            Self::Udp => IpProtocol::Udp,
            Self::Tcp => IpProtocol::Tcp,
            Self::RawIcmp => IpProtocol::Icmp,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SocketHandle {
    slot: u16,
    generation: u16,
}

impl SocketHandle {
    #[must_use]
    pub const fn slot(self) -> usize {
        self.slot as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketError {
    TableFull,
    InvalidHandle,
    InvalidPort,
    AddressInUse,
    NotBound,
    NotConnected,
    WrongProtocol,
    InvalidState,
    WouldBlock,
    ReceiveQueueFull,
    ConnectionReset,
    BacklogFull,
    AlreadyConnected,
    ConnectionInProgress,
}

impl From<TcpStateError> for SocketError {
    fn from(_: TcpStateError) -> Self {
        Self::InvalidState
    }
}

#[derive(Clone, Debug)]
pub struct ReceivedPacket {
    pub source: Endpoint,
    pub payload: KVec<u8>,
}

#[derive(Clone, Debug)]
pub struct SocketTx {
    pub protocol: IpProtocol,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub payload: KVec<u8>,
    pub tcp: Option<TcpHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendDisposition {
    QueuedLoopback(usize),
    NeedsNetwork,
}

#[derive(Clone, Debug)]
pub struct SendResult {
    pub disposition: SendDisposition,
    pub packet: Option<SocketTx>,
}

#[derive(Clone, Copy, Debug)]
pub struct TcpIngress {
    pub handle: Option<SocketHandle>,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub action: TcpAction,
}

#[derive(Clone, Debug)]
struct TcpOutstanding {
    packet: SocketTx,
    sequence_end: u32,
    sent_at: u64,
    rto_ns: u64,
    retries: u8,
}

#[derive(Clone, Debug)]
struct OutOfOrderSegment {
    sequence: u32,
    acknowledgement: u32,
    window: u16,
    payload: KVec<u8>,
    fin: bool,
}

struct Socket {
    kind: SocketKind,
    local: Option<Endpoint>,
    remote: Option<Endpoint>,
    tcp: Option<TcpControlBlock>,
    rx: VecDeque<ReceivedPacket>,
    pending: VecDeque<SocketHandle>,
    parent_listener: Option<SocketHandle>,
    listen_backlog: usize,
    last_error: Option<SocketError>,
    outstanding: VecDeque<TcpOutstanding>,
    out_of_order: VecDeque<OutOfOrderSegment>,
    congestion_window: u32,
    slow_start_threshold: u32,
    duplicate_acks: u8,
    detached_at: Option<u64>,
}

impl Socket {
    fn new(kind: SocketKind) -> Self {
        Self {
            kind,
            local: None,
            remote: None,
            tcp: (kind == SocketKind::Tcp).then(|| TcpControlBlock::closed(65_535)),
            rx: VecDeque::new(),
            pending: VecDeque::new(),
            parent_listener: None,
            listen_backlog: 0,
            last_error: None,
            outstanding: VecDeque::new(),
            out_of_order: VecDeque::new(),
            congestion_window: TCP_INITIAL_CWND,
            slow_start_threshold: TCP_INITIAL_SSTHRESH,
            duplicate_acks: 0,
            detached_at: None,
        }
    }

    fn queue_rx(&mut self, packet: ReceivedPacket) -> Result<(), SocketError> {
        if self.rx.len() >= MAX_RX_PACKETS {
            return Err(SocketError::ReceiveQueueFull);
        }
        self.rx.push_back(packet);
        Ok(())
    }
}

struct Slot {
    generation: u16,
    socket: Option<Socket>,
}

pub struct SocketTable {
    slots: KVec<Slot>,
    next_ephemeral: u16,
}

impl SocketTable {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: KVec::new(),
            next_ephemeral: EPHEMERAL_FIRST,
        }
    }

    pub fn create(&mut self, kind: SocketKind) -> Result<SocketHandle, SocketError> {
        if let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.socket.is_none())
        {
            slot.socket = Some(Socket::new(kind));
            return Ok(SocketHandle {
                slot: index as u16,
                generation: slot.generation,
            });
        }
        if self.slots.len() >= MAX_SOCKETS {
            return Err(SocketError::TableFull);
        }
        let index = self.slots.len();
        self.slots.push(Slot {
            generation: 1,
            socket: Some(Socket::new(kind)),
        });
        Ok(SocketHandle {
            slot: index as u16,
            generation: 1,
        })
    }

    fn get(&self, handle: SocketHandle) -> Result<&Socket, SocketError> {
        let slot = self
            .slots
            .get(handle.slot())
            .filter(|slot| slot.generation == handle.generation)
            .ok_or(SocketError::InvalidHandle)?;
        slot.socket.as_ref().ok_or(SocketError::InvalidHandle)
    }

    fn get_mut(&mut self, handle: SocketHandle) -> Result<&mut Socket, SocketError> {
        let slot = self
            .slots
            .get_mut(handle.slot())
            .filter(|slot| slot.generation == handle.generation)
            .ok_or(SocketError::InvalidHandle)?;
        slot.socket.as_mut().ok_or(SocketError::InvalidHandle)
    }

    pub fn close(&mut self, handle: SocketHandle) -> Result<Option<SocketTx>, SocketError> {
        let closing = {
            let socket = self.get_mut(handle)?;
            if socket.kind == SocketKind::Tcp {
                let state = socket.tcp.as_ref().expect("TCP socket has a TCB").state;
                if matches!(state, TcpState::Established | TcpState::CloseWait) {
                    let reply = socket.tcp.as_mut().expect("TCP socket has a TCB").close()?;
                    Some(build_tcp_tx(socket, reply, KVec::new())?)
                } else {
                    None
                }
            } else {
                None
            }
        };
        if closing.is_some() {
            return Ok(closing);
        }
        self.discard(handle)?;
        Ok(None)
    }

    pub fn bind(&mut self, handle: SocketHandle, endpoint: Endpoint) -> Result<(), SocketError> {
        if endpoint.port == 0 {
            return Err(SocketError::InvalidPort);
        }
        let kind = self.get(handle)?.kind;
        if self.endpoint_in_use(kind, endpoint, Some(handle)) {
            return Err(SocketError::AddressInUse);
        }
        let socket = self.get_mut(handle)?;
        if socket.local.is_some() {
            return Err(SocketError::InvalidState);
        }
        socket.local = Some(endpoint);
        Ok(())
    }

    pub fn bind_ephemeral(
        &mut self,
        handle: SocketHandle,
        address: Ipv4Addr,
    ) -> Result<Endpoint, SocketError> {
        let kind = self.get(handle)?.kind;
        for _ in 0..=(u16::MAX - EPHEMERAL_FIRST) {
            let port = self.next_ephemeral;
            self.next_ephemeral = if port == u16::MAX {
                EPHEMERAL_FIRST
            } else {
                port + 1
            };
            let endpoint = Endpoint::new(address, port);
            if !self.endpoint_in_use(kind, endpoint, Some(handle)) {
                self.get_mut(handle)?.local = Some(endpoint);
                return Ok(endpoint);
            }
        }
        Err(SocketError::AddressInUse)
    }

    fn endpoint_in_use(
        &self,
        kind: SocketKind,
        endpoint: Endpoint,
        except: Option<SocketHandle>,
    ) -> bool {
        self.slots.iter().enumerate().any(|(index, slot)| {
            let Some(socket) = &slot.socket else {
                return false;
            };
            let handle = SocketHandle {
                slot: index as u16,
                generation: slot.generation,
            };
            if except == Some(handle) || socket.kind != kind {
                return false;
            }
            socket.local.is_some_and(|bound| {
                bound.port == endpoint.port
                    && (bound.address.is_unspecified()
                        || endpoint.address.is_unspecified()
                        || bound.address == endpoint.address)
            })
        })
    }

    pub fn listen(&mut self, handle: SocketHandle, backlog: usize) -> Result<(), SocketError> {
        if backlog == 0 || backlog > MAX_LISTEN_BACKLOG {
            return Err(SocketError::InvalidState);
        }
        let initial_sequence = next_isn();
        let socket = self.get_mut(handle)?;
        if socket.kind != SocketKind::Tcp {
            return Err(SocketError::WrongProtocol);
        }
        if socket.local.is_none() {
            return Err(SocketError::NotBound);
        }
        socket
            .tcp
            .as_mut()
            .expect("TCP socket has a TCB")
            .listen(initial_sequence)?;
        socket.listen_backlog = backlog;
        Ok(())
    }

    pub fn connect(
        &mut self,
        handle: SocketHandle,
        remote: Endpoint,
        source_address: Ipv4Addr,
    ) -> Result<Option<SocketTx>, SocketError> {
        if remote.port == 0 || remote.address.is_unspecified() {
            return Err(SocketError::InvalidPort);
        }
        if self.get(handle)?.kind == SocketKind::Tcp {
            match self
                .get(handle)?
                .tcp
                .as_ref()
                .expect("TCP socket has a TCB")
                .state
            {
                TcpState::Closed => {},
                TcpState::SynSent | TcpState::SynReceived => {
                    return Err(SocketError::ConnectionInProgress);
                },
                TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck
                | TcpState::TimeWait => return Err(SocketError::AlreadyConnected),
                TcpState::Listen => return Err(SocketError::InvalidState),
            }
        }
        if self.get(handle)?.local.is_none() {
            self.bind_ephemeral(handle, source_address)?;
        } else if self
            .get(handle)?
            .local
            .is_some_and(|local| local.address.is_unspecified())
        {
            self.get_mut(handle)?
                .local
                .as_mut()
                .expect("local endpoint was present")
                .address = source_address;
        }
        let socket = self.get_mut(handle)?;
        socket.remote = Some(remote);
        match socket.kind {
            SocketKind::Udp => Ok(None),
            SocketKind::Tcp => {
                let reply = socket
                    .tcp
                    .as_mut()
                    .expect("TCP socket has a TCB")
                    .connect(next_isn())?;
                Ok(Some(build_tcp_tx(socket, reply, KVec::new())?))
            },
            SocketKind::RawIcmp => Ok(None),
        }
    }

    pub fn accept(&mut self, listener: SocketHandle) -> Result<SocketHandle, SocketError> {
        let child = {
            let socket = self.get_mut(listener)?;
            if socket.kind != SocketKind::Tcp {
                return Err(SocketError::WrongProtocol);
            }
            if socket.tcp.as_ref().expect("TCP socket has a TCB").state != TcpState::Listen {
                return Err(SocketError::InvalidState);
            }
            socket.pending.pop_front().ok_or(SocketError::WouldBlock)?
        };
        self.get_mut(child)?.parent_listener = None;
        Ok(child)
    }

    pub fn send(
        &mut self,
        handle: SocketHandle,
        payload: &[u8],
    ) -> Result<SendResult, SocketError> {
        let (kind, local, remote, tcp_header) = {
            let socket = self.get_mut(handle)?;
            let local = socket.local.ok_or(SocketError::NotBound)?;
            let remote = socket.remote.ok_or(SocketError::NotConnected)?;
            let tcp_header = if socket.kind == SocketKind::Tcp {
                let tcb = socket.tcp.as_mut().expect("TCP socket has a TCB");
                if tcb.state != TcpState::Established {
                    return Err(if tcb.state == TcpState::SynSent {
                        SocketError::ConnectionInProgress
                    } else {
                        SocketError::InvalidState
                    });
                }
                if socket.outstanding.len() >= MAX_TCP_OUTSTANDING {
                    return Err(SocketError::WouldBlock);
                }
                let in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una);
                let allowed = u32::from(tcb.snd_wnd)
                    .min(socket.congestion_window)
                    .saturating_sub(in_flight);
                if u32::try_from(payload.len()).unwrap_or(u32::MAX) > allowed {
                    return Err(SocketError::WouldBlock);
                }
                let sequence = tcb.snd_nxt;
                tcb.snd_nxt = tcb
                    .snd_nxt
                    .wrapping_add(u32::try_from(payload.len()).unwrap_or(u32::MAX));
                Some(TcpHeader {
                    source_port: local.port,
                    destination_port: remote.port,
                    sequence,
                    acknowledgement: tcb.rcv_nxt,
                    flags: TcpFlags::PSH.union(TcpFlags::ACK),
                    window: tcb.rcv_wnd,
                    urgent_pointer: 0,
                })
            } else {
                None
            };
            (socket.kind, local, remote, tcp_header)
        };
        let mut owned = KVec::with_capacity(payload.len());
        owned.extend_from_slice(payload);
        if kind == SocketKind::Udp && remote.address.is_loopback() {
            self.deliver_udp(remote, local, &owned)?;
            return Ok(SendResult {
                disposition: SendDisposition::QueuedLoopback(owned.len()),
                packet: None,
            });
        }
        Ok(SendResult {
            disposition: SendDisposition::NeedsNetwork,
            packet: Some(SocketTx {
                protocol: kind.protocol(),
                source: local,
                destination: remote,
                payload: owned,
                tcp: tcp_header,
            }),
        })
    }

    pub fn receive(&mut self, handle: SocketHandle) -> Result<ReceivedPacket, SocketError> {
        let socket = self.get_mut(handle)?;
        if let Some(error) = socket.last_error.take() {
            return Err(error);
        }
        socket.rx.pop_front().ok_or(SocketError::WouldBlock)
    }

    pub fn deliver_udp(
        &mut self,
        destination: Endpoint,
        source: Endpoint,
        payload: &[u8],
    ) -> Result<SocketHandle, SocketError> {
        let index = self
            .slots
            .iter()
            .position(|slot| {
                slot.socket.as_ref().is_some_and(|socket| {
                    socket.kind == SocketKind::Udp
                        && socket.local.is_some_and(|local| {
                            local.port == destination.port
                                && (local.address.is_unspecified()
                                    || local.address == destination.address)
                        })
                        && socket.remote.is_none_or(|remote| remote == source)
                })
            })
            .ok_or(SocketError::NotBound)?;
        let slot = &mut self.slots[index];
        let handle = SocketHandle {
            slot: index as u16,
            generation: slot.generation,
        };
        let mut owned = KVec::with_capacity(payload.len());
        owned.extend_from_slice(payload);
        slot.socket
            .as_mut()
            .expect("selected occupied socket")
            .queue_rx(ReceivedPacket {
                source,
                payload: owned,
            })?;
        Ok(handle)
    }

    pub fn deliver_icmp(
        &mut self,
        destination: Ipv4Addr,
        source: Ipv4Addr,
        identifier: u16,
        payload: &[u8],
    ) -> Result<SocketHandle, SocketError> {
        let index = self
            .slots
            .iter()
            .position(|slot| {
                slot.socket.as_ref().is_some_and(|socket| {
                    socket.kind == SocketKind::RawIcmp
                        && socket.local.is_some_and(|local| {
                            local.port == identifier
                                && (local.address.is_unspecified() || local.address == destination)
                        })
                        && socket.remote.is_none_or(|remote| remote.address == source)
                })
            })
            .ok_or(SocketError::NotBound)?;
        let slot = &mut self.slots[index];
        let handle = SocketHandle {
            slot: index as u16,
            generation: slot.generation,
        };
        let mut owned = KVec::with_capacity(payload.len());
        owned.extend_from_slice(payload);
        slot.socket
            .as_mut()
            .expect("selected occupied socket")
            .queue_rx(ReceivedPacket {
                source: Endpoint::new(source, identifier),
                payload: owned,
            })?;
        Ok(handle)
    }

    pub fn deliver_tcp(
        &mut self,
        source: Endpoint,
        destination: Endpoint,
        segment: &TcpSegment<'_>,
    ) -> Result<TcpIngress, SocketError> {
        if let Some(index) = self.find_tcp_connection(source, destination) {
            return self.deliver_tcp_to(index, source, destination, segment);
        }
        let Some(listener_index) = self.find_tcp_listener(destination) else {
            let mut closed = TcpControlBlock::closed(0);
            return Ok(TcpIngress {
                handle: None,
                source,
                destination,
                action: closed.on_segment(segment).map_err(SocketError::from)?,
            });
        };
        if !segment.flags.contains(TcpFlags::SYN) || segment.flags.contains(TcpFlags::ACK) {
            let mut closed = TcpControlBlock::closed(0);
            return Ok(TcpIngress {
                handle: None,
                source,
                destination,
                action: closed.on_segment(segment).map_err(SocketError::from)?,
            });
        }
        let listener_handle = SocketHandle {
            slot: listener_index as u16,
            generation: self.slots[listener_index].generation,
        };
        let child = self.create(SocketKind::Tcp)?;
        {
            let socket = self.get_mut(child)?;
            socket.local = Some(destination);
            socket.remote = Some(source);
            socket.parent_listener = Some(listener_handle);
            socket
                .tcp
                .as_mut()
                .expect("TCP child has a TCB")
                .listen(next_isn())?;
        }
        let child_index = child.slot();
        self.deliver_tcp_to(child_index, source, destination, segment)
    }

    fn deliver_tcp_to(
        &mut self,
        index: usize,
        source: Endpoint,
        destination: Endpoint,
        segment: &TcpSegment<'_>,
    ) -> Result<TcpIngress, SocketError> {
        let generation = self.slots[index].generation;
        let handle = SocketHandle {
            slot: index as u16,
            generation,
        };
        let (action, parent, became_connected) = {
            let socket = self.slots[index]
                .socket
                .as_mut()
                .expect("selected occupied socket");
            let previous_state = socket.tcp.as_ref().expect("TCP socket has a TCB").state;
            let previous_una = socket.tcp.as_ref().expect("TCP socket has a TCB").snd_una;
            let action = process_tcp_ingress(socket, source, segment)?;
            acknowledge_transmissions(socket, segment, previous_una);
            if matches!(action, TcpAction::Reset) {
                socket.last_error = Some(SocketError::ConnectionReset);
                socket.outstanding.clear();
                socket.out_of_order.clear();
            }
            let became_connected = previous_state == TcpState::SynReceived
                && socket.tcp.as_ref().expect("TCP socket has a TCB").state
                    == TcpState::Established;
            (action, socket.parent_listener, became_connected)
        };
        if became_connected {
            if let Some(parent) = parent {
                let full = match self.get(parent) {
                    Ok(listener) => listener.pending.len() >= listener.listen_backlog,
                    Err(error) => {
                        let _ = self.discard(handle);
                        return Err(error);
                    },
                };
                if full {
                    let _ = self.discard(handle);
                    return Err(SocketError::BacklogFull);
                }
                self.get_mut(parent)?.pending.push_back(handle);
            }
        }
        Ok(TcpIngress {
            handle: Some(handle),
            source,
            destination,
            action,
        })
    }

    fn find_tcp_connection(&self, source: Endpoint, destination: Endpoint) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.socket.as_ref().is_some_and(|socket| {
                socket.kind == SocketKind::Tcp
                    && socket.local.is_some_and(|local| {
                        local.port == destination.port
                            && (local.address.is_unspecified()
                                || local.address == destination.address)
                    })
                    && socket.remote == Some(source)
                    && socket
                        .tcp
                        .as_ref()
                        .is_some_and(|tcb| tcb.state != TcpState::Listen)
            })
        })
    }

    fn find_tcp_listener(&self, destination: Endpoint) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.socket.as_ref().is_some_and(|socket| {
                socket.kind == SocketKind::Tcp
                    && socket.local.is_some_and(|local| {
                        local.port == destination.port
                            && (local.address.is_unspecified()
                                || local.address == destination.address)
                    })
                    && socket
                        .tcp
                        .as_ref()
                        .is_some_and(|tcb| tcb.state == TcpState::Listen)
            })
        })
    }

    pub fn local_endpoint(&self, handle: SocketHandle) -> Result<Option<Endpoint>, SocketError> {
        Ok(self.get(handle)?.local)
    }

    pub fn tcp_state(&self, handle: SocketHandle) -> Result<Option<TcpState>, SocketError> {
        Ok(self.get(handle)?.tcp.as_ref().map(|tcb| tcb.state))
    }

    pub fn remote_endpoint(&self, handle: SocketHandle) -> Result<Option<Endpoint>, SocketError> {
        Ok(self.get(handle)?.remote)
    }

    /// Record a successfully dispatched TCP segment for acknowledgement and
    /// retransmission tracking. Pure ACKs consume no sequence space and are
    /// intentionally not retained.
    pub fn track_transmission(
        &mut self,
        handle: SocketHandle,
        packet: SocketTx,
        now: u64,
    ) -> Result<(), SocketError> {
        if packet.protocol != IpProtocol::Tcp {
            return Ok(());
        }
        let header = packet.tcp.ok_or(SocketError::InvalidState)?;
        let sequence_len = u32::try_from(packet.payload.len())
            .unwrap_or(u32::MAX)
            .saturating_add(u32::from(header.flags.contains(TcpFlags::SYN)))
            .saturating_add(u32::from(header.flags.contains(TcpFlags::FIN)));
        if sequence_len == 0 {
            return Ok(());
        }
        let sequence_end = header.sequence.wrapping_add(sequence_len);
        let socket = self.get_mut(handle)?;
        let tcb = socket.tcp.as_ref().ok_or(SocketError::WrongProtocol)?;
        if !sequence_after(sequence_end, tcb.snd_una) {
            return Ok(());
        }
        if let Some(existing) = socket.outstanding.iter_mut().find(|existing| {
            existing.sequence_end == sequence_end
                && existing.packet.tcp.is_some_and(|queued| {
                    queued.sequence == header.sequence && queued.flags == header.flags
                })
        }) {
            existing.sent_at = now;
            return Ok(());
        }
        if socket.outstanding.len() >= MAX_TCP_OUTSTANDING {
            return Err(SocketError::WouldBlock);
        }
        if socket.outstanding.is_empty() {
            socket.duplicate_acks = 0;
        }
        socket.outstanding.push_back(TcpOutstanding {
            packet,
            sequence_end,
            sent_at: now,
            rto_ns: TCP_INITIAL_RTO_NS,
            retries: 0,
        });
        Ok(())
    }

    /// Return TCP segments whose retransmission deadline (or fast-retransmit
    /// duplicate-ACK threshold) has elapsed. Each socket emits at most one
    /// segment per tick, and repeated failure closes it after a hard bound.
    pub fn poll_retransmissions(&mut self, now: u64) -> KVec<SocketTx> {
        let mut retransmit = KVec::new();
        for slot in &mut self.slots {
            let reap = slot.socket.as_ref().is_some_and(|socket| {
                socket.detached_at.is_some_and(|detached_at| {
                    socket
                        .tcp
                        .as_ref()
                        .is_none_or(|tcb| tcb.state == TcpState::Closed)
                        || now.saturating_sub(detached_at) >= TCP_DETACHED_TIMEOUT_NS
                })
            });
            if reap {
                slot.socket = None;
                slot.generation = slot.generation.wrapping_add(1).max(1);
                continue;
            }
            let Some(socket) = slot.socket.as_mut() else {
                continue;
            };
            if socket.kind != SocketKind::Tcp {
                continue;
            }
            let Some(front) = socket.outstanding.front_mut() else {
                continue;
            };
            let expired = now.saturating_sub(front.sent_at) >= front.rto_ns;
            if !expired && socket.duplicate_acks < 3 {
                continue;
            }
            if front.retries >= TCP_MAX_RETRIES {
                socket.last_error = Some(SocketError::ConnectionReset);
                socket.outstanding.clear();
                socket.out_of_order.clear();
                if let Some(tcb) = socket.tcp.as_mut() {
                    *tcb = TcpControlBlock::closed(tcb.rcv_wnd);
                }
                continue;
            }
            socket.slow_start_threshold = (socket.congestion_window / 2).max(TCP_MSS * 2);
            socket.congestion_window = TCP_MSS;
            socket.duplicate_acks = 0;
            front.retries = front.retries.saturating_add(1);
            front.sent_at = now;
            front.rto_ns = front.rto_ns.saturating_mul(2).min(TCP_MAX_RTO_NS);
            retransmit.push(front.packet.clone());
        }
        retransmit
    }

    pub fn detach(&mut self, handle: SocketHandle, now: u64) -> Result<(), SocketError> {
        self.get_mut(handle)?.detached_at = Some(now);
        Ok(())
    }

    pub fn rollback_send(
        &mut self,
        handle: SocketHandle,
        sequence: u32,
        length: usize,
    ) -> Result<(), SocketError> {
        let socket = self.get_mut(handle)?;
        if socket.kind != SocketKind::Tcp {
            return Ok(());
        }
        let tcb = socket.tcp.as_mut().expect("TCP socket has a TCB");
        let expected = sequence.wrapping_add(u32::try_from(length).unwrap_or(u32::MAX));
        if tcb.snd_nxt != expected {
            return Err(SocketError::InvalidState);
        }
        tcb.snd_nxt = sequence;
        Ok(())
    }

    pub fn cancel_connect(&mut self, handle: SocketHandle) -> Result<(), SocketError> {
        let socket = self.get_mut(handle)?;
        if socket.kind == SocketKind::Tcp {
            let tcb = socket.tcp.as_mut().expect("TCP socket has a TCB");
            if tcb.state != TcpState::SynSent {
                return Err(SocketError::InvalidState);
            }
            *tcb = TcpControlBlock::closed(tcb.rcv_wnd);
        }
        socket.remote = None;
        Ok(())
    }

    /// Remove a socket immediately without emitting transport traffic.
    ///
    /// This is used only to unwind a syscall after the kernel has accepted a
    /// child socket but cannot install or return its userspace descriptor.
    pub fn discard(&mut self, handle: SocketHandle) -> Result<(), SocketError> {
        self.get(handle)?;
        let mut children = KVec::new();
        for (index, slot) in self.slots.iter().enumerate() {
            if slot
                .socket
                .as_ref()
                .is_some_and(|socket| socket.parent_listener == Some(handle))
            {
                children.push(SocketHandle {
                    slot: index as u16,
                    generation: slot.generation,
                });
            }
        }
        let slot = self
            .slots
            .get_mut(handle.slot())
            .ok_or(SocketError::InvalidHandle)?;
        slot.socket = None;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        for child in children {
            let _ = self.discard(child);
        }
        Ok(())
    }
}

fn process_tcp_ingress(
    socket: &mut Socket,
    source: Endpoint,
    segment: &TcpSegment<'_>,
) -> Result<TcpAction, SocketError> {
    let tcb = socket.tcp.as_ref().expect("TCP socket has a TCB");
    let can_reorder = matches!(
        tcb.state,
        TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 | TcpState::CloseWait
    );
    if can_reorder
        && (!segment.payload.is_empty() || segment.flags.contains(TcpFlags::FIN))
        && sequence_after(segment.sequence, tcb.rcv_nxt)
    {
        let distance = segment.sequence.wrapping_sub(tcb.rcv_nxt);
        if distance < u32::from(tcb.rcv_wnd) {
            queue_out_of_order(socket, segment)?;
        }
        let tcb = socket.tcp.as_ref().expect("TCP socket has a TCB");
        return Ok(TcpAction::Send(TcpReply {
            sequence: tcb.snd_nxt,
            acknowledgement: tcb.rcv_nxt,
            flags: TcpFlags::ACK,
        }));
    }

    let mut action = socket
        .tcp
        .as_mut()
        .expect("TCP socket has a TCB")
        .on_segment(segment)
        .map_err(SocketError::from)?;
    if matches!(action, TcpAction::Deliver { .. } | TcpAction::PeerClosed(_))
        && !segment.payload.is_empty()
    {
        queue_payload(socket, source, segment.payload)?;
    }

    loop {
        let expected = socket.tcp.as_ref().expect("TCP socket has a TCB").rcv_nxt;
        let Some(index) = socket
            .out_of_order
            .iter()
            .position(|queued| queued.sequence == expected)
        else {
            break;
        };
        let queued = socket
            .out_of_order
            .remove(index)
            .expect("position selected an out-of-order segment");
        let flags = if queued.fin {
            TcpFlags::ACK.union(TcpFlags::FIN)
        } else {
            TcpFlags::ACK
        };
        let queued_action = {
            let queued_segment = TcpSegment {
                source_port: 0,
                destination_port: 0,
                sequence: queued.sequence,
                acknowledgement: queued.acknowledgement,
                flags,
                window: queued.window,
                urgent_pointer: 0,
                options: &[],
                payload: &queued.payload,
            };
            socket
                .tcp
                .as_mut()
                .expect("TCP socket has a TCB")
                .on_segment(&queued_segment)
                .map_err(SocketError::from)?
        };
        if !queued.payload.is_empty() {
            socket.queue_rx(ReceivedPacket {
                source,
                payload: queued.payload,
            })?;
        }
        action = queued_action;
    }
    Ok(action)
}

fn queue_out_of_order(socket: &mut Socket, segment: &TcpSegment<'_>) -> Result<(), SocketError> {
    if socket
        .out_of_order
        .iter()
        .any(|queued| queued.sequence == segment.sequence)
    {
        return Ok(());
    }
    let queued_bytes: usize = socket
        .out_of_order
        .iter()
        .map(|queued| queued.payload.len())
        .sum();
    if socket.out_of_order.len() >= MAX_OUT_OF_ORDER_SEGMENTS
        || queued_bytes.saturating_add(segment.payload.len()) > MAX_OUT_OF_ORDER_BYTES
    {
        return Err(SocketError::ReceiveQueueFull);
    }
    let mut payload = KVec::with_capacity(segment.payload.len());
    payload.extend_from_slice(segment.payload);
    let queued = OutOfOrderSegment {
        sequence: segment.sequence,
        acknowledgement: segment.acknowledgement,
        window: segment.window,
        payload,
        fin: segment.flags.contains(TcpFlags::FIN),
    };
    let index = socket
        .out_of_order
        .iter()
        .position(|existing| sequence_after(existing.sequence, segment.sequence))
        .unwrap_or(socket.out_of_order.len());
    socket.out_of_order.insert(index, queued);
    Ok(())
}

fn queue_payload(socket: &mut Socket, source: Endpoint, payload: &[u8]) -> Result<(), SocketError> {
    let mut owned = KVec::with_capacity(payload.len());
    owned.extend_from_slice(payload);
    socket.queue_rx(ReceivedPacket {
        source,
        payload: owned,
    })
}

fn acknowledge_transmissions(socket: &mut Socket, segment: &TcpSegment<'_>, previous_una: u32) {
    if !segment.flags.contains(TcpFlags::ACK) {
        return;
    }
    let snd_una = socket.tcp.as_ref().expect("TCP socket has a TCB").snd_una;
    let mut acknowledged = 0u32;
    while socket
        .outstanding
        .front()
        .is_some_and(|entry| !sequence_after(entry.sequence_end, snd_una))
    {
        let entry = socket.outstanding.pop_front().expect("front was present");
        acknowledged = acknowledged.saturating_add(
            u32::try_from(entry.packet.payload.len())
                .unwrap_or(u32::MAX)
                .max(1),
        );
    }
    if sequence_after(snd_una, previous_una) {
        socket.duplicate_acks = 0;
        if socket.congestion_window < socket.slow_start_threshold {
            socket.congestion_window = socket
                .congestion_window
                .saturating_add(acknowledged.max(1))
                .min(u32::from(u16::MAX));
        } else {
            let increase = TCP_MSS
                .saturating_mul(TCP_MSS)
                .checked_div(socket.congestion_window.max(1))
                .unwrap_or(1)
                .max(1);
            socket.congestion_window = socket
                .congestion_window
                .saturating_add(increase)
                .min(u32::from(u16::MAX));
        }
    } else if !socket.outstanding.is_empty()
        && segment.payload.is_empty()
        && segment.acknowledgement == snd_una
    {
        socket.duplicate_acks = socket.duplicate_acks.saturating_add(1);
    }
}

#[inline]
fn sequence_after(left: u32, right: u32) -> bool {
    (right.wrapping_sub(left) as i32) < 0
}

impl Default for SocketTable {
    fn default() -> Self {
        Self::new()
    }
}

fn next_isn() -> u32 {
    ISN_COUNTER.fetch_add(64_001, Ordering::Relaxed)
}

fn build_tcp_tx(
    socket: &Socket,
    reply: TcpReply,
    payload: KVec<u8>,
) -> Result<SocketTx, SocketError> {
    let local = socket.local.ok_or(SocketError::NotBound)?;
    let remote = socket.remote.ok_or(SocketError::NotConnected)?;
    Ok(SocketTx {
        protocol: IpProtocol::Tcp,
        source: local,
        destination: remote,
        payload,
        tcp: Some(TcpHeader {
            source_port: local.port,
            destination_port: remote.port,
            sequence: reply.sequence,
            acknowledgement: reply.acknowledgement,
            flags: reply.flags,
            window: socket.tcp.as_ref().expect("TCP socket has a TCB").rcv_wnd,
            urgent_pointer: 0,
        }),
    })
}

pub static SOCKETS: SpinLock<SocketTable> = SpinLock::new(SocketTable::new());

pub fn create(kind: SocketKind) -> Result<SocketHandle, SocketError> {
    SOCKETS.lock().create(kind)
}

pub fn bind(handle: SocketHandle, endpoint: Endpoint) -> Result<(), SocketError> {
    SOCKETS.lock().bind(handle, endpoint)
}

pub fn listen(handle: SocketHandle, backlog: usize) -> Result<(), SocketError> {
    SOCKETS.lock().listen(handle, backlog)
}

pub fn accept(handle: SocketHandle) -> Result<SocketHandle, SocketError> {
    SOCKETS.lock().accept(handle)
}

pub fn connect(
    handle: SocketHandle,
    remote: Endpoint,
    source_address: Ipv4Addr,
) -> Result<Option<SocketTx>, SocketError> {
    SOCKETS.lock().connect(handle, remote, source_address)
}

pub fn send(handle: SocketHandle, payload: &[u8]) -> Result<SendResult, SocketError> {
    SOCKETS.lock().send(handle, payload)
}

pub fn receive(handle: SocketHandle) -> Result<ReceivedPacket, SocketError> {
    SOCKETS.lock().receive(handle)
}

pub fn close(handle: SocketHandle) -> Result<Option<SocketTx>, SocketError> {
    SOCKETS.lock().close(handle)
}

pub fn cancel_connect(handle: SocketHandle) -> Result<(), SocketError> {
    SOCKETS.lock().cancel_connect(handle)
}

pub fn discard(handle: SocketHandle) -> Result<(), SocketError> {
    SOCKETS.lock().discard(handle)
}

pub fn track_transmission(
    handle: SocketHandle,
    packet: SocketTx,
    now: u64,
) -> Result<(), SocketError> {
    SOCKETS.lock().track_transmission(handle, packet, now)
}

#[must_use]
pub fn poll_retransmissions(now: u64) -> KVec<SocketTx> {
    SOCKETS.lock().poll_retransmissions(now)
}

pub fn detach(handle: SocketHandle, now: u64) -> Result<(), SocketError> {
    SOCKETS.lock().detach(handle, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn established_client() -> (SocketTable, SocketHandle, Endpoint, Endpoint) {
        let mut table = SocketTable::new();
        let handle = table.create(SocketKind::Tcp).unwrap();
        let local = Endpoint::new(Ipv4Addr::new(192, 0, 2, 10), 50_000);
        let remote = Endpoint::new(Ipv4Addr::new(192, 0, 2, 20), 443);
        table.bind(handle, local).unwrap();
        let syn = table
            .connect(handle, remote, local.address)
            .unwrap()
            .unwrap();
        let syn_header = syn.tcp.unwrap();
        table.track_transmission(handle, syn, 0).unwrap();
        let syn_ack = TcpSegment {
            source_port: remote.port,
            destination_port: local.port,
            sequence: 100,
            acknowledgement: syn_header.sequence.wrapping_add(1),
            flags: TcpFlags::SYN.union(TcpFlags::ACK),
            window: 32_768,
            urgent_pointer: 0,
            options: &[],
            payload: &[],
        };
        table.deliver_tcp(remote, local, &syn_ack).unwrap();
        assert_eq!(
            table.tcp_state(handle).unwrap(),
            Some(TcpState::Established)
        );
        (table, handle, local, remote)
    }

    #[test]
    fn retransmission_timer_is_bounded_and_ack_cancels_syn() {
        let mut table = SocketTable::new();
        let handle = table.create(SocketKind::Tcp).unwrap();
        let local = Endpoint::new(Ipv4Addr::new(192, 0, 2, 10), 50_000);
        let remote = Endpoint::new(Ipv4Addr::new(192, 0, 2, 20), 443);
        table.bind(handle, local).unwrap();
        let syn = table
            .connect(handle, remote, local.address)
            .unwrap()
            .unwrap();
        table.track_transmission(handle, syn.clone(), 10).unwrap();
        assert!(table
            .poll_retransmissions(10 + TCP_INITIAL_RTO_NS - 1)
            .is_empty());
        let retransmit = table.poll_retransmissions(10 + TCP_INITIAL_RTO_NS);
        assert_eq!(retransmit.len(), 1);
        assert_eq!(
            retransmit[0].tcp.unwrap().sequence,
            syn.tcp.unwrap().sequence
        );

        let syn_header = syn.tcp.unwrap();
        let syn_ack = TcpSegment {
            source_port: remote.port,
            destination_port: local.port,
            sequence: 700,
            acknowledgement: syn_header.sequence.wrapping_add(1),
            flags: TcpFlags::SYN.union(TcpFlags::ACK),
            window: 32_768,
            urgent_pointer: 0,
            options: &[],
            payload: &[],
        };
        table.deliver_tcp(remote, local, &syn_ack).unwrap();
        assert!(table.poll_retransmissions(u64::MAX / 2).is_empty());
    }

    #[test]
    fn out_of_order_payload_is_bounded_buffered_and_drained_in_order() {
        let (mut table, handle, local, remote) = established_client();
        let acknowledgement = table.get(handle).unwrap().tcp.as_ref().unwrap().snd_nxt;
        let later = TcpSegment {
            source_port: remote.port,
            destination_port: local.port,
            sequence: 104,
            acknowledgement,
            flags: TcpFlags::ACK,
            window: 32_768,
            urgent_pointer: 0,
            options: &[],
            payload: b"def",
        };
        let ingress = table.deliver_tcp(remote, local, &later).unwrap();
        assert!(matches!(ingress.action, TcpAction::Send(_)));
        assert!(matches!(
            table.receive(handle),
            Err(SocketError::WouldBlock)
        ));

        let first = TcpSegment {
            sequence: 101,
            payload: b"abc",
            ..later
        };
        table.deliver_tcp(remote, local, &first).unwrap();
        assert_eq!(table.receive(handle).unwrap().payload, b"abc");
        assert_eq!(table.receive(handle).unwrap().payload, b"def");
        assert_eq!(
            table.get(handle).unwrap().tcp.as_ref().unwrap().rcv_nxt,
            107
        );
    }
}
