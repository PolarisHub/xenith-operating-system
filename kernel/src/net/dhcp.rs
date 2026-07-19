//! DHCPv4 client wire format and bounded lease state machine.
//!
//! The state machine is transport-independent: the network worker supplies a
//! monotonic timestamp, transmits returned messages, and applies returned
//! leases to the interface table. This keeps parsing testable without device
//! or scheduler state.

use super::eth::MacAddress;
use super::ip::Ipv4Addr;
use super::PacketError;
use crate::mm::Kbox;

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;
pub const MAX_MESSAGE_LEN: usize = 576;

const BOOTP_FIXED_LEN: usize = 236;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const OPTIONS_OFFSET: usize = BOOTP_FIXED_LEN + MAGIC_COOKIE.len();
const RETRY_BASE_NS: u64 = 1_000_000_000;
const RETRY_MAX_NS: u64 = 16_000_000_000;
const RESTART_NS: u64 = 60_000_000_000;
const MAX_ATTEMPTS: u8 = 5;

const OPTION_SUBNET_MASK: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNS: u8 = 6;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_ID: u8 = 54;
const OPTION_PARAMETER_REQUEST: u8 = 55;
const OPTION_RENEWAL_TIME: u8 = 58;
const OPTION_REBIND_TIME: u8 = 59;
const OPTION_CLIENT_ID: u8 = 61;
const OPTION_END: u8 = 255;

#[derive(Clone, Copy)]
struct MessageOptions {
    message_type: MessageType,
    requested_address: Option<Ipv4Addr>,
    server: Option<Ipv4Addr>,
    client_address: Ipv4Addr,
    broadcast: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MessageType {
    fn parse(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: [Option<Ipv4Addr>; 2],
    pub server: Ipv4Addr,
    pub lease_seconds: u32,
    pub renewal_seconds: u32,
    pub rebind_seconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub message_type: MessageType,
    pub transaction_id: u32,
    pub client_mac: MacAddress,
    pub offered_address: Ipv4Addr,
    pub subnet_mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: [Option<Ipv4Addr>; 2],
    pub server: Option<Ipv4Addr>,
    pub lease_seconds: Option<u32>,
    pub renewal_seconds: Option<u32>,
    pub rebind_seconds: Option<u32>,
}

impl Reply {
    pub fn parse(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < OPTIONS_OFFSET || bytes[0] != 2 || bytes[1] != 1 || bytes[2] != 6 {
            return Err(PacketError::Malformed);
        }
        if bytes[BOOTP_FIXED_LEN..OPTIONS_OFFSET] != MAGIC_COOKIE {
            return Err(PacketError::Malformed);
        }
        let transaction_id = u32::from_be_bytes(
            bytes[4..8]
                .try_into()
                .expect("DHCP transaction ID is four bytes"),
        );
        let offered_address = Ipv4Addr(bytes[16..20].try_into().expect("yiaddr is four bytes"));
        let client_mac = MacAddress(bytes[28..34].try_into().expect("chaddr is six bytes"));
        let mut message_type = None;
        let mut subnet_mask = None;
        let mut gateway = None;
        let mut dns_servers = [None; 2];
        let mut server = None;
        let mut lease_seconds = None;
        let mut renewal_seconds = None;
        let mut rebind_seconds = None;
        let mut offset = OPTIONS_OFFSET;
        while offset < bytes.len() {
            let code = bytes[offset];
            offset += 1;
            if code == 0 {
                continue;
            }
            if code == OPTION_END {
                break;
            }
            let length = usize::from(*bytes.get(offset).ok_or(PacketError::Truncated)?);
            offset += 1;
            let end = offset.checked_add(length).ok_or(PacketError::Oversized)?;
            let value = bytes.get(offset..end).ok_or(PacketError::Truncated)?;
            offset = end;
            match code {
                OPTION_MESSAGE_TYPE if value.len() == 1 => {
                    message_type = MessageType::parse(value[0]);
                },
                OPTION_SUBNET_MASK if value.len() == 4 => {
                    subnet_mask = Some(Ipv4Addr(value.try_into().expect("mask is four bytes")));
                },
                OPTION_ROUTER if value.len() >= 4 => {
                    gateway = Some(Ipv4Addr(
                        value[..4].try_into().expect("router is four bytes"),
                    ));
                },
                OPTION_DNS => {
                    for (index, slot) in dns_servers.iter_mut().enumerate() {
                        let start = index * 4;
                        let Some(address) = value.get(start..start + 4) else {
                            break;
                        };
                        *slot = Some(Ipv4Addr(
                            address.try_into().expect("DNS address is four bytes"),
                        ));
                    }
                },
                OPTION_SERVER_ID if value.len() == 4 => {
                    server = Some(Ipv4Addr(value.try_into().expect("server ID is four bytes")));
                },
                OPTION_LEASE_TIME if value.len() == 4 => {
                    lease_seconds = Some(u32::from_be_bytes(value.try_into().expect("u32 option")));
                },
                OPTION_RENEWAL_TIME if value.len() == 4 => {
                    renewal_seconds =
                        Some(u32::from_be_bytes(value.try_into().expect("u32 option")));
                },
                OPTION_REBIND_TIME if value.len() == 4 => {
                    rebind_seconds =
                        Some(u32::from_be_bytes(value.try_into().expect("u32 option")));
                },
                _ => {},
            }
        }
        Ok(Self {
            message_type: message_type.ok_or(PacketError::Malformed)?,
            transaction_id,
            client_mac,
            offered_address,
            subnet_mask,
            gateway,
            dns_servers,
            server,
            lease_seconds,
            renewal_seconds,
            rebind_seconds,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Init,
    Selecting,
    Requesting { address: Ipv4Addr, server: Ipv4Addr },
    Bound { lease: Lease, acquired_at: u64 },
    Renewing { lease: Lease, acquired_at: u64 },
    Rebinding { lease: Lease, acquired_at: u64 },
    Backoff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    Transmit {
        length: usize,
        bytes: Kbox<[u8; MAX_MESSAGE_LEN]>,
        broadcast: bool,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    },
    LeaseAcquired(Lease),
    LeaseExpired,
}

pub struct Client {
    pub interface: u16,
    mac: MacAddress,
    transaction_id: u32,
    state: State,
    attempts: u8,
    next_action_at: u64,
}

impl Client {
    #[must_use]
    pub const fn new(interface: u16, mac: MacAddress) -> Self {
        let bytes = mac.0;
        let transaction_id = 0x584e_0000
            ^ ((interface as u32) << 8)
            ^ ((bytes[2] as u32) << 24)
            ^ ((bytes[3] as u32) << 16)
            ^ ((bytes[4] as u32) << 8)
            ^ bytes[5] as u32;
        Self {
            interface,
            mac,
            transaction_id,
            state: State::Init,
            attempts: 0,
            next_action_at: 0,
        }
    }

    #[must_use]
    pub fn lease(&self) -> Option<Lease> {
        match self.state {
            State::Bound { lease, .. }
            | State::Renewing { lease, .. }
            | State::Rebinding { lease, .. } => Some(lease),
            _ => None,
        }
    }

    #[must_use]
    pub fn lease_remaining_seconds(&self, now: u64) -> u32 {
        let (lease, acquired_at) = match self.state {
            State::Bound { lease, acquired_at }
            | State::Renewing { lease, acquired_at }
            | State::Rebinding { lease, acquired_at } => (lease, acquired_at),
            _ => return 0,
        };
        let elapsed = now.saturating_sub(acquired_at) / 1_000_000_000;
        lease
            .lease_seconds
            .saturating_sub(u32::try_from(elapsed).unwrap_or(u32::MAX))
    }

    pub fn poll(&mut self, now: u64) -> Result<Option<ClientEvent>, PacketError> {
        if now < self.next_action_at {
            return Ok(None);
        }
        match self.state {
            State::Init => {
                self.state = State::Selecting;
                self.attempts = 0;
                self.transmit_discover(now).map(Some)
            },
            State::Selecting => {
                if self.attempts >= MAX_ATTEMPTS {
                    self.state = State::Backoff;
                    self.next_action_at = now.saturating_add(RESTART_NS);
                    return Ok(None);
                }
                self.transmit_discover(now).map(Some)
            },
            State::Requesting { address, server } => {
                if self.attempts >= MAX_ATTEMPTS {
                    self.state = State::Backoff;
                    self.next_action_at = now.saturating_add(RESTART_NS);
                    return Ok(None);
                }
                self.transmit_request(now, address, Some(server), Ipv4Addr::UNSPECIFIED, true)
                    .map(Some)
            },
            State::Bound { lease, acquired_at } => {
                let renew_at = acquired_at.saturating_add(seconds_ns(lease.renewal_seconds));
                if now < renew_at {
                    self.next_action_at = renew_at;
                    return Ok(None);
                }
                self.state = State::Renewing { lease, acquired_at };
                self.attempts = 0;
                self.transmit_request(now, lease.address, None, lease.address, false)
                    .map(Some)
            },
            State::Renewing { lease, acquired_at } => {
                let rebind_at = acquired_at.saturating_add(seconds_ns(lease.rebind_seconds));
                if now >= rebind_at {
                    self.state = State::Rebinding { lease, acquired_at };
                    self.attempts = 0;
                    return self
                        .transmit_request(now, lease.address, None, lease.address, true)
                        .map(Some);
                }
                self.transmit_request(now, lease.address, None, lease.address, false)
                    .map(Some)
            },
            State::Rebinding { lease, acquired_at } => {
                let expires_at = acquired_at.saturating_add(seconds_ns(lease.lease_seconds));
                if now >= expires_at {
                    self.state = State::Init;
                    self.next_action_at = now;
                    return Ok(Some(ClientEvent::LeaseExpired));
                }
                self.transmit_request(now, lease.address, None, lease.address, true)
                    .map(Some)
            },
            State::Backoff => {
                self.state = State::Init;
                self.poll(now)
            },
        }
    }

    pub fn receive(&mut self, bytes: &[u8], now: u64) -> Result<Option<ClientEvent>, PacketError> {
        let reply = Reply::parse(bytes)?;
        if reply.transaction_id != self.transaction_id || reply.client_mac != self.mac {
            return Ok(None);
        }
        match (self.state, reply.message_type) {
            (State::Selecting, MessageType::Offer) => {
                let server = reply.server.ok_or(PacketError::Malformed)?;
                if reply.offered_address.is_unspecified() {
                    return Err(PacketError::Malformed);
                }
                self.state = State::Requesting {
                    address: reply.offered_address,
                    server,
                };
                self.attempts = 0;
                self.transmit_request(
                    now,
                    reply.offered_address,
                    Some(server),
                    Ipv4Addr::UNSPECIFIED,
                    true,
                )
                .map(Some)
            },
            (
                State::Requesting { .. } | State::Renewing { .. } | State::Rebinding { .. },
                MessageType::Ack,
            ) => {
                let previous_lease = match self.state {
                    State::Renewing { lease, .. } | State::Rebinding { lease, .. } => Some(lease),
                    _ => None,
                };
                let lease = lease_from_reply(reply, previous_lease)?;
                self.state = State::Bound {
                    lease,
                    acquired_at: now,
                };
                self.attempts = 0;
                self.next_action_at = now.saturating_add(seconds_ns(lease.renewal_seconds));
                Ok(Some(ClientEvent::LeaseAcquired(lease)))
            },
            (
                State::Requesting { .. } | State::Renewing { .. } | State::Rebinding { .. },
                MessageType::Nak,
            ) => {
                let had_lease =
                    matches!(self.state, State::Renewing { .. } | State::Rebinding { .. });
                self.state = State::Init;
                self.attempts = 0;
                self.next_action_at = now;
                Ok(had_lease.then_some(ClientEvent::LeaseExpired))
            },
            _ => Ok(None),
        }
    }

    fn transmit_discover(&mut self, now: u64) -> Result<ClientEvent, PacketError> {
        let mut bytes = Kbox::new([0u8; MAX_MESSAGE_LEN]);
        let length = write_message(&mut *bytes, self.transaction_id, self.mac, MessageOptions {
            message_type: MessageType::Discover,
            requested_address: None,
            server: None,
            client_address: Ipv4Addr::UNSPECIFIED,
            broadcast: true,
        })?;
        self.schedule_retry(now);
        Ok(ClientEvent::Transmit {
            length,
            bytes,
            broadcast: true,
            source: Ipv4Addr::UNSPECIFIED,
            destination: Ipv4Addr::BROADCAST,
        })
    }

    fn transmit_request(
        &mut self,
        now: u64,
        address: Ipv4Addr,
        server: Option<Ipv4Addr>,
        source: Ipv4Addr,
        broadcast: bool,
    ) -> Result<ClientEvent, PacketError> {
        let mut bytes = Kbox::new([0u8; MAX_MESSAGE_LEN]);
        let length = write_message(&mut *bytes, self.transaction_id, self.mac, MessageOptions {
            message_type: MessageType::Request,
            requested_address: Some(address),
            server,
            client_address: source,
            broadcast,
        })?;
        self.schedule_retry(now);
        Ok(ClientEvent::Transmit {
            length,
            bytes,
            broadcast,
            source,
            destination: server.unwrap_or(Ipv4Addr::BROADCAST),
        })
    }

    fn schedule_retry(&mut self, now: u64) {
        let shift = self.attempts.min(4);
        let delay = RETRY_BASE_NS
            .saturating_mul(1u64 << shift)
            .min(RETRY_MAX_NS);
        self.attempts = self.attempts.saturating_add(1);
        self.next_action_at = now.saturating_add(delay);
    }
}

fn lease_from_reply(reply: Reply, previous: Option<Lease>) -> Result<Lease, PacketError> {
    let address = if reply.offered_address.is_unspecified() {
        previous.ok_or(PacketError::Malformed)?.address
    } else {
        reply.offered_address
    };
    let prefix_len = if let Some(mask) = reply.subnet_mask {
        prefix_length(mask).ok_or(PacketError::Malformed)?
    } else {
        previous.ok_or(PacketError::Malformed)?.prefix_len
    };
    let lease_seconds = reply
        .lease_seconds
        .or(previous.map(|lease| lease.lease_seconds))
        .unwrap_or(3600)
        .max(60);
    let renewal_seconds = reply
        .renewal_seconds
        .unwrap_or(lease_seconds / 2)
        .clamp(1, lease_seconds.saturating_sub(2));
    let rebind_seconds = reply
        .rebind_seconds
        .unwrap_or(lease_seconds.saturating_mul(7) / 8)
        .clamp(
            renewal_seconds.saturating_add(1),
            lease_seconds.saturating_sub(1),
        );
    Ok(Lease {
        address,
        prefix_len,
        gateway: reply
            .gateway
            .filter(|address| !address.is_unspecified())
            .or(previous.and_then(|lease| lease.gateway)),
        dns_servers: if reply.dns_servers == [None; 2] {
            previous.map_or([None; 2], |lease| lease.dns_servers)
        } else {
            reply.dns_servers
        },
        server: reply
            .server
            .or(previous.map(|lease| lease.server))
            .ok_or(PacketError::Malformed)?,
        lease_seconds,
        renewal_seconds,
        rebind_seconds,
    })
}

fn prefix_length(mask: Ipv4Addr) -> Option<u8> {
    let mut prefix = 0u8;
    let mut saw_zero = false;
    for byte in mask.0 {
        for bit in (0..8).rev() {
            let set = byte & (1 << bit) != 0;
            if saw_zero && set {
                return None;
            }
            if set {
                prefix += 1;
            } else {
                saw_zero = true;
            }
        }
    }
    Some(prefix)
}

fn write_message(
    output: &mut [u8],
    transaction_id: u32,
    mac: MacAddress,
    options: MessageOptions,
) -> Result<usize, PacketError> {
    if output.len() < MAX_MESSAGE_LEN {
        return Err(PacketError::BufferTooSmall);
    }
    output[..MAX_MESSAGE_LEN].fill(0);
    output[0] = 1;
    output[1] = 1;
    output[2] = 6;
    output[4..8].copy_from_slice(&transaction_id.to_be_bytes());
    output[12..16].copy_from_slice(&options.client_address.0);
    if options.broadcast {
        output[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    }
    output[28..34].copy_from_slice(&mac.0);
    output[BOOTP_FIXED_LEN..OPTIONS_OFFSET].copy_from_slice(&MAGIC_COOKIE);
    let mut offset = OPTIONS_OFFSET;
    push_option(output, &mut offset, OPTION_MESSAGE_TYPE, &[
        options.message_type as u8,
    ])?;
    push_option(output, &mut offset, OPTION_CLIENT_ID, &[
        1, mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5],
    ])?;
    if let Some(address) = options.requested_address {
        push_option(output, &mut offset, OPTION_REQUESTED_IP, &address.0)?;
    }
    if let Some(server) = options.server {
        push_option(output, &mut offset, OPTION_SERVER_ID, &server.0)?;
    }
    push_option(output, &mut offset, OPTION_PARAMETER_REQUEST, &[
        OPTION_SUBNET_MASK,
        OPTION_ROUTER,
        OPTION_DNS,
        OPTION_LEASE_TIME,
        OPTION_RENEWAL_TIME,
        OPTION_REBIND_TIME,
    ])?;
    *output.get_mut(offset).ok_or(PacketError::BufferTooSmall)? = OPTION_END;
    offset += 1;
    // BOOTP clients must accept 576-byte IP datagrams. Padding the payload to
    // 300 bytes avoids broken legacy DHCP relays without forcing every frame
    // to the maximum receive size.
    Ok(offset.max(300))
}

fn push_option(
    output: &mut [u8],
    offset: &mut usize,
    code: u8,
    value: &[u8],
) -> Result<(), PacketError> {
    let length = u8::try_from(value.len()).map_err(|_| PacketError::Oversized)?;
    let end = offset
        .checked_add(2 + value.len())
        .ok_or(PacketError::Oversized)?;
    if end > output.len() {
        return Err(PacketError::BufferTooSmall);
    }
    output[*offset] = code;
    output[*offset + 1] = length;
    output[*offset + 2..end].copy_from_slice(value);
    *offset = end;
    Ok(())
}

const fn seconds_ns(seconds: u32) -> u64 {
    (seconds as u64).saturating_mul(1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(
        client: &Client,
        kind: MessageType,
        address: Ipv4Addr,
        server: Ipv4Addr,
    ) -> [u8; MAX_MESSAGE_LEN] {
        let mut bytes = [0u8; MAX_MESSAGE_LEN];
        bytes[0] = 2;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[4..8].copy_from_slice(&client.transaction_id.to_be_bytes());
        bytes[16..20].copy_from_slice(&address.0);
        bytes[28..34].copy_from_slice(&client.mac.0);
        bytes[BOOTP_FIXED_LEN..OPTIONS_OFFSET].copy_from_slice(&MAGIC_COOKIE);
        let mut offset = OPTIONS_OFFSET;
        push_option(&mut bytes, &mut offset, OPTION_MESSAGE_TYPE, &[kind as u8]).unwrap();
        push_option(&mut bytes, &mut offset, OPTION_SERVER_ID, &server.0).unwrap();
        push_option(&mut bytes, &mut offset, OPTION_SUBNET_MASK, &[
            255, 255, 255, 0,
        ])
        .unwrap();
        push_option(&mut bytes, &mut offset, OPTION_ROUTER, &[10, 0, 2, 2]).unwrap();
        push_option(&mut bytes, &mut offset, OPTION_DNS, &[
            1, 1, 1, 1, 8, 8, 8, 8,
        ])
        .unwrap();
        push_option(
            &mut bytes,
            &mut offset,
            OPTION_LEASE_TIME,
            &120u32.to_be_bytes(),
        )
        .unwrap();
        bytes[offset] = OPTION_END;
        bytes
    }

    #[test]
    fn discover_offer_request_ack_installs_valid_lease() {
        let mac = MacAddress([0x02, 1, 2, 3, 4, 5]);
        let mut client = Client::new(1, mac);
        let discover = client.poll(0).unwrap().unwrap();
        assert!(matches!(discover, ClientEvent::Transmit {
            broadcast: true,
            ..
        }));
        let offered = Ipv4Addr::new(10, 0, 2, 15);
        let server = Ipv4Addr::new(10, 0, 2, 2);
        let request = client
            .receive(&reply(&client, MessageType::Offer, offered, server), 1)
            .unwrap()
            .unwrap();
        assert!(matches!(request, ClientEvent::Transmit {
            broadcast: true,
            ..
        }));
        let event = client
            .receive(&reply(&client, MessageType::Ack, offered, server), 2)
            .unwrap()
            .unwrap();
        let ClientEvent::LeaseAcquired(lease) = event else {
            panic!("expected lease");
        };
        assert_eq!(lease.address, offered);
        assert_eq!(lease.prefix_len, 24);
        assert_eq!(lease.gateway, Some(server));
        assert_eq!(lease.dns_servers[0], Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(lease.renewal_seconds, 60);
        assert_eq!(lease.rebind_seconds, 105);
    }

    #[test]
    fn retries_are_bounded_then_back_off() {
        let mut client = Client::new(1, MacAddress([0x02, 1, 2, 3, 4, 5]));
        let mut now = 0;
        let mut sends = 0;
        for _ in 0..16 {
            if matches!(
                client.poll(now).unwrap(),
                Some(ClientEvent::Transmit { .. })
            ) {
                sends += 1;
            }
            now = now.saturating_add(RETRY_MAX_NS);
        }
        assert!(sends >= usize::from(MAX_ATTEMPTS));
        assert!(sends < 16);
    }

    #[test]
    fn malformed_non_contiguous_mask_is_rejected() {
        let reply = Reply {
            message_type: MessageType::Ack,
            transaction_id: 1,
            client_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            offered_address: Ipv4Addr::new(10, 0, 0, 2),
            subnet_mask: Some(Ipv4Addr::new(255, 0, 255, 0)),
            gateway: None,
            dns_servers: [None; 2],
            server: Some(Ipv4Addr::new(10, 0, 0, 1)),
            lease_seconds: Some(60),
            renewal_seconds: None,
            rebind_seconds: None,
        };
        assert_eq!(lease_from_reply(reply, None), Err(PacketError::Malformed));
    }
}
