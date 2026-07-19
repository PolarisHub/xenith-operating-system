//! Ethernet/IPv4 ARP packets and a bounded neighbour cache.

use super::eth::MacAddress;
use super::ip::Ipv4Addr;
use super::PacketError;
use crate::mm::KVec;

pub const PACKET_LEN: usize = 28;
pub const PROBE_INTERVAL_NS: u64 = 1_000_000_000;
pub const REACHABLE_TIME_NS: u64 = 30_000_000_000;
pub const ENTRY_LIFETIME_NS: u64 = 1_200_000_000_000;
pub const FAILED_HOLD_NS: u64 = 60_000_000_000;
pub const MAX_PROBES: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ArpOperation {
    Request = 1,
    Reply = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: ArpOperation,
    pub sender_hardware: MacAddress,
    pub sender_protocol: Ipv4Addr,
    pub target_hardware: MacAddress,
    pub target_protocol: Ipv4Addr,
}

impl ArpPacket {
    pub fn parse(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < PACKET_LEN {
            return Err(PacketError::Truncated);
        }
        if u16::from_be_bytes([bytes[0], bytes[1]]) != 1
            || u16::from_be_bytes([bytes[2], bytes[3]]) != 0x0800
            || bytes[4] != 6
            || bytes[5] != 4
        {
            return Err(PacketError::UnsupportedProtocol);
        }
        let operation = match u16::from_be_bytes([bytes[6], bytes[7]]) {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            _ => return Err(PacketError::Malformed),
        };
        Ok(Self {
            operation,
            sender_hardware: MacAddress(bytes[8..14].try_into().expect("six-byte slice")),
            sender_protocol: Ipv4Addr(bytes[14..18].try_into().expect("four-byte slice")),
            target_hardware: MacAddress(bytes[18..24].try_into().expect("six-byte slice")),
            target_protocol: Ipv4Addr(bytes[24..28].try_into().expect("four-byte slice")),
        })
    }

    pub fn write(self, output: &mut [u8]) -> Result<usize, PacketError> {
        if output.len() < PACKET_LEN {
            return Err(PacketError::BufferTooSmall);
        }
        output[..PACKET_LEN].fill(0);
        output[0..2].copy_from_slice(&1u16.to_be_bytes());
        output[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        output[4] = 6;
        output[5] = 4;
        output[6..8].copy_from_slice(&(self.operation as u16).to_be_bytes());
        output[8..14].copy_from_slice(&self.sender_hardware.0);
        output[14..18].copy_from_slice(&self.sender_protocol.0);
        output[18..24].copy_from_slice(&self.target_hardware.0);
        output[24..28].copy_from_slice(&self.target_protocol.0);
        Ok(PACKET_LEN)
    }

    #[must_use]
    pub const fn reply(self, local_mac: MacAddress) -> Option<Self> {
        if !matches!(self.operation, ArpOperation::Request) {
            return None;
        }
        Some(Self {
            operation: ArpOperation::Reply,
            sender_hardware: local_mac,
            sender_protocol: self.target_protocol,
            target_hardware: self.sender_hardware,
            target_protocol: self.sender_protocol,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeighborState {
    Incomplete,
    Reachable,
    Stale,
}

#[derive(Clone, Copy, Debug)]
pub struct Neighbor {
    pub protocol: Ipv4Addr,
    pub hardware: MacAddress,
    pub state: NeighborState,
    pub updated_at: u64,
    pub probes: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeDecision {
    Send,
    Wait,
    Exhausted,
    Resolved,
}

pub struct ArpCache {
    entries: KVec<Neighbor>,
    capacity: usize,
}

impl ArpCache {
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            entries: KVec::new(),
            capacity,
        }
    }

    pub fn update(&mut self, entry: Neighbor) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|candidate| candidate.protocol == entry.protocol)
        {
            *existing = entry;
            return;
        }
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() == self.capacity {
            let oldest = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, candidate)| candidate.updated_at)
                .map(|(index, _)| index)
                .unwrap_or(0);
            self.entries.swap_remove(oldest);
        }
        self.entries.push(entry);
    }

    /// Begin or advance one bounded address-resolution attempt.
    pub fn probe(&mut self, address: Ipv4Addr, now: u64) -> ProbeDecision {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|candidate| candidate.protocol == address)
        {
            if entry.state != NeighborState::Incomplete {
                return ProbeDecision::Resolved;
            }
            if entry.probes >= MAX_PROBES {
                return ProbeDecision::Exhausted;
            }
            if now.saturating_sub(entry.updated_at) < PROBE_INTERVAL_NS {
                return ProbeDecision::Wait;
            }
            entry.probes = entry.probes.saturating_add(1);
            entry.updated_at = now;
            return ProbeDecision::Send;
        }
        self.update(Neighbor {
            protocol: address,
            hardware: MacAddress::ZERO,
            state: NeighborState::Incomplete,
            updated_at: now,
            probes: 1,
        });
        ProbeDecision::Send
    }

    /// Age reachable entries, expire old mappings, and return unresolved
    /// addresses whose next bounded retry is due.
    pub fn maintain(&mut self, now: u64) -> KVec<Ipv4Addr> {
        let mut retry = KVec::new();
        self.entries.retain_mut(|entry| {
            let age = now.saturating_sub(entry.updated_at);
            match entry.state {
                NeighborState::Reachable if age >= ENTRY_LIFETIME_NS => return false,
                NeighborState::Reachable if age >= REACHABLE_TIME_NS => {
                    entry.state = NeighborState::Stale;
                },
                NeighborState::Stale if age >= ENTRY_LIFETIME_NS => return false,
                NeighborState::Incomplete
                    if entry.probes >= MAX_PROBES && age >= FAILED_HOLD_NS =>
                {
                    return false;
                },
                NeighborState::Incomplete
                    if entry.probes < MAX_PROBES && age >= PROBE_INTERVAL_NS =>
                {
                    entry.probes = entry.probes.saturating_add(1);
                    entry.updated_at = now;
                    retry.push(entry.protocol);
                },
                _ => {},
            }
            true
        });
        retry
    }

    #[must_use]
    pub fn lookup(&self, address: Ipv4Addr) -> Option<Neighbor> {
        self.entries
            .iter()
            .find(|entry| entry.protocol == address && entry.state != NeighborState::Incomplete)
            .copied()
    }

    pub fn mark_stale_before(&mut self, deadline: u64) {
        for entry in &mut self.entries {
            if entry.updated_at < deadline && entry.state == NeighborState::Reachable {
                entry.state = NeighborState::Stale;
            }
        }
    }

    pub fn remove(&mut self, address: Ipv4Addr) -> bool {
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.protocol == address)
        else {
            return false;
        };
        self.entries.swap_remove(index);
        true
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_are_rate_limited_bounded_and_expired() {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let mut cache = ArpCache::new(4);
        assert_eq!(cache.probe(address, 0), ProbeDecision::Send);
        assert_eq!(
            cache.probe(address, PROBE_INTERVAL_NS - 1),
            ProbeDecision::Wait
        );
        let mut now = PROBE_INTERVAL_NS;
        for _ in 1..MAX_PROBES {
            assert_eq!(cache.probe(address, now), ProbeDecision::Send);
            now += PROBE_INTERVAL_NS;
        }
        assert_eq!(cache.probe(address, now), ProbeDecision::Exhausted);
        assert!(cache.maintain(now).is_empty());
        assert_eq!(cache.probe(address, now), ProbeDecision::Exhausted);
        cache.maintain(now + FAILED_HOLD_NS);
        assert!(cache.is_empty());
    }

    #[test]
    fn resolved_neighbors_age_from_reachable_to_stale_then_expire() {
        let address = Ipv4Addr::new(198, 51, 100, 7);
        let mut cache = ArpCache::new(4);
        cache.update(Neighbor {
            protocol: address,
            hardware: MacAddress([2, 0, 0, 0, 0, 7]),
            state: NeighborState::Reachable,
            updated_at: 10,
            probes: 0,
        });
        cache.maintain(10 + REACHABLE_TIME_NS);
        assert_eq!(cache.lookup(address).unwrap().state, NeighborState::Stale);
        cache.maintain(10 + ENTRY_LIFETIME_NS);
        assert!(cache.lookup(address).is_none());
    }
}
