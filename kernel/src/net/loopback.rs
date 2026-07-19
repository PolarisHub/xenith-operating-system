//! In-kernel loopback packet queue.

use alloc::collections::VecDeque;

use super::ip::IpProtocol;
use super::socket::Endpoint;
use crate::mm::KVec;

#[derive(Clone, Debug)]
pub struct LoopbackPacket {
    pub protocol: IpProtocol,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub payload: KVec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopbackError {
    QueueFull,
    PayloadTooLarge,
}

pub struct Loopback {
    queue: VecDeque<LoopbackPacket>,
    capacity: usize,
    mtu: usize,
}

impl Loopback {
    #[must_use]
    pub fn new(capacity: usize, mtu: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            capacity,
            mtu,
        }
    }

    pub fn enqueue(&mut self, packet: LoopbackPacket) -> Result<(), LoopbackError> {
        if packet.payload.len() > self.mtu {
            return Err(LoopbackError::PayloadTooLarge);
        }
        if self.queue.len() >= self.capacity {
            return Err(LoopbackError::QueueFull);
        }
        self.queue.push_back(packet);
        Ok(())
    }

    pub fn dequeue(&mut self) -> Option<LoopbackPacket> {
        self.queue.pop_front()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}
