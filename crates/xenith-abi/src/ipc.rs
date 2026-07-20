//! Stable records for Xenith's bounded local IPC transport.
//!
//! The channel syscalls use fixed-width records so no Rust pointer, `usize`,
//! `bool`, or data-carrying enum crosses the kernel boundary. A channel
//! message carries at most [`IPC_MAX_MESSAGE_BYTES`] inline bytes and at most
//! [`IPC_MAX_TRANSFERS`] descriptor transfers. Unused bytes and transfer slots
//! must be zero, making every accepted record canonical.

use core::mem::{align_of, size_of};

/// Version of the channel record ABI.
pub const IPC_ABI_VERSION: u16 = 1;
/// Maximum inline payload carried by one atomic channel message.
pub const IPC_MAX_MESSAGE_BYTES: u32 = 4096;
/// Maximum descriptors transferred atomically with one channel message.
pub const IPC_MAX_TRANSFERS: u16 = 4;
/// Block without a deadline in `channel_send` or `channel_recv`.
pub const IPC_TIMEOUT_INFINITE: u64 = u64::MAX;

/// Permit read operations through a transferred descriptor.
pub const IPC_TRANSFER_RIGHT_READ: u32 = 1 << 0;
/// Permit write operations through a transferred descriptor.
pub const IPC_TRANSFER_RIGHT_WRITE: u32 = 1 << 1;
/// Permit mappings to be created through a transferred descriptor.
pub const IPC_TRANSFER_RIGHT_MAP: u32 = 1 << 2;
/// Permit the received descriptor to be transferred again.
pub const IPC_TRANSFER_RIGHT_TRANSFER: u32 = 1 << 3;
pub const IPC_TRANSFER_RIGHTS_ALL: u32 = IPC_TRANSFER_RIGHT_READ
    | IPC_TRANSFER_RIGHT_WRITE
    | IPC_TRANSFER_RIGHT_MAP
    | IPC_TRANSFER_RIGHT_TRANSFER;

/// Size of the channel-pair output record written by `channel_create`.
pub const IPC_CHANNEL_PAIR_SIZE: u16 = size_of::<IpcChannelPair>() as u16;
/// Size of either direction-specific descriptor transfer record.
pub const IPC_TRANSFER_SIZE: u16 = size_of::<IpcSendTransfer>() as u16;
/// Byte offset of the inline payload in both message record variants.
pub const IPC_MESSAGE_HEADER_SIZE: u16 = 80;
/// Total fixed width of either channel message record variant.
pub const IPC_MESSAGE_RECORD_SIZE: u32 = size_of::<IpcSendMessage>() as u32;

/// Output of `channel_create(out_pair, flags)`.
///
/// `flags` is currently reserved and must be zero. On success both endpoint
/// descriptors are nonnegative and distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct IpcChannelPair {
    pub version: u16,
    pub record_size: u16,
    pub flags: u32,
    pub endpoint0: i32,
    pub endpoint1: i32,
}

impl IpcChannelPair {
    #[must_use]
    pub const fn new(endpoint0: i32, endpoint1: i32) -> Self {
        Self {
            version: IPC_ABI_VERSION,
            record_size: IPC_CHANNEL_PAIR_SIZE,
            flags: 0,
            endpoint0,
            endpoint1,
        }
    }

    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.version == IPC_ABI_VERSION
            && self.record_size == IPC_CHANNEL_PAIR_SIZE
            && self.flags == 0
            && self.endpoint0 >= 0
            && self.endpoint1 >= 0
            && self.endpoint0 != self.endpoint1
    }
}

impl Default for IpcChannelPair {
    fn default() -> Self {
        Self::new(-1, -1)
    }
}

/// One descriptor attached to a message passed to `channel_send`.
///
/// `source_fd` names a descriptor in the sender. `rights` requests an
/// attenuation of that descriptor's current rights; the kernel must reject
/// rights the source does not possess. `tag` is opaque and is echoed to the
/// receiver.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct IpcSendTransfer {
    pub source_fd: i32,
    pub rights: u32,
    pub tag: u64,
}

impl IpcSendTransfer {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.source_fd >= 0 && self.rights != 0 && self.rights & !IPC_TRANSFER_RIGHTS_ALL == 0
    }

    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.source_fd == 0 && self.rights == 0 && self.tag == 0
    }
}

/// One installed descriptor returned in a message by `channel_recv`.
///
/// `installed_fd` is local to the receiver, `rights` is the attenuated rights
/// mask granted by the sender, and `tag` is copied unchanged from the matching
/// [`IpcSendTransfer`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct IpcReceiveTransfer {
    pub installed_fd: i32,
    pub rights: u32,
    pub tag: u64,
}

impl IpcReceiveTransfer {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.installed_fd >= 0 && self.rights != 0 && self.rights & !IPC_TRANSFER_RIGHTS_ALL == 0
    }

    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.installed_fd == 0 && self.rights == 0 && self.tag == 0
    }
}

/// Fixed input record for `channel_send(fd, message, timeout_ns, flags)`.
///
/// The syscall `flags` argument and this record's `flags` field are currently
/// reserved and must both be zero. Sending is atomic: either the payload and
/// every active transfer are queued together or the channel is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct IpcSendMessage {
    pub version: u16,
    pub header_size: u16,
    pub payload_length: u32,
    pub transfer_count: u16,
    pub flags: u16,
    /// Must be zero.
    pub reserved: u32,
    pub transfers: [IpcSendTransfer; IPC_MAX_TRANSFERS as usize],
    pub payload: [u8; IPC_MAX_MESSAGE_BYTES as usize],
}

impl IpcSendMessage {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            version: IPC_ABI_VERSION,
            header_size: IPC_MESSAGE_HEADER_SIZE,
            payload_length: 0,
            transfer_count: 0,
            flags: 0,
            reserved: 0,
            transfers: [IpcSendTransfer {
                source_fd: 0,
                rights: 0,
                tag: 0,
            }; IPC_MAX_TRANSFERS as usize],
            payload: [0; IPC_MAX_MESSAGE_BYTES as usize],
        }
    }

    /// Replace the inline payload, zeroing the inactive tail.
    pub fn set_payload(&mut self, payload: &[u8]) -> bool {
        if payload.len() > IPC_MAX_MESSAGE_BYTES as usize {
            return false;
        }
        self.payload.fill(0);
        self.payload[..payload.len()].copy_from_slice(payload);
        self.payload_length = payload.len() as u32;
        true
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.version != IPC_ABI_VERSION
            || self.header_size != IPC_MESSAGE_HEADER_SIZE
            || self.payload_length > IPC_MAX_MESSAGE_BYTES
            || self.transfer_count > IPC_MAX_TRANSFERS
            || self.flags != 0
            || self.reserved != 0
        {
            return false;
        }
        let payload_length = self.payload_length as usize;
        let transfer_count = self.transfer_count as usize;
        self.transfers[..transfer_count]
            .iter()
            .all(IpcSendTransfer::is_valid)
            && self.transfers[transfer_count..]
                .iter()
                .all(IpcSendTransfer::is_zero)
            && self.payload[payload_length..].iter().all(|byte| *byte == 0)
    }
}

impl Default for IpcSendMessage {
    fn default() -> Self {
        Self::empty()
    }
}

/// Fixed output record for `channel_recv(fd, message, timeout_ns, flags)`.
///
/// The kernel installs all transferred descriptors before publishing this
/// record. Failure, including insufficient descriptor capacity, leaves the
/// queued message unconsumed. The syscall `flags` argument and record `flags`
/// are currently reserved and must be zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct IpcReceiveMessage {
    pub version: u16,
    pub header_size: u16,
    pub payload_length: u32,
    pub transfer_count: u16,
    pub flags: u16,
    /// Must be zero.
    pub reserved: u32,
    pub transfers: [IpcReceiveTransfer; IPC_MAX_TRANSFERS as usize],
    pub payload: [u8; IPC_MAX_MESSAGE_BYTES as usize],
}

impl IpcReceiveMessage {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            version: IPC_ABI_VERSION,
            header_size: IPC_MESSAGE_HEADER_SIZE,
            payload_length: 0,
            transfer_count: 0,
            flags: 0,
            reserved: 0,
            transfers: [IpcReceiveTransfer {
                installed_fd: 0,
                rights: 0,
                tag: 0,
            }; IPC_MAX_TRANSFERS as usize],
            payload: [0; IPC_MAX_MESSAGE_BYTES as usize],
        }
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.version != IPC_ABI_VERSION
            || self.header_size != IPC_MESSAGE_HEADER_SIZE
            || self.payload_length > IPC_MAX_MESSAGE_BYTES
            || self.transfer_count > IPC_MAX_TRANSFERS
            || self.flags != 0
            || self.reserved != 0
        {
            return false;
        }
        let payload_length = self.payload_length as usize;
        let transfer_count = self.transfer_count as usize;
        self.transfers[..transfer_count]
            .iter()
            .all(IpcReceiveTransfer::is_valid)
            && self.transfers[transfer_count..]
                .iter()
                .all(IpcReceiveTransfer::is_zero)
            && self.payload[payload_length..].iter().all(|byte| *byte == 0)
    }
}

impl Default for IpcReceiveMessage {
    fn default() -> Self {
        Self::empty()
    }
}

macro_rules! assert_layout {
    ($ty:ty, $size:expr, $align:expr) => {
        const _: [(); $size] = [(); size_of::<$ty>()];
        const _: [(); $align] = [(); align_of::<$ty>()];
    };
}

assert_layout!(IpcChannelPair, 16, 4);
assert_layout!(IpcSendTransfer, 16, 8);
assert_layout!(IpcReceiveTransfer, 16, 8);
assert_layout!(IpcSendMessage, 4176, 8);
assert_layout!(IpcReceiveMessage, 4176, 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_have_stable_layouts_and_offsets() {
        assert_eq!(IPC_CHANNEL_PAIR_SIZE, 16);
        assert_eq!(IPC_TRANSFER_SIZE, 16);
        assert_eq!(IPC_MESSAGE_RECORD_SIZE, 4176);
        assert_eq!(size_of::<IpcChannelPair>(), 16);
        assert_eq!(align_of::<IpcChannelPair>(), 4);
        assert_eq!(core::mem::offset_of!(IpcChannelPair, endpoint0), 8);
        assert_eq!(core::mem::offset_of!(IpcChannelPair, endpoint1), 12);

        assert_eq!(size_of::<IpcSendTransfer>(), 16);
        assert_eq!(align_of::<IpcSendTransfer>(), 8);
        assert_eq!(core::mem::offset_of!(IpcSendTransfer, source_fd), 0);
        assert_eq!(core::mem::offset_of!(IpcSendTransfer, rights), 4);
        assert_eq!(core::mem::offset_of!(IpcSendTransfer, tag), 8);
        assert_eq!(size_of::<IpcReceiveTransfer>(), 16);
        assert_eq!(core::mem::offset_of!(IpcReceiveTransfer, installed_fd), 0);

        assert_eq!(size_of::<IpcSendMessage>(), 4176);
        assert_eq!(align_of::<IpcSendMessage>(), 8);
        assert_eq!(core::mem::offset_of!(IpcSendMessage, version), 0);
        assert_eq!(core::mem::offset_of!(IpcSendMessage, payload_length), 4);
        assert_eq!(core::mem::offset_of!(IpcSendMessage, transfer_count), 8);
        assert_eq!(core::mem::offset_of!(IpcSendMessage, transfers), 16);
        assert_eq!(
            core::mem::offset_of!(IpcSendMessage, payload),
            IPC_MESSAGE_HEADER_SIZE as usize
        );
        assert_eq!(size_of::<IpcReceiveMessage>(), 4176);
        assert_eq!(
            core::mem::offset_of!(IpcReceiveMessage, payload),
            IPC_MESSAGE_HEADER_SIZE as usize
        );
    }

    #[test]
    fn channel_pair_requires_canonical_distinct_descriptors() {
        assert!(IpcChannelPair::new(3, 4).is_valid());
        assert!(!IpcChannelPair::default().is_valid());
        assert!(!IpcChannelPair::new(3, 3).is_valid());

        let mut pair = IpcChannelPair::new(3, 4);
        pair.version += 1;
        assert!(!pair.is_valid());
        pair = IpcChannelPair::new(3, 4);
        pair.record_size -= 1;
        assert!(!pair.is_valid());
        pair = IpcChannelPair::new(3, 4);
        pair.flags = 1;
        assert!(!pair.is_valid());
    }

    #[test]
    fn send_record_enforces_all_bounds_and_canonical_tails() {
        let mut message = IpcSendMessage::empty();
        assert!(message.set_payload(b"hello"));
        message.transfer_count = 1;
        message.transfers[0] = IpcSendTransfer {
            source_fd: 7,
            rights: IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_MAP,
            tag: 0xCAFE,
        };
        assert!(message.is_valid());

        let canonical = message;
        message.version += 1;
        assert!(!message.is_valid());
        message = canonical;
        message.header_size -= 1;
        assert!(!message.is_valid());
        message = canonical;
        message.payload_length = IPC_MAX_MESSAGE_BYTES + 1;
        assert!(!message.is_valid());
        message = canonical;
        message.transfer_count = IPC_MAX_TRANSFERS + 1;
        assert!(!message.is_valid());
        message = canonical;
        message.flags = 1;
        assert!(!message.is_valid());
        message = canonical;
        message.reserved = 1;
        assert!(!message.is_valid());
        message = canonical;
        message.transfers[0].source_fd = -1;
        assert!(!message.is_valid());
        message = canonical;
        message.transfers[0].rights = 0;
        assert!(!message.is_valid());
        message = canonical;
        message.transfers[0].rights = IPC_TRANSFER_RIGHTS_ALL | (1 << 31);
        assert!(!message.is_valid());
        message = canonical;
        message.transfers[1].tag = 1;
        assert!(!message.is_valid());
        message = canonical;
        message.payload[5] = 1;
        assert!(!message.is_valid());

        let oversized = [0u8; IPC_MAX_MESSAGE_BYTES as usize + 1];
        assert!(!message.set_payload(&oversized));

        let mut maximum = IpcSendMessage::empty();
        assert!(maximum.set_payload(&[0xA5; IPC_MAX_MESSAGE_BYTES as usize]));
        maximum.transfer_count = IPC_MAX_TRANSFERS;
        for (index, transfer) in maximum.transfers.iter_mut().enumerate() {
            *transfer = IpcSendTransfer {
                source_fd: index as i32,
                rights: IPC_TRANSFER_RIGHTS_ALL,
                tag: index as u64,
            };
        }
        assert!(maximum.is_valid());
    }

    #[test]
    fn receive_record_has_direction_specific_descriptor_semantics() {
        let mut message = IpcReceiveMessage::empty();
        message.payload_length = 1;
        message.payload[0] = 0x7F;
        message.transfer_count = 1;
        message.transfers[0] = IpcReceiveTransfer {
            installed_fd: 12,
            rights: IPC_TRANSFER_RIGHT_READ,
            tag: 99,
        };
        assert!(message.is_valid());

        let canonical = message;
        message.transfers[0].installed_fd = -1;
        assert!(!message.is_valid());
        message = canonical;
        message.transfers[0].rights = IPC_TRANSFER_RIGHTS_ALL | (1 << 30);
        assert!(!message.is_valid());
        message = canonical;
        message.transfers[1].installed_fd = 1;
        assert!(!message.is_valid());
        message = canonical;
        message.payload[1] = 1;
        assert!(!message.is_valid());
    }
}
