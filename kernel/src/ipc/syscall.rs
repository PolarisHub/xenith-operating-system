//! Transactional syscall adapters for bounded channels and shared memory.
//!
//! Large wire records are never instantiated on the kernel stack. The
//! fixed 80-byte metadata prefix is decoded explicitly, while the 4096-byte
//! payload moves directly between prepared user memory and a preallocated
//! channel queue slot.

use core::array;

use xenith_abi::ipc::{
    IpcReceiveTransfer, IpcSendTransfer, IPC_ABI_VERSION, IPC_MAX_MESSAGE_BYTES, IPC_MAX_TRANSFERS,
    IPC_MESSAGE_HEADER_SIZE, IPC_TIMEOUT_INFINITE, IPC_TRANSFER_RIGHTS_ALL,
    IPC_TRANSFER_RIGHT_READ, IPC_TRANSFER_RIGHT_WRITE,
};

use super::channel::{self, ChannelError, CHANNEL_TRANSFER_CAPACITY};
use super::shared_memory::{SharedMemoryError, SharedMemoryObject};
use crate::arch::x86_64::usercopy::{prepare_user_read, prepare_user_write};
use crate::fs::syscalls as fs;
use crate::syscall::{Errno, SyscallContext};
use crate::time::{Duration, Instant};

const HEADER_BYTES: usize = IPC_MESSAGE_HEADER_SIZE as usize;
const MESSAGE_BYTES: usize = HEADER_BYTES + IPC_MAX_MESSAGE_BYTES as usize;
const TRANSFER_OFFSET: usize = 16;
const TRANSFER_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SendHeader {
    payload_length: usize,
    transfer_count: usize,
    transfers: [IpcSendTransfer; CHANNEL_TRANSFER_CAPACITY],
}

fn parse_send_header(bytes: &[u8; HEADER_BYTES]) -> Result<SendHeader, Errno> {
    let version = read_u16(bytes, 0);
    let header_size = read_u16(bytes, 2);
    let payload_length = read_u32(bytes, 4);
    let transfer_count = read_u16(bytes, 8);
    let flags = read_u16(bytes, 10);
    let reserved = read_u32(bytes, 12);
    if version != IPC_ABI_VERSION
        || header_size != IPC_MESSAGE_HEADER_SIZE
        || payload_length > IPC_MAX_MESSAGE_BYTES
        || transfer_count > IPC_MAX_TRANSFERS
        || flags != 0
        || reserved != 0
    {
        return Err(Errno::Einval);
    }

    let active = usize::from(transfer_count);
    let mut transfers = [IpcSendTransfer::default(); CHANNEL_TRANSFER_CAPACITY];
    for (index, output) in transfers.iter_mut().enumerate() {
        let offset = TRANSFER_OFFSET + index * TRANSFER_BYTES;
        let transfer = IpcSendTransfer {
            source_fd: read_i32(bytes, offset),
            rights: read_u32(bytes, offset + 4),
            tag: read_u64(bytes, offset + 8),
        };
        if index < active {
            if transfer.source_fd < 0
                || transfer.rights == 0
                || transfer.rights & !IPC_TRANSFER_RIGHTS_ALL != 0
            {
                return Err(Errno::Einval);
            }
            *output = transfer;
        } else if transfer.source_fd != 0 || transfer.rights != 0 || transfer.tag != 0 {
            return Err(Errno::Einval);
        }
    }

    Ok(SendHeader {
        payload_length: payload_length as usize,
        transfer_count: active,
        transfers,
    })
}

fn encode_receive_header(
    payload_length: usize,
    transfers: &[Option<IpcReceiveTransfer>; CHANNEL_TRANSFER_CAPACITY],
) -> Result<[u8; HEADER_BYTES], Errno> {
    if payload_length > IPC_MAX_MESSAGE_BYTES as usize {
        return Err(Errno::Eio);
    }
    let transfer_count = transfers.iter().take_while(|slot| slot.is_some()).count();
    if transfers[transfer_count..].iter().any(Option::is_some) {
        return Err(Errno::Eio);
    }

    let mut bytes = [0u8; HEADER_BYTES];
    write_u16(&mut bytes, 0, IPC_ABI_VERSION);
    write_u16(&mut bytes, 2, IPC_MESSAGE_HEADER_SIZE);
    write_u32(&mut bytes, 4, payload_length as u32);
    write_u16(&mut bytes, 8, transfer_count as u16);
    for (index, transfer) in transfers.iter().enumerate().take(transfer_count) {
        let transfer = transfer.ok_or(Errno::Eio)?;
        if transfer.installed_fd < 0
            || transfer.rights == 0
            || transfer.rights & !IPC_TRANSFER_RIGHTS_ALL != 0
        {
            return Err(Errno::Eio);
        }
        let offset = TRANSFER_OFFSET + index * TRANSFER_BYTES;
        write_i32(&mut bytes, offset, transfer.installed_fd);
        write_u32(&mut bytes, offset + 4, transfer.rights);
        write_u64(&mut bytes, offset + 8, transfer.tag);
    }
    Ok(bytes)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn channel_errno(error: ChannelError) -> Errno {
    match error {
        ChannelError::Fault => Errno::Efault,
        ChannelError::InvalidMessage => Errno::Einval,
        ChannelError::MessageTooLarge | ChannelError::TooManyTransfers => Errno::Emsgsize,
        ChannelError::WouldBlock | ChannelError::TimedOut => Errno::Eagain,
        ChannelError::BrokenPipe => Errno::Epipe,
        ChannelError::Interrupted => Errno::Eintr,
        ChannelError::Busy => Errno::Ebusy,
        ChannelError::NoCurrentTask => Errno::Esrch,
        ChannelError::StateCorrupt => Errno::Eio,
        ChannelError::ResourceExhausted => Errno::Enobufs,
    }
}

fn shared_memory_errno(error: SharedMemoryError) -> Errno {
    match error {
        SharedMemoryError::InvalidLength | SharedMemoryError::InvalidOffset => Errno::Einval,
        SharedMemoryError::QuotaExceeded | SharedMemoryError::OutOfMemory => Errno::Enomem,
    }
}

fn timeout(timeout_ns: u64) -> (bool, Option<Instant>) {
    (
        timeout_ns == 0,
        (timeout_ns != IPC_TIMEOUT_INFINITE)
            .then(|| Instant::now() + Duration::from_nanos(timeout_ns)),
    )
}

fn descriptor(raw: u64) -> Result<i32, Errno> {
    i32::try_from(raw).map_err(|_| Errno::Ebadf)
}

pub fn sys_channel_create(context: &SyscallContext) -> i64 {
    if context.arg(1) != 0 {
        return Errno::Einval.as_ret();
    }
    let Some(output) = prepare_user_write(context.arg(0), 16) else {
        return Errno::Efault.as_ret();
    };
    let (first, second) = match channel::create() {
        Ok(pair) => pair,
        Err(error) => return channel_errno(error).as_ret(),
    };
    let (first_fd, second_fd) = match fs::install_channel_pair(first, second) {
        Ok(pair) => pair,
        Err(error) => return Errno::from(error).as_ret(),
    };

    let mut pair = [0u8; 16];
    write_u16(&mut pair, 0, IPC_ABI_VERSION);
    write_u16(&mut pair, 2, 16);
    write_i32(&mut pair, 8, first_fd);
    write_i32(&mut pair, 12, second_fd);
    if !output.copy_from_kernel(&pair) {
        // Both descriptors were installed as one transaction. A late user
        // fault removes both before failure becomes observable.
        let _ = fs::sys_close(first_fd);
        let _ = fs::sys_close(second_fd);
        return Errno::Efault.as_ret();
    }
    0
}

pub fn sys_channel_send(context: &SyscallContext) -> i64 {
    if context.arg(3) != 0 {
        return Errno::Einval.as_ret();
    }
    let fd = match descriptor(context.arg(0)) {
        Ok(fd) => fd,
        Err(error) => return error.as_ret(),
    };
    let Some(message) = prepare_user_read(context.arg(1), MESSAGE_BYTES) else {
        return Errno::Efault.as_ret();
    };
    let mut prefix = [0u8; HEADER_BYTES];
    if !message.copy_to_kernel(0, &mut prefix) {
        return Errno::Efault.as_ret();
    }
    let header = match parse_send_header(&prefix) {
        Ok(header) => header,
        Err(error) => return error.as_ret(),
    };
    let transfers = match fs::snapshot_channel_transfers(&header.transfers, header.transfer_count) {
        Ok(transfers) => transfers,
        Err(error) => return Errno::from(error).as_ret(),
    };
    let file = match fs::get_channel(fd, IPC_TRANSFER_RIGHT_WRITE) {
        Ok(file) => file,
        Err(error) => return Errno::from(error).as_ret(),
    };
    let Some(endpoint) = file.channel_endpoint() else {
        return Errno::Ebadf.as_ret();
    };
    let (nonblocking, deadline) = timeout(context.arg(2));
    let result = endpoint.send_with(
        header.payload_length,
        transfers,
        nonblocking,
        deadline,
        |destination| {
            if !message.copy_to_kernel(HEADER_BYTES, destination) {
                return Err(ChannelError::Fault);
            }
            if destination[header.payload_length..]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(ChannelError::InvalidMessage);
            }
            Ok(())
        },
    );
    match result {
        Ok(()) => header.payload_length as i64,
        Err(error) => channel_errno(error).as_ret(),
    }
}

pub fn sys_channel_recv(context: &SyscallContext) -> i64 {
    if context.arg(3) != 0 {
        return Errno::Einval.as_ret();
    }
    let fd = match descriptor(context.arg(0)) {
        Ok(fd) => fd,
        Err(error) => return error.as_ret(),
    };
    let Some(message) = prepare_user_write(context.arg(1), MESSAGE_BYTES) else {
        return Errno::Efault.as_ret();
    };
    let file = match fs::get_channel(fd, IPC_TRANSFER_RIGHT_READ) {
        Ok(file) => file,
        Err(error) => return Errno::from(error).as_ret(),
    };
    let Some(endpoint) = file.channel_endpoint() else {
        return Errno::Ebadf.as_ret();
    };
    let (nonblocking, deadline) = timeout(context.arg(2));
    let pending = match endpoint.begin_receive(nonblocking, deadline) {
        Ok(pending) => pending,
        Err(error) => return channel_errno(error).as_ret(),
    };
    let payload_length = pending.length;

    let installed = match fs::install_channel_transfers(&pending.transfers) {
        Ok(installed) => installed,
        Err(error) => {
            let cancel = endpoint.cancel_receive(&pending);
            return cancel.map_or_else(
                |channel_error| channel_errno(channel_error).as_ret(),
                |()| Errno::from(error).as_ret(),
            );
        },
    };
    let mut receive_transfers = array::from_fn(|_| None);
    for (index, record) in installed
        .records()
        .iter()
        .copied()
        .enumerate()
        .take(installed.count())
    {
        receive_transfers[index] = Some(IpcReceiveTransfer {
            installed_fd: record.installed_fd,
            rights: record.rights,
            tag: record.tag,
        });
    }
    let prefix = match encode_receive_header(payload_length, &receive_transfers) {
        Ok(prefix) => prefix,
        Err(error) => {
            let retired = fs::rollback_channel_transfers(installed);
            let _ = endpoint.cancel_receive(&pending);
            drop(retired);
            return error.as_ret();
        },
    };
    if let Err(error) = endpoint.copy_receive_with(&pending, |source, _payload_length| {
        message
            .copy_from_kernel_at(HEADER_BYTES, source)
            .then_some(())
            .ok_or(ChannelError::Fault)
    }) {
        let retired = fs::rollback_channel_transfers(installed);
        let _ = endpoint.cancel_receive(&pending);
        drop(retired);
        return channel_errno(error).as_ret();
    }
    if !message.copy_from_kernel_at(0, &prefix) {
        let retired = fs::rollback_channel_transfers(installed);
        let _ = endpoint.cancel_receive(&pending);
        drop(retired);
        return Errno::Efault.as_ret();
    }
    if let Err(error) = endpoint.finish_receive(pending) {
        let retired = fs::rollback_channel_transfers(installed);
        drop(retired);
        return channel_errno(error).as_ret();
    }
    drop(installed);
    payload_length as i64
}

pub fn sys_shm_create(context: &SyscallContext) -> i64 {
    if context.arg(1) != 0 {
        return Errno::Einval.as_ret();
    }
    let object = match SharedMemoryObject::create(context.arg(0)) {
        Ok(object) => object,
        Err(error) => return shared_memory_errno(error).as_ret(),
    };
    match fs::install_shared_memory(object) {
        Ok(fd) => i64::from(fd),
        Err(error) => Errno::from(error).as_ret(),
    }
}

#[cfg(test)]
mod tests {
    use xenith_abi::ipc::{IPC_TRANSFER_RIGHT_MAP, IPC_TRANSFER_RIGHT_READ};

    use super::*;

    #[test]
    fn send_header_parser_rejects_every_noncanonical_field() {
        let mut header = [0u8; HEADER_BYTES];
        write_u16(&mut header, 0, IPC_ABI_VERSION);
        write_u16(&mut header, 2, IPC_MESSAGE_HEADER_SIZE);
        write_u32(&mut header, 4, 17);
        write_u16(&mut header, 8, 1);
        write_i32(&mut header, TRANSFER_OFFSET, 7);
        write_u32(
            &mut header,
            TRANSFER_OFFSET + 4,
            IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_MAP,
        );
        write_u64(&mut header, TRANSFER_OFFSET + 8, 0xABCD);
        let parsed = parse_send_header(&header).unwrap();
        assert_eq!(parsed.payload_length, 17);
        assert_eq!(parsed.transfers[0].source_fd, 7);

        let mut invalid = header;
        write_u16(&mut invalid, 0, IPC_ABI_VERSION + 1);
        assert_eq!(parse_send_header(&invalid), Err(Errno::Einval));
        let mut invalid = header;
        write_u16(&mut invalid, 2, IPC_MESSAGE_HEADER_SIZE - 1);
        assert_eq!(parse_send_header(&invalid), Err(Errno::Einval));
        let mut invalid = header;
        write_u32(&mut invalid, 4, IPC_MAX_MESSAGE_BYTES + 1);
        assert_eq!(parse_send_header(&invalid), Err(Errno::Einval));
        let mut invalid = header;
        write_u16(&mut invalid, 8, IPC_MAX_TRANSFERS + 1);
        assert_eq!(parse_send_header(&invalid), Err(Errno::Einval));
        let mut invalid = header;
        write_u16(&mut invalid, 10, 1);
        assert_eq!(parse_send_header(&invalid), Err(Errno::Einval));
        let mut invalid = header;
        write_u32(&mut invalid, 12, 1);
        assert_eq!(parse_send_header(&invalid), Err(Errno::Einval));
        let mut invalid = header;
        invalid[TRANSFER_OFFSET + TRANSFER_BYTES + 8] = 1;
        assert_eq!(parse_send_header(&invalid), Err(Errno::Einval));
        let mut invalid = header;
        write_i32(&mut invalid, TRANSFER_OFFSET, -1);
        assert_eq!(parse_send_header(&invalid), Err(Errno::Einval));
        let mut invalid = header;
        write_u32(&mut invalid, TRANSFER_OFFSET + 4, 0);
        assert_eq!(parse_send_header(&invalid), Err(Errno::Einval));
    }

    #[test]
    fn receive_header_encoder_is_fixed_width_and_canonical() {
        let mut transfers = array::from_fn(|_| None);
        transfers[0] = Some(IpcReceiveTransfer {
            installed_fd: 9,
            rights: IPC_TRANSFER_RIGHT_READ,
            tag: 42,
        });
        let bytes = encode_receive_header(123, &transfers).unwrap();
        assert_eq!(read_u16(&bytes, 0), IPC_ABI_VERSION);
        assert_eq!(read_u16(&bytes, 2), IPC_MESSAGE_HEADER_SIZE);
        assert_eq!(read_u32(&bytes, 4), 123);
        assert_eq!(read_u16(&bytes, 8), 1);
        assert_eq!(read_i32(&bytes, TRANSFER_OFFSET), 9);
        assert_eq!(
            read_u32(&bytes, TRANSFER_OFFSET + 4),
            IPC_TRANSFER_RIGHT_READ
        );
        assert_eq!(read_u64(&bytes, TRANSFER_OFFSET + 8), 42);
        assert!(bytes[TRANSFER_OFFSET + TRANSFER_BYTES..]
            .iter()
            .all(|byte| *byte == 0));

        transfers[2] = transfers[0];
        assert_eq!(encode_receive_header(1, &transfers), Err(Errno::Eio));
        assert_eq!(
            encode_receive_header(
                IPC_MAX_MESSAGE_BYTES as usize + 1,
                &array::from_fn(|_| None)
            ),
            Err(Errno::Eio)
        );
    }

    #[test]
    fn wire_size_matches_the_public_record_without_large_stack_values() {
        assert_eq!(HEADER_BYTES, 80);
        assert_eq!(MESSAGE_BYTES, 4176);
        assert_eq!(CHANNEL_TRANSFER_CAPACITY, IPC_MAX_TRANSFERS as usize);
    }

    #[test]
    fn channel_errors_have_stable_syscall_mapping() {
        assert_eq!(channel_errno(ChannelError::Fault), Errno::Efault);
        assert_eq!(channel_errno(ChannelError::InvalidMessage), Errno::Einval);
        assert_eq!(channel_errno(ChannelError::WouldBlock), Errno::Eagain);
        assert_eq!(channel_errno(ChannelError::TimedOut), Errno::Eagain);
        assert_eq!(channel_errno(ChannelError::BrokenPipe), Errno::Epipe);
    }
}
