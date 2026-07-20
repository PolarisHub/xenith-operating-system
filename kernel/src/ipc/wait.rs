//! Allocation-free readiness wait across bounded channel and UI sources.

use alloc::sync::Arc;
use core::array;

use xenith_abi::wait::{
    WaitItem, WAIT_ABI_VERSION, WAIT_INTEREST_READABLE, WAIT_INTEREST_WRITABLE, WAIT_ITEM_SIZE,
    WAIT_MAX_ITEMS, WAIT_SOURCE_UI, WAIT_TIMEOUT_INFINITE,
};

use crate::fs::fd::FileRef;
use crate::fs::syscalls as fs;
use crate::sched::TaskId;
use crate::syscall::{Errno, SyscallContext};
use crate::time::{Duration, Instant};
use crate::user::ProcessId;

const ITEM_BYTES: usize = WAIT_ITEM_SIZE as usize;
const MAX_WIRE_BYTES: usize = WAIT_MAX_ITEMS * ITEM_BYTES;

pub fn sys_wait(context: &SyscallContext) -> i64 {
    if context.arg(3) != 0 {
        return Errno::Einval.as_ret();
    }
    let count = match usize::try_from(context.arg(1)) {
        Ok(count @ 1..=WAIT_MAX_ITEMS) => count,
        _ => return Errno::Einval.as_ret(),
    };
    let byte_length = count * ITEM_BYTES;
    // Resolve COW before the read snapshot so both capabilities refer to the
    // same final mappings for the duration of this one-thread process call.
    let Some(output) =
        crate::arch::x86_64::usercopy::prepare_user_write(context.arg(0), byte_length)
    else {
        return Errno::Efault.as_ret();
    };
    let Some(input) = crate::arch::x86_64::usercopy::prepare_user_read(context.arg(0), byte_length)
    else {
        return Errno::Efault.as_ret();
    };

    let mut wire = [0u8; MAX_WIRE_BYTES];
    if !input.copy_to_kernel(0, &mut wire[..byte_length]) {
        return Errno::Efault.as_ret();
    }
    let mut items = [WaitItem::default(); WAIT_MAX_ITEMS];
    for (index, item) in items[..count].iter_mut().enumerate() {
        *item = decode_item(&wire[index * ITEM_BYTES..(index + 1) * ITEM_BYTES]);
        if !item.is_canonical_input() {
            return Errno::Einval.as_ret();
        }
    }

    let pid = match crate::user::process::try_current_pid() {
        Some(pid) => pid,
        None => return Errno::Esrch.as_ret(),
    };
    let task = match crate::sched::scheduler::with_current_node(|node| node.task.id) {
        Some(task) => task,
        None => return Errno::Esrch.as_ret(),
    };
    let mut files: [Option<FileRef>; WAIT_MAX_ITEMS] = array::from_fn(|_| None);
    let mut saw_ui = false;
    for index in 0..count {
        let item = items[index];
        if item.source == WAIT_SOURCE_UI {
            if saw_ui || !crate::ui::is_owner(pid) {
                return if saw_ui {
                    Errno::Einval.as_ret()
                } else {
                    Errno::Eacces.as_ret()
                };
            }
            saw_ui = true;
            continue;
        }
        if items[..index]
            .iter()
            .any(|previous| previous.source == item.source)
        {
            return Errno::Einval.as_ret();
        }
        let mut required = 0;
        if item.interests & WAIT_INTEREST_READABLE != 0 {
            required |= xenith_abi::ipc::IPC_TRANSFER_RIGHT_READ;
        }
        if item.interests & WAIT_INTEREST_WRITABLE != 0 {
            required |= xenith_abi::ipc::IPC_TRANSFER_RIGHT_WRITE;
        }
        let file = match fs::get_channel(item.source, required) {
            Ok(file) => file,
            Err(error) => return Errno::from(error).as_ret(),
        };
        if files[..index]
            .iter()
            .flatten()
            .any(|previous| Arc::ptr_eq(previous, &file))
        {
            return Errno::Einval.as_ret();
        }
        files[index] = Some(file);
    }

    let timeout_ns = context.arg(2);
    let nonblocking = timeout_ns == 0;
    let deadline = (timeout_ns != WAIT_TIMEOUT_INFINITE)
        .then(|| Instant::now() + Duration::from_nanos(timeout_ns));
    loop {
        let ready = poll_sources(&mut items[..count], &files, pid);
        if ready != 0 || nonblocking {
            return publish(&items[..count], &mut wire, &output)
                .map_or_else(Errno::as_ret, |()| ready as i64);
        }
        if current_interrupted() {
            return Errno::Eintr.as_ret();
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return publish(&items[..count], &mut wire, &output).map_or_else(Errno::as_ret, |()| 0);
        }

        match arm_sources(&mut items[..count], &files, pid, task) {
            Ok(0) => crate::sched::scheduler::block_current_interruptible(deadline),
            Ok(_) => {},
            Err(error) => {
                disarm_sources(&items[..count], &files, task);
                return error.as_ret();
            },
        }
        disarm_sources(&items[..count], &files, task);
    }
}

fn poll_sources(items: &mut [WaitItem], files: &[Option<FileRef>], pid: ProcessId) -> usize {
    let mut count = 0;
    for (index, item) in items.iter_mut().enumerate() {
        item.ready = if item.source == WAIT_SOURCE_UI {
            crate::ui::wait_ready(pid)
        } else {
            files[index]
                .as_ref()
                .and_then(|file| file.channel_endpoint())
                .map_or(0, |endpoint| endpoint.poll_ready(item.interests))
        };
        count += usize::from(item.ready != 0);
    }
    count
}

fn arm_sources(
    items: &mut [WaitItem],
    files: &[Option<FileRef>],
    pid: ProcessId,
    task: TaskId,
) -> Result<usize, Errno> {
    let mut ready = 0;
    for (index, item) in items.iter_mut().enumerate() {
        item.ready = if item.source == WAIT_SOURCE_UI {
            crate::ui::arm_external_wait(pid, task).map_err(ui_errno)?
        } else {
            files[index]
                .as_ref()
                .and_then(|file| file.channel_endpoint())
                .ok_or(Errno::Ebadf)?
                .arm_wait(task, item.interests)
                .map_err(super::syscall::channel_errno)?
        };
        ready += usize::from(item.ready != 0);
    }
    Ok(ready)
}

fn disarm_sources(items: &[WaitItem], files: &[Option<FileRef>], task: TaskId) {
    for (index, item) in items.iter().enumerate() {
        if item.source == WAIT_SOURCE_UI {
            crate::ui::disarm_external_wait(task);
        } else if let Some(endpoint) = files[index]
            .as_ref()
            .and_then(|file| file.channel_endpoint())
        {
            endpoint.disarm_wait(task, item.interests);
        }
    }
}

fn publish(
    items: &[WaitItem],
    wire: &mut [u8; MAX_WIRE_BYTES],
    output: &crate::arch::x86_64::usercopy::PreparedUserWrite,
) -> Result<(), Errno> {
    for (index, item) in items.iter().enumerate() {
        encode_item(
            item,
            &mut wire[index * ITEM_BYTES..(index + 1) * ITEM_BYTES],
        );
    }
    output
        .copy_from_kernel(&wire[..items.len() * ITEM_BYTES])
        .then_some(())
        .ok_or(Errno::Efault)
}

fn decode_item(bytes: &[u8]) -> WaitItem {
    WaitItem {
        version: u16::from_le_bytes([bytes[0], bytes[1]]),
        record_size: u16::from_le_bytes([bytes[2], bytes[3]]),
        source: i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        interests: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        ready: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        token: u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        reserved: u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
    }
}

fn encode_item(item: &WaitItem, bytes: &mut [u8]) {
    bytes.fill(0);
    bytes[0..2].copy_from_slice(&WAIT_ABI_VERSION.to_le_bytes());
    bytes[2..4].copy_from_slice(&WAIT_ITEM_SIZE.to_le_bytes());
    bytes[4..8].copy_from_slice(&item.source.to_le_bytes());
    bytes[8..12].copy_from_slice(&item.interests.to_le_bytes());
    bytes[12..16].copy_from_slice(&item.ready.to_le_bytes());
    bytes[16..24].copy_from_slice(&item.token.to_le_bytes());
}

fn current_interrupted() -> bool {
    crate::user::process::with_current_process(|process| {
        process.signals.has_interrupting_delivery()
    })
    .unwrap_or(false)
}

fn ui_errno(error: crate::ui::UiError) -> Errno {
    match error {
        crate::ui::UiError::Busy => Errno::Ebusy,
        crate::ui::UiError::NotOwner => Errno::Eacces,
        crate::ui::UiError::Interrupted => Errno::Eintr,
        crate::ui::UiError::NoCurrentTask => Errno::Esrch,
        crate::ui::UiError::Fault => Errno::Efault,
        crate::ui::UiError::NoDisplay => Errno::Enodev,
        crate::ui::UiError::InvalidArgument => Errno::Einval,
    }
}

#[cfg(test)]
mod tests {
    use xenith_abi::wait::{WAIT_READY_HANGUP, WAIT_READY_READABLE, WAIT_READY_UI_INPUT};

    use super::*;

    #[test]
    fn manual_codec_round_trips_without_padding_or_native_layout_access() {
        let mut item = WaitItem::channel(
            7,
            WAIT_INTEREST_READABLE | WAIT_INTEREST_WRITABLE,
            0x1122_3344_5566_7788,
        );
        item.ready = WAIT_READY_READABLE | WAIT_READY_HANGUP;
        let mut bytes = [0xA5; ITEM_BYTES];
        encode_item(&item, &mut bytes);
        assert_eq!(decode_item(&bytes), item);
        assert_eq!(&bytes[24..32], &[0; 8]);
    }

    #[test]
    fn ui_codec_uses_only_ui_readiness_bits() {
        let mut item = WaitItem::ui_input(9);
        item.ready = WAIT_READY_UI_INPUT;
        let mut bytes = [0u8; ITEM_BYTES];
        encode_item(&item, &mut bytes);
        assert!(decode_item(&bytes).is_canonical_output());
    }
}
