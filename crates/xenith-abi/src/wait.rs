//! Fixed-width ABI for allocation-free multi-source waits.

use core::mem::{align_of, size_of};

pub const WAIT_ABI_VERSION: u16 = 1;
pub const WAIT_MAX_ITEMS: usize = 32;
pub const WAIT_TIMEOUT_INFINITE: u64 = u64::MAX;

/// Sentinel source used to wait for the caller's exclusive UI input seat.
pub const WAIT_SOURCE_UI: i32 = -1;

pub const WAIT_INTEREST_READABLE: u32 = 1 << 0;
pub const WAIT_INTEREST_WRITABLE: u32 = 1 << 1;
pub const WAIT_INTEREST_UI_INPUT: u32 = 1 << 2;
pub const WAIT_INTEREST_ALL: u32 =
    WAIT_INTEREST_READABLE | WAIT_INTEREST_WRITABLE | WAIT_INTEREST_UI_INPUT;

pub const WAIT_READY_READABLE: u32 = 1 << 0;
pub const WAIT_READY_WRITABLE: u32 = 1 << 1;
pub const WAIT_READY_UI_INPUT: u32 = 1 << 2;
/// The relevant peer or exclusive UI session has closed.
pub const WAIT_READY_HANGUP: u32 = 1 << 3;
pub const WAIT_READY_ALL: u32 =
    WAIT_READY_READABLE | WAIT_READY_WRITABLE | WAIT_READY_UI_INPUT | WAIT_READY_HANGUP;

pub const WAIT_ITEM_SIZE: u16 = size_of::<WaitItem>() as u16;

/// One in/out entry for `wait(items, count, timeout_ns, flags)`.
///
/// The caller supplies `version`, `record_size`, `source`, `interests`, and
/// an opaque `token`; `ready` and `reserved` must be zero. The kernel writes
/// the complete array back transactionally with `ready` populated and every
/// other field unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct WaitItem {
    pub version: u16,
    pub record_size: u16,
    pub source: i32,
    pub interests: u32,
    pub ready: u32,
    pub token: u64,
    pub reserved: u64,
}

impl WaitItem {
    #[must_use]
    pub const fn channel(source: i32, interests: u32, token: u64) -> Self {
        Self {
            version: WAIT_ABI_VERSION,
            record_size: WAIT_ITEM_SIZE,
            source,
            interests,
            ready: 0,
            token,
            reserved: 0,
        }
    }

    #[must_use]
    pub const fn ui_input(token: u64) -> Self {
        Self::channel(WAIT_SOURCE_UI, WAIT_INTEREST_UI_INPUT, token)
    }

    #[must_use]
    pub const fn is_canonical_input(&self) -> bool {
        if self.version != WAIT_ABI_VERSION
            || self.record_size != WAIT_ITEM_SIZE
            || self.interests == 0
            || self.interests & !WAIT_INTEREST_ALL != 0
            || self.ready != 0
            || self.reserved != 0
        {
            return false;
        }
        if self.source == WAIT_SOURCE_UI {
            self.interests == WAIT_INTEREST_UI_INPUT
        } else {
            self.source >= 0 && self.interests & WAIT_INTEREST_UI_INPUT == 0
        }
    }

    #[must_use]
    pub const fn is_canonical_output(&self) -> bool {
        self.version == WAIT_ABI_VERSION
            && self.record_size == WAIT_ITEM_SIZE
            && self.reserved == 0
            && self.ready & !WAIT_READY_ALL == 0
            && if self.source == WAIT_SOURCE_UI {
                self.interests == WAIT_INTEREST_UI_INPUT
                    && self.ready & !(WAIT_READY_UI_INPUT | WAIT_READY_HANGUP) == 0
            } else {
                self.source >= 0
                    && self.interests != 0
                    && self.interests & !(WAIT_INTEREST_READABLE | WAIT_INTEREST_WRITABLE) == 0
                    && self.ready & !(WAIT_READY_READABLE | WAIT_READY_WRITABLE | WAIT_READY_HANGUP)
                        == 0
                    && (self.ready & WAIT_READY_READABLE == 0
                        || self.interests & WAIT_INTEREST_READABLE != 0)
                    && (self.ready & WAIT_READY_WRITABLE == 0
                        || self.interests & WAIT_INTEREST_WRITABLE != 0)
            }
    }
}

impl Default for WaitItem {
    fn default() -> Self {
        Self::channel(-2, 0, 0)
    }
}

const _: [(); 32] = [(); size_of::<WaitItem>()];
const _: [(); 8] = [(); align_of::<WaitItem>()];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_item_layout_and_sources_are_stable() {
        assert_eq!(size_of::<WaitItem>(), 32);
        assert_eq!(align_of::<WaitItem>(), 8);
        assert_eq!(core::mem::offset_of!(WaitItem, source), 4);
        assert_eq!(core::mem::offset_of!(WaitItem, interests), 8);
        assert_eq!(core::mem::offset_of!(WaitItem, token), 16);
        assert!(WaitItem::channel(3, WAIT_INTEREST_READABLE, 7).is_canonical_input());
        assert!(WaitItem::ui_input(9).is_canonical_input());
        assert!(!WaitItem::default().is_canonical_input());
    }

    #[test]
    fn input_and_output_masks_are_direction_specific() {
        let mut channel = WaitItem::channel(4, WAIT_INTEREST_READABLE | WAIT_INTEREST_WRITABLE, 11);
        channel.ready = WAIT_READY_READABLE | WAIT_READY_HANGUP;
        assert!(channel.is_canonical_output());
        channel.ready |= WAIT_READY_UI_INPUT;
        assert!(!channel.is_canonical_output());

        let mut ui = WaitItem::ui_input(12);
        ui.ready = WAIT_READY_UI_INPUT;
        assert!(ui.is_canonical_output());
        ui.interests |= WAIT_INTEREST_READABLE;
        assert!(!ui.is_canonical_output());
    }
}
