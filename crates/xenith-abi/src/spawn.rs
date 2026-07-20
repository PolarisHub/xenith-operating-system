//! Versioned restricted-spawn descriptor inheritance records.
//!
//! A restricted child starts with an empty descriptor table. Each active
//! action names one source descriptor in the parent, one exact target number
//! in the child, and a nonempty attenuation of the source rights. Unused
//! action slots and every reserved field must be zero so accepted records have
//! one canonical byte representation.

use crate::ipc::IPC_TRANSFER_RIGHTS_ALL;

/// Wire ABI version accepted by `spawn_restricted`.
pub const SPAWN_RESTRICTED_ABI_VERSION: u16 = 1;
/// Maximum descriptor mappings carried by one atomic restricted spawn.
pub const SPAWN_RESTRICTED_MAX_FILE_ACTIONS: usize = 16;
/// Fixed header width before [`SpawnRestrictedRequest::file_actions`].
pub const SPAWN_RESTRICTED_HEADER_SIZE: u16 = 32;
/// Fixed width of one [`SpawnFileAction`].
pub const SPAWN_FILE_ACTION_SIZE: u16 = 16;
/// Total fixed width of [`SpawnRestrictedRequest`].
pub const SPAWN_RESTRICTED_REQUEST_SIZE: u32 = 288;

/// Map one parent descriptor to one exact child descriptor number.
///
/// `rights` must be nonzero, contain only `IPC_TRANSFER_RIGHT_*` bits, and be
/// a subset of the source descriptor's current rights. `flags` is reserved
/// and must be zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct SpawnFileAction {
    pub source_fd: i32,
    pub target_fd: i32,
    pub rights: u32,
    pub flags: u32,
}

impl SpawnFileAction {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.source_fd >= 0
            && self.target_fd >= 0
            && self.rights != 0
            && self.rights & !IPC_TRANSFER_RIGHTS_ALL == 0
            && self.flags == 0
    }

    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.source_fd == 0 && self.target_fd == 0 && self.rights == 0 && self.flags == 0
    }
}

/// Canonical fixed-width request consumed by `spawn_restricted`.
///
/// `process_group` uses the ordinary spawn encoding: zero inherits the
/// caller's group, `u64::MAX` creates a child-led group, and another value
/// joins an existing group in the caller's session. Request and action flags
/// are reserved and must be zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SpawnRestrictedRequest {
    pub version: u16,
    pub header_size: u16,
    pub record_size: u32,
    pub flags: u32,
    pub file_action_count: u16,
    pub file_action_size: u16,
    pub process_group: u64,
    pub reserved: u64,
    pub file_actions: [SpawnFileAction; SPAWN_RESTRICTED_MAX_FILE_ACTIONS],
}

impl SpawnRestrictedRequest {
    #[must_use]
    pub const fn new(process_group: u64) -> Self {
        Self {
            version: SPAWN_RESTRICTED_ABI_VERSION,
            header_size: SPAWN_RESTRICTED_HEADER_SIZE,
            record_size: SPAWN_RESTRICTED_REQUEST_SIZE,
            flags: 0,
            file_action_count: 0,
            file_action_size: SPAWN_FILE_ACTION_SIZE,
            process_group,
            reserved: 0,
            file_actions: [SpawnFileAction {
                source_fd: 0,
                target_fd: 0,
                rights: 0,
                flags: 0,
            }; SPAWN_RESTRICTED_MAX_FILE_ACTIONS],
        }
    }

    /// Validate header fields, active actions, zero tail, and target
    /// uniqueness without consulting a descriptor table.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        if self.version != SPAWN_RESTRICTED_ABI_VERSION
            || self.header_size != SPAWN_RESTRICTED_HEADER_SIZE
            || self.record_size != SPAWN_RESTRICTED_REQUEST_SIZE
            || self.flags != 0
            || self.file_action_size != SPAWN_FILE_ACTION_SIZE
            || usize::from(self.file_action_count) > SPAWN_RESTRICTED_MAX_FILE_ACTIONS
            || self.reserved != 0
        {
            return false;
        }

        let active = usize::from(self.file_action_count);
        for index in 0..SPAWN_RESTRICTED_MAX_FILE_ACTIONS {
            let action = &self.file_actions[index];
            if index < active {
                if !action.is_valid() {
                    return false;
                }
                for previous in &self.file_actions[..index] {
                    if previous.target_fd == action.target_fd {
                        return false;
                    }
                }
            } else if !action.is_zero() {
                return false;
            }
        }
        true
    }
}

impl Default for SpawnRestrictedRequest {
    fn default() -> Self {
        Self::new(crate::syscall::SPAWN_GROUP_INHERIT)
    }
}

const _: () = assert!(core::mem::size_of::<SpawnFileAction>() == SPAWN_FILE_ACTION_SIZE as usize);
const _: () = assert!(
    core::mem::size_of::<SpawnRestrictedRequest>() == SPAWN_RESTRICTED_REQUEST_SIZE as usize
);
const _: () = assert!(
    core::mem::offset_of!(SpawnRestrictedRequest, file_actions)
        == SPAWN_RESTRICTED_HEADER_SIZE as usize
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IPC_TRANSFER_RIGHT_READ, IPC_TRANSFER_RIGHT_WRITE};

    fn one_action() -> SpawnRestrictedRequest {
        let mut file_actions = [SpawnFileAction::default(); SPAWN_RESTRICTED_MAX_FILE_ACTIONS];
        file_actions[0] = SpawnFileAction {
            source_fd: 7,
            target_fd: 1,
            rights: IPC_TRANSFER_RIGHT_WRITE,
            flags: 0,
        };
        SpawnRestrictedRequest {
            file_action_count: 1,
            file_actions,
            ..SpawnRestrictedRequest::default()
        }
    }

    #[test]
    fn restricted_spawn_layout_is_exact() {
        assert_eq!(core::mem::size_of::<SpawnFileAction>(), 16);
        assert_eq!(core::mem::align_of::<SpawnFileAction>(), 4);
        assert_eq!(core::mem::offset_of!(SpawnFileAction, source_fd), 0);
        assert_eq!(core::mem::offset_of!(SpawnFileAction, target_fd), 4);
        assert_eq!(core::mem::offset_of!(SpawnFileAction, rights), 8);
        assert_eq!(core::mem::offset_of!(SpawnFileAction, flags), 12);

        assert_eq!(core::mem::size_of::<SpawnRestrictedRequest>(), 288);
        assert_eq!(core::mem::align_of::<SpawnRestrictedRequest>(), 8);
        assert_eq!(core::mem::offset_of!(SpawnRestrictedRequest, version), 0);
        assert_eq!(
            core::mem::offset_of!(SpawnRestrictedRequest, header_size),
            2
        );
        assert_eq!(
            core::mem::offset_of!(SpawnRestrictedRequest, record_size),
            4
        );
        assert_eq!(core::mem::offset_of!(SpawnRestrictedRequest, flags), 8);
        assert_eq!(
            core::mem::offset_of!(SpawnRestrictedRequest, file_action_count),
            12
        );
        assert_eq!(
            core::mem::offset_of!(SpawnRestrictedRequest, file_action_size),
            14
        );
        assert_eq!(
            core::mem::offset_of!(SpawnRestrictedRequest, process_group),
            16
        );
        assert_eq!(core::mem::offset_of!(SpawnRestrictedRequest, reserved), 24);
        assert_eq!(
            core::mem::offset_of!(SpawnRestrictedRequest, file_actions),
            32
        );
    }

    #[test]
    fn canonical_request_rejects_every_ambiguous_shape() {
        assert!(one_action().is_canonical());

        let mut request = one_action();
        request.version += 1;
        assert!(!request.is_canonical());
        let mut request = one_action();
        request.header_size += 1;
        assert!(!request.is_canonical());
        let mut request = one_action();
        request.record_size += 1;
        assert!(!request.is_canonical());
        let mut request = one_action();
        request.file_action_size += 1;
        assert!(!request.is_canonical());
        let mut request = one_action();
        request.flags = 1;
        assert!(!request.is_canonical());
        let mut request = one_action();
        request.reserved = 1;
        assert!(!request.is_canonical());
        let mut request = one_action();
        request.file_action_count = SPAWN_RESTRICTED_MAX_FILE_ACTIONS as u16 + 1;
        assert!(!request.is_canonical());
        let mut request = one_action();
        request.file_actions[0].rights = 0;
        assert!(!request.is_canonical());
        let mut request = one_action();
        request.file_actions[0].flags = 1;
        assert!(!request.is_canonical());
        let mut request = one_action();
        request.file_actions[1] = SpawnFileAction {
            source_fd: 8,
            target_fd: 2,
            rights: IPC_TRANSFER_RIGHT_READ,
            flags: 0,
        };
        assert!(!request.is_canonical());
    }

    #[test]
    fn duplicate_targets_are_rejected_but_duplicate_sources_are_allowed() {
        let mut request = one_action();
        request.file_action_count = 2;
        request.file_actions[1] = SpawnFileAction {
            source_fd: request.file_actions[0].source_fd,
            target_fd: 2,
            rights: IPC_TRANSFER_RIGHT_READ,
            flags: 0,
        };
        assert!(request.is_canonical());

        request.file_actions[1].target_fd = request.file_actions[0].target_fd;
        assert!(!request.is_canonical());
    }
}
