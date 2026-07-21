//! Stable native/archive names for the Windows compatibility namespace.

/// Native VFS mount beneath which Windows drive directories are exposed.
pub const WINDOWS_NATIVE_ROOT: &str = "/win";

/// Top-level initramfs entry routed into [`WINDOWS_NATIVE_ROOT`].
pub const WINDOWS_INITRAMFS_ROOT: &str = "win";

/// Windows system drive visible to compatibility guests.
pub const WINDOWS_SYSTEM_DRIVE: &str = "C:";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_and_native_roots_are_one_stable_component() {
        assert_eq!(WINDOWS_NATIVE_ROOT, "/win");
        assert_eq!(WINDOWS_INITRAMFS_ROOT, "win");
        assert_eq!(
            WINDOWS_NATIVE_ROOT.strip_prefix('/'),
            Some(WINDOWS_INITRAMFS_ROOT)
        );
        assert!(!WINDOWS_INITRAMFS_ROOT.contains('/'));
        assert_eq!(WINDOWS_SYSTEM_DRIVE, "C:");
    }
}
