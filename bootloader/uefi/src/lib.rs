//! Pure UEFI descriptor translation shared with host-side tests.

#![no_std]

use xenith_boot_common::BootMemoryKind;

pub const EFI_PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryDescriptor {
    pub memory_type: u32,
    pub padding: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

#[must_use]
pub const fn boot_memory_kind(memory_type: u32) -> BootMemoryKind {
    match memory_type {
        3 | 4 => BootMemoryKind::BootloaderReclaimable,
        7 => BootMemoryKind::Usable,
        8 => BootMemoryKind::BadMemory,
        9 => BootMemoryKind::AcpiReclaimable,
        10 => BootMemoryKind::AcpiNvs,
        _ => BootMemoryKind::Reserved,
    }
}

pub fn descriptor_length(descriptor: MemoryDescriptor) -> Option<u64> {
    descriptor.number_of_pages.checked_mul(EFI_PAGE_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_ownership_without_reclaiming_runtime_memory() {
        assert_eq!(boot_memory_kind(7), BootMemoryKind::Usable);
        assert_eq!(boot_memory_kind(3), BootMemoryKind::BootloaderReclaimable);
        assert_eq!(boot_memory_kind(5), BootMemoryKind::Reserved);
        assert_eq!(boot_memory_kind(10), BootMemoryKind::AcpiNvs);
    }

    #[test]
    fn catches_descriptor_length_overflow() {
        let descriptor = MemoryDescriptor {
            memory_type: 7,
            padding: 0,
            physical_start: 0,
            virtual_start: 0,
            number_of_pages: u64::MAX,
            attribute: 0,
        };
        assert_eq!(descriptor_length(descriptor), None);
    }
}
