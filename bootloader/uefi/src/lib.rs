//! Pure UEFI descriptor translation shared with host-side tests.

#![no_std]

use xenith_boot_common::{BootMemoryKind, XenithMemoryRegion};

pub mod splash;

pub const EFI_PAGE_SIZE: u64 = 4096;
pub const UEFI_COMMAND_LINE: &[u8] = b"xenith.boot=uefi";
pub const UEFI_SPLASH_COMMAND_LINE: &[u8] = b"xenith.boot=uefi xenith.splash=1";

/// Select the exact handoff command line for the loader state that was
/// actually presented. A firmware without a compatible GOP surface must not
/// ask the kernel to preserve pixels that were never painted.
#[must_use]
pub const fn uefi_command_line(splash_active: bool) -> &'static [u8] {
    if splash_active {
        UEFI_SPLASH_COMMAND_LINE
    } else {
        UEFI_COMMAND_LINE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMapLayoutError {
    AddressOverflow { index: usize },
    Overlap { previous_end: u64, next_base: u64 },
}

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

/// Sort translated firmware regions by physical address and compact them in place.
///
/// UEFI does not require `GetMemoryMap` descriptors to arrive in address order.
/// The Xenith handoff does require a sorted, disjoint map so the kernel can
/// validate it before enabling the physical allocator. Empty descriptors are
/// discarded and adjacent descriptors with the same ownership kind are merged.
pub fn normalize_memory_regions(
    regions: &mut [XenithMemoryRegion],
) -> Result<usize, MemoryMapLayoutError> {
    for (index, region) in regions.iter().enumerate() {
        region
            .base
            .checked_add(region.length)
            .ok_or(MemoryMapLayoutError::AddressOverflow { index })?;
    }

    // The firmware map is small and this no-allocator insertion sort keeps the
    // loader usable in its `no_std` environment.
    for index in 1..regions.len() {
        let mut cursor = index;
        while cursor != 0 && regions[cursor].base < regions[cursor - 1].base {
            regions.swap(cursor, cursor - 1);
            cursor -= 1;
        }
    }

    let mut used = 0;
    for index in 0..regions.len() {
        let region = regions[index];
        if region.length == 0 {
            continue;
        }
        let region_end = region
            .base
            .checked_add(region.length)
            .ok_or(MemoryMapLayoutError::AddressOverflow { index })?;
        if used != 0 {
            let previous = regions[used - 1];
            let previous_end = previous
                .base
                .checked_add(previous.length)
                .ok_or(MemoryMapLayoutError::AddressOverflow { index: used - 1 })?;
            if region.base < previous_end {
                return Err(MemoryMapLayoutError::Overlap {
                    previous_end,
                    next_base: region.base,
                });
            }
            if region.base == previous_end && region.kind == previous.kind {
                regions[used - 1].length = region_end
                    .checked_sub(previous.base)
                    .ok_or(MemoryMapLayoutError::AddressOverflow { index })?;
                continue;
            }
        }
        regions[used] = region;
        used += 1;
    }
    Ok(used)
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

    #[test]
    fn command_line_advertises_only_a_successful_splash() {
        assert_eq!(uefi_command_line(false), b"xenith.boot=uefi");
        assert_eq!(uefi_command_line(true), b"xenith.boot=uefi xenith.splash=1");
    }

    const fn region(base: u64, length: u64, kind: BootMemoryKind) -> XenithMemoryRegion {
        XenithMemoryRegion {
            base,
            length,
            kind,
            reserved: 0,
        }
    }

    #[test]
    fn sorts_vmware_style_out_of_order_regions_and_coalesces_neighbors() {
        let mut regions = [
            region(0x0010_0000, 0x0010_0000, BootMemoryKind::Usable),
            region(0xf000_0000, 0x0100_0000, BootMemoryKind::Reserved),
            region(0, 0x0010_0000, BootMemoryKind::Reserved),
            region(0x0020_0000, 0x0010_0000, BootMemoryKind::Usable),
        ];

        let used = normalize_memory_regions(&mut regions).unwrap();

        assert_eq!(used, 3);
        assert_eq!(regions[0].base, 0);
        assert_eq!(regions[1].base, 0x0010_0000);
        assert_eq!(regions[1].length, 0x0020_0000);
        assert_eq!(regions[1].kind, BootMemoryKind::Usable);
        assert_eq!(regions[2].base, 0xf000_0000);
    }

    #[test]
    fn rejects_genuine_overlaps_after_sorting() {
        let mut regions = [
            region(0x3000, 0x1000, BootMemoryKind::Usable),
            region(0x1000, 0x2800, BootMemoryKind::Reserved),
        ];

        assert_eq!(
            normalize_memory_regions(&mut regions),
            Err(MemoryMapLayoutError::Overlap {
                previous_end: 0x3800,
                next_base: 0x3000,
            })
        );
    }

    #[test]
    fn rejects_region_address_overflow() {
        let mut regions = [region(u64::MAX - 0xfff, 0x1001, BootMemoryKind::Reserved)];

        assert_eq!(
            normalize_memory_regions(&mut regions),
            Err(MemoryMapLayoutError::AddressOverflow { index: 0 })
        );
    }
}
