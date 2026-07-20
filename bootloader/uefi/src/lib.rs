//! Pure UEFI descriptor translation shared with host-side tests.

#![no_std]

use xenith_boot_common::{BootMemoryKind, XenithFramebuffer, XenithMemoryRegion};

pub mod splash;

pub const EFI_PAGE_SIZE: u64 = 4096;
pub const UEFI_COMMAND_LINE: &[u8] = b"xenith.boot=uefi";
pub const UEFI_SPLASH_COMMAND_LINE: &[u8] = b"xenith.boot=uefi xenith.splash=1";

/// Validate one GOP mode and translate it into Xenith's native framebuffer
/// descriptor. `pixel_masks` is used only for GOP's bit-mask format (`2`).
#[must_use]
pub fn gop_framebuffer(
    address: u64,
    available_bytes: usize,
    width: u32,
    height: u32,
    pixels_per_scan_line: u32,
    pixel_format: u32,
    pixel_masks: [u32; 3],
) -> Option<XenithFramebuffer> {
    if address == 0 || !address.is_multiple_of(4) || width == 0 || height == 0 {
        return None;
    }
    let pitch = pixels_per_scan_line.checked_mul(4)?;
    let visible_row_bytes = width.checked_mul(4)?;
    if pitch < visible_row_bytes || !pitch.is_multiple_of(4) {
        return None;
    }
    let required = usize::try_from(pitch).ok()?.checked_mul(height as usize)?;
    if required > available_bytes || address.checked_add(required as u64).is_none() {
        return None;
    }

    let channels = match pixel_format {
        // PixelRedGreenBlueReserved8BitPerColor: bytes R, G, B, X.
        0 => (0, 8, 8, 8, 16, 8),
        // PixelBlueGreenRedReserved8BitPerColor: bytes B, G, R, X.
        1 => (16, 8, 8, 8, 0, 8),
        2 => {
            let red = contiguous_channel(pixel_masks[0])?;
            let green = contiguous_channel(pixel_masks[1])?;
            let blue = contiguous_channel(pixel_masks[2])?;
            if pixel_masks[0] & pixel_masks[1] != 0
                || pixel_masks[0] & pixel_masks[2] != 0
                || pixel_masks[1] & pixel_masks[2] != 0
            {
                return None;
            }
            (red.0, red.1, green.0, green.1, blue.0, blue.1)
        },
        // PixelBltOnly and unknown future formats expose no linear scanout.
        _ => return None,
    };

    Some(XenithFramebuffer {
        address,
        pitch,
        width,
        height,
        bpp: 32,
        red_shift: channels.0,
        red_size: channels.1,
        green_shift: channels.2,
        green_size: channels.3,
        blue_shift: channels.4,
        blue_size: channels.5,
    })
}

fn contiguous_channel(mask: u32) -> Option<(u8, u8)> {
    if mask == 0 {
        return None;
    }
    let shift = mask.trailing_zeros() as u8;
    let shifted = mask >> shift;
    if shifted & shifted.wrapping_add(1) != 0 {
        return None;
    }
    Some((shift, mask.count_ones() as u8))
}

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

    #[test]
    fn gop_framebuffer_preserves_rgb_and_bgr_layouts() {
        let rgb = gop_framebuffer(0x8000_0000, 800 * 600 * 4, 800, 600, 800, 0, [0; 3])
            .expect("RGB GOP mode");
        assert_eq!((rgb.red_shift, rgb.green_shift, rgb.blue_shift), (0, 8, 16));
        let bgr = gop_framebuffer(0x8000_0000, 800 * 600 * 4, 800, 600, 800, 1, [0; 3])
            .expect("BGR GOP mode");
        assert_eq!((bgr.red_shift, bgr.green_shift, bgr.blue_shift), (16, 8, 0));
    }

    #[test]
    fn gop_framebuffer_validates_masks_pitch_and_aperture_size() {
        let rgb565 = gop_framebuffer(0x8000_0000, 1024 * 768 * 4, 1024, 768, 1024, 2, [
            0x0000_f800,
            0x0000_07e0,
            0x0000_001f,
        ])
        .expect("contiguous RGB masks");
        assert_eq!(
            (rgb565.red_size, rgb565.green_size, rgb565.blue_size),
            (5, 6, 5)
        );
        assert!(
            gop_framebuffer(0x8000_0000, 1024 * 768 * 4 - 1, 1024, 768, 1024, 1, [0; 3],).is_none()
        );
        assert!(
            gop_framebuffer(0x8000_0000, 1024 * 768 * 4, 1024, 768, 1024, 2, [
                0x0000_00f5,
                0x0000_ff00,
                0x00ff_0000
            ],)
            .is_none()
        );
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
