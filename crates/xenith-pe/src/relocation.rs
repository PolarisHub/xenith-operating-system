use crate::{PeError, PeImage, IMAGE_DIRECTORY_ENTRY_BASERELOC};

/// Padding relocation kind; entries of this type are validated and ignored.
pub const RELOCATION_TYPE_ABSOLUTE: u8 = 0;
/// AMD64 64-bit virtual-address relocation kind.
pub const RELOCATION_TYPE_DIR64: u8 = 10;
/// Maximum effective DIR64 patches accepted from one image.
pub const MAX_BASE_RELOCATIONS: usize = 65_536;

const RELOCATION_BLOCK_HEADER_SIZE: usize = 8;
const RELOCATION_ENTRY_SIZE: usize = 2;
const RELOCATION_PAGE_SIZE: u32 = 0x1000;
const IMAGE_BASE_ALIGNMENT: u64 = 0x1_0000;

/// Validated summary of rebasing one image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseRelocationPlan {
    /// Preferred image base stored in the optional header.
    pub preferred_image_base: u64,
    /// Actual image base supplied by the prospective loader.
    pub actual_image_base: u64,
    /// Signed mathematical difference between actual and preferred bases.
    pub image_delta: i128,
    /// Number of effective DIR64 writes; ABSOLUTE padding is excluded.
    pub patch_count: usize,
}

/// One checked DIR64 write that a later memory loader may apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationPatch {
    /// RVA of the eight-byte pointer to replace.
    pub target_rva: u32,
    /// Original little-endian value from initialized section bytes.
    pub original_value: u64,
    /// Value after applying the checked image-base delta.
    pub relocated_value: u64,
}

impl<'data> PeImage<'data> {
    /// Validates all AMD64 base-relocation blocks and returns their plan summary.
    ///
    /// No image bytes are changed. ABSOLUTE entries are ignored, DIR64 entries
    /// are checked, and every other relocation kind is rejected.
    pub fn base_relocation_plan(
        &self,
        actual_image_base: u64,
    ) -> Result<BaseRelocationPlan, PeError> {
        scan_base_relocations(self, actual_image_base, &mut |_| {})
    }

    /// Visits checked DIR64 writes without allocating or mutating the image.
    ///
    /// A complete validation pass runs before `visitor` is called, so malformed
    /// metadata cannot leave a consumer with a partial application plan.
    pub fn visit_base_relocations<F>(
        &self,
        actual_image_base: u64,
        mut visitor: F,
    ) -> Result<BaseRelocationPlan, PeError>
    where
        F: FnMut(RelocationPatch),
    {
        let validated = self.base_relocation_plan(actual_image_base)?;
        let emitted = scan_base_relocations(self, actual_image_base, &mut visitor)?;
        debug_assert_eq!(validated, emitted);
        Ok(validated)
    }
}

fn scan_base_relocations<F>(
    image: &PeImage<'_>,
    actual_image_base: u64,
    visitor: &mut F,
) -> Result<BaseRelocationPlan, PeError>
where
    F: FnMut(RelocationPatch),
{
    let optional = image.headers().optional;
    if actual_image_base & (IMAGE_BASE_ALIGNMENT - 1) != 0 {
        return Err(PeError::InvalidActualImageBase {
            value: actual_image_base,
        });
    }
    if actual_image_base
        .checked_add(u64::from(optional.size_of_image))
        .is_none()
    {
        return Err(PeError::ActualImageAddressOverflow);
    }

    let directory = image
        .directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
        .filter(|directory| !directory.is_empty());
    let Some(directory) = directory else {
        if actual_image_base != optional.image_base {
            return Err(PeError::RelocationsRequiredButMissing {
                preferred_image_base: optional.image_base,
                actual_image_base,
            });
        }
        return Ok(BaseRelocationPlan {
            preferred_image_base: optional.image_base,
            actual_image_base,
            image_delta: 0,
            patch_count: 0,
        });
    };

    let bytes = image.section_bytes(directory.address, directory.size)?;
    let mut cursor = 0_usize;
    let mut patch_count = 0_usize;
    let mut previous_page_rva = None;
    while cursor < bytes.len() {
        let remaining = bytes.len() - cursor;
        if remaining < RELOCATION_BLOCK_HEADER_SIZE {
            return Err(PeError::RelocationBlockHeaderTruncated {
                directory_offset: as_u32(cursor, "relocation directory offset")?,
                remaining: as_u32(remaining, "relocation remaining size")?,
            });
        }

        let page_rva = read_u32(&bytes[cursor..cursor + 4]);
        let block_size = read_u32(&bytes[cursor + 4..cursor + 8]);
        let block_size_usize =
            usize::try_from(block_size).map_err(|_| PeError::ArithmeticOverflow {
                field: "relocation block size",
            })?;
        if block_size_usize < RELOCATION_BLOCK_HEADER_SIZE
            || block_size_usize & 3 != 0
            || block_size_usize > remaining
        {
            return Err(PeError::InvalidRelocationBlockSize {
                directory_offset: as_u32(cursor, "relocation directory offset")?,
                block_size,
                remaining: as_u32(remaining, "relocation remaining size")?,
            });
        }
        if page_rva & (RELOCATION_PAGE_SIZE - 1) != 0 {
            return Err(PeError::RelocationPageMisaligned { page_rva });
        }
        if page_rva >= optional.size_of_image {
            return Err(PeError::RelocationPageOutsideImage { page_rva });
        }
        if let Some(previous) = previous_page_rva {
            if page_rva <= previous {
                return Err(PeError::RelocationPagesNotIncreasing {
                    previous_page_rva: previous,
                    page_rva,
                });
            }
        }
        previous_page_rva = Some(page_rva);

        let block_end = cursor + block_size_usize;
        let mut entry_cursor = cursor + RELOCATION_BLOCK_HEADER_SIZE;
        while entry_cursor < block_end {
            let raw = read_u16(&bytes[entry_cursor..entry_cursor + RELOCATION_ENTRY_SIZE]);
            let relocation_type = (raw >> 12) as u8;
            let page_offset = raw & 0x0fff;
            entry_cursor += RELOCATION_ENTRY_SIZE;

            if relocation_type == RELOCATION_TYPE_ABSOLUTE {
                continue;
            }
            if relocation_type != RELOCATION_TYPE_DIR64 {
                return Err(PeError::UnsupportedRelocationType {
                    relocation_type,
                    page_rva,
                    page_offset,
                });
            }

            patch_count = patch_count
                .checked_add(1)
                .ok_or(PeError::TooManyBaseRelocations {
                    count: usize::MAX,
                    maximum: MAX_BASE_RELOCATIONS,
                })?;
            if patch_count > MAX_BASE_RELOCATIONS {
                return Err(PeError::TooManyBaseRelocations {
                    count: patch_count,
                    maximum: MAX_BASE_RELOCATIONS,
                });
            }
            let target_rva = page_rva.checked_add(u32::from(page_offset)).ok_or(
                PeError::RelocationTargetOverflow {
                    page_rva,
                    page_offset,
                },
            )?;
            let source = image.section_bytes(target_rva, 8)?;
            let original_value = read_u64(source);
            let relocated_value = relocate_value(
                original_value,
                optional.image_base,
                actual_image_base,
                target_rva,
            )?;
            visitor(RelocationPatch {
                target_rva,
                original_value,
                relocated_value,
            });
        }
        cursor = block_end;
    }

    Ok(BaseRelocationPlan {
        preferred_image_base: optional.image_base,
        actual_image_base,
        image_delta: i128::from(actual_image_base) - i128::from(optional.image_base),
        patch_count,
    })
}

fn relocate_value(
    original: u64,
    preferred_base: u64,
    actual_base: u64,
    target_rva: u32,
) -> Result<u64, PeError> {
    let relocated = if actual_base >= preferred_base {
        original.checked_add(actual_base - preferred_base)
    } else {
        original.checked_sub(preferred_base - actual_base)
    };
    relocated.ok_or(PeError::RelocatedValueOverflow {
        target_rva,
        original_value: original,
    })
}

fn as_u32(value: usize, field: &'static str) -> Result<u32, PeError> {
    u32::try_from(value).map_err(|_| PeError::ArithmeticOverflow { field })
}

fn read_u16(bytes: &[u8]) -> u16 {
    debug_assert_eq!(bytes.len(), 2);
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    debug_assert_eq!(bytes.len(), 4);
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    debug_assert_eq!(bytes.len(), 8);
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}
