use crate::{
    FileRange, PeError, PeImage, RvaRange, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE, MAX_SECTIONS,
};

/// Final page permissions requested by a validated section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadPermissions {
    /// Page contents may be read.
    pub read: bool,
    /// Page contents may be modified.
    pub write: bool,
    /// Instructions may be fetched from the page.
    pub execute: bool,
}

impl LoadPermissions {
    const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };

    pub(crate) const fn from_characteristics(characteristics: u32) -> Self {
        Self {
            read: characteristics & IMAGE_SCN_MEM_READ != 0,
            write: characteristics & IMAGE_SCN_MEM_WRITE != 0,
            execute: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
        }
    }
}

/// Header bytes and zero padding to materialize at image RVA zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderLoad {
    /// Header bytes copied from the start of the file.
    pub file: FileRange,
    /// Section-aligned virtual range. Loaders zero it before copying `file`.
    pub virtual_range: RvaRange,
}

/// Declarative copy and protection operation for one validated section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionLoad {
    /// Section-table index, preserving original order.
    pub index: usize,
    /// Raw eight-byte PE section name.
    pub name: [u8; 8],
    /// Section-aligned image range. Loaders zero it before copying `file`.
    pub virtual_range: RvaRange,
    /// Initialized source bytes, or `None` for a purely zero-filled section.
    pub file: Option<FileRange>,
    /// Final memory permissions after all copying is complete.
    pub permissions: LoadPermissions,
    /// Original section characteristics.
    pub characteristics: u32,
}

impl SectionLoad {
    const EMPTY: Self = Self {
        index: 0,
        name: [0; 8],
        virtual_range: RvaRange { rva: 0, size: 0 },
        file: None,
        permissions: LoadPermissions::NONE,
        characteristics: 0,
    };
}

/// Allocation-free loader plan derived from a fully validated image.
///
/// A consumer should reserve `size_of_image`, zero each declared virtual range,
/// copy the associated file bytes, and only then install the final permissions.
/// This type never performs those operations itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoaderPlan {
    /// Preferred PE image base.
    pub image_base: u64,
    /// Total section-aligned image reservation.
    pub size_of_image: u32,
    /// Entry-point RVA, or zero when absent.
    pub entry_rva: u32,
    /// Read-only mapped header range.
    pub headers: HeaderLoad,
    sections: [SectionLoad; MAX_SECTIONS],
    section_count: usize,
}

impl LoaderPlan {
    pub(crate) fn from_image(image: &PeImage<'_>) -> Result<Self, PeError> {
        let optional = image.headers().optional;
        let header_mapped_size = crate::reader::align_up(
            optional.size_of_headers,
            optional.section_alignment,
            "mapped headers",
        )?;
        let mut sections = [SectionLoad::EMPTY; MAX_SECTIONS];

        for (index, section) in image.sections().iter().copied().enumerate() {
            sections[index] = SectionLoad {
                index,
                name: section.name,
                virtual_range: section.virtual_range(),
                file: section.file_range(),
                permissions: LoadPermissions::from_characteristics(section.characteristics),
                characteristics: section.characteristics,
            };
        }

        Ok(Self {
            image_base: optional.image_base,
            size_of_image: optional.size_of_image,
            entry_rva: optional.address_of_entry_point,
            headers: HeaderLoad {
                file: FileRange {
                    offset: 0,
                    size: optional.size_of_headers,
                },
                virtual_range: RvaRange {
                    rva: 0,
                    size: header_mapped_size,
                },
            },
            sections,
            section_count: image.sections().len(),
        })
    }

    /// Returns validated section copy operations in original table order.
    #[must_use]
    pub fn sections(&self) -> &[SectionLoad] {
        &self.sections[..self.section_count]
    }

    /// Returns the preferred entry address, or `None` for a zero entry RVA.
    #[must_use]
    pub const fn preferred_entry(&self) -> Option<u64> {
        if self.entry_rva == 0 {
            None
        } else {
            self.image_base.checked_add(self.entry_rva as u64)
        }
    }
}
