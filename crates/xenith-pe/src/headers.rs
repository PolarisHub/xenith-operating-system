/// Maximum section count accepted by the Windows PE loader contract.
pub const MAX_SECTIONS: usize = 96;
/// Maximum standard PE data-directory entries retained by the parser.
pub const MAX_DATA_DIRECTORIES: usize = 16;
/// Maximum image reservation accepted by this initial Xenith loader policy.
pub const MAX_IMAGE_SIZE: u32 = 512 * 1024 * 1024;

/// COFF machine identifier for AMD64.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// Optional-header magic for PE32+ images.
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020b;
/// Data-directory index for the regular import descriptor table.
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
/// Data-directory index whose address is a file offset rather than an RVA.
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
/// Data-directory index for image base relocations.
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
/// Data-directory index for the TLS directory.
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
/// Data-directory index for delayed imports.
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;

/// Section contains executable code.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Section is readable after loading.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// Section is writable after loading.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Relevant fixed DOS-header fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DosHeader {
    /// File offset of the PE signature from DOS `e_lfanew`.
    pub pe_offset: u32,
}

/// Complete 20-byte COFF file header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoffHeader {
    /// Target machine identifier.
    pub machine: u16,
    /// Number of following section-table entries.
    pub number_of_sections: u16,
    /// Producer timestamp; retained but not trusted for validation.
    pub time_date_stamp: u32,
    /// COFF symbol-table file offset.
    pub pointer_to_symbol_table: u32,
    /// Number of COFF symbols.
    pub number_of_symbols: u32,
    /// Size of the following optional header.
    pub size_of_optional_header: u16,
    /// COFF image characteristics.
    pub characteristics: u16,
}

/// Fixed fields of the 64-bit PE optional header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionalHeader64 {
    /// Linker major version.
    pub major_linker_version: u8,
    /// Linker minor version.
    pub minor_linker_version: u8,
    /// Sum of code section sizes.
    pub size_of_code: u32,
    /// Sum of initialized-data section sizes.
    pub size_of_initialized_data: u32,
    /// Sum of uninitialized-data section sizes.
    pub size_of_uninitialized_data: u32,
    /// Entry-point RVA, or zero when absent.
    pub address_of_entry_point: u32,
    /// Beginning-of-code RVA.
    pub base_of_code: u32,
    /// Preferred virtual image base.
    pub image_base: u64,
    /// In-memory section alignment.
    pub section_alignment: u32,
    /// On-disk section alignment.
    pub file_alignment: u32,
    /// Required operating-system major version.
    pub major_operating_system_version: u16,
    /// Required operating-system minor version.
    pub minor_operating_system_version: u16,
    /// Image major version.
    pub major_image_version: u16,
    /// Image minor version.
    pub minor_image_version: u16,
    /// Required subsystem major version.
    pub major_subsystem_version: u16,
    /// Required subsystem minor version.
    pub minor_subsystem_version: u16,
    /// Reserved Win32 version field.
    pub win32_version_value: u32,
    /// Section-aligned memory reservation for the entire image.
    pub size_of_image: u32,
    /// File-aligned byte size of all headers.
    pub size_of_headers: u32,
    /// Image checksum.
    pub checksum: u32,
    /// Required subsystem identifier.
    pub subsystem: u16,
    /// DLL/image characteristics.
    pub dll_characteristics: u16,
    /// Initial thread stack reservation.
    pub size_of_stack_reserve: u64,
    /// Initial thread stack commitment.
    pub size_of_stack_commit: u64,
    /// Initial process heap reservation.
    pub size_of_heap_reserve: u64,
    /// Initial process heap commitment.
    pub size_of_heap_commit: u64,
    /// Reserved loader flags.
    pub loader_flags: u32,
    /// Number of advertised data-directory entries.
    pub number_of_rva_and_sizes: u32,
}

/// Parsed top-level PE headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeHeaders {
    /// DOS header fields.
    pub dos: DosHeader,
    /// COFF file header.
    pub coff: CoffHeader,
    /// PE32+ optional header.
    pub optional: OptionalHeader64,
}

/// One standard PE data-directory tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataDirectory {
    /// RVA for normal directories, or file offset for the security directory.
    pub address: u32,
    /// Directory size in bytes.
    pub size: u32,
}

impl DataDirectory {
    pub(crate) const EMPTY: Self = Self {
        address: 0,
        size: 0,
    };

    /// Returns whether both address and size are zero.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.address == 0 && self.size == 0
    }
}

/// Validated contiguous range in the PE file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRange {
    /// First byte offset in the file.
    pub offset: u32,
    /// Number of bytes in the range.
    pub size: u32,
}

impl FileRange {
    /// Returns the exclusive end when arithmetic remains representable.
    #[must_use]
    pub const fn checked_end(self) -> Option<u32> {
        self.offset.checked_add(self.size)
    }
}

/// Validated relative-virtual-address range in the loaded image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RvaRange {
    /// First relative virtual address.
    pub rva: u32,
    /// Number of bytes in the range.
    pub size: u32,
}

impl RvaRange {
    /// Returns the exclusive end when arithmetic remains representable.
    #[must_use]
    pub const fn checked_end(self) -> Option<u32> {
        self.rva.checked_add(self.size)
    }
}

/// Parsed 40-byte PE section header plus its validated aligned load size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionHeader {
    /// Raw, zero-padded eight-byte section name.
    pub name: [u8; 8],
    /// Declared in-memory content size before section alignment.
    pub virtual_size: u32,
    /// Section RVA.
    pub virtual_address: u32,
    /// File-aligned initialized byte size.
    pub size_of_raw_data: u32,
    /// File offset of initialized bytes.
    pub pointer_to_raw_data: u32,
    /// COFF relocation-table file offset.
    pub pointer_to_relocations: u32,
    /// COFF line-number-table file offset.
    pub pointer_to_line_numbers: u32,
    /// COFF relocation count.
    pub number_of_relocations: u16,
    /// COFF line-number count.
    pub number_of_line_numbers: u16,
    /// Section characteristics and memory permissions.
    pub characteristics: u32,
    /// Validated in-memory span, rounded up to `SectionAlignment`.
    pub mapped_size: u32,
}

impl SectionHeader {
    pub(crate) const EMPTY: Self = Self {
        name: [0; 8],
        virtual_size: 0,
        virtual_address: 0,
        size_of_raw_data: 0,
        pointer_to_raw_data: 0,
        pointer_to_relocations: 0,
        pointer_to_line_numbers: 0,
        number_of_relocations: 0,
        number_of_line_numbers: 0,
        characteristics: 0,
        mapped_size: 0,
    };

    /// Returns the initialized raw-data range, when present.
    #[must_use]
    pub const fn file_range(self) -> Option<FileRange> {
        if self.size_of_raw_data == 0 {
            None
        } else {
            Some(FileRange {
                offset: self.pointer_to_raw_data,
                size: self.size_of_raw_data,
            })
        }
    }

    /// Returns the aligned virtual range reserved for this section.
    #[must_use]
    pub const fn virtual_range(self) -> RvaRange {
        RvaRange {
            rva: self.virtual_address,
            size: self.mapped_size,
        }
    }
}
