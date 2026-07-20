use core::fmt;

/// Structural reason that a byte slice is not in Xenith's accepted PE32+ subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeError {
    /// A requested field or range extends beyond the supplied file bytes.
    Truncated {
        /// First byte requested.
        offset: usize,
        /// Number of bytes requested.
        size: usize,
    },
    /// Checked address or size arithmetic overflowed.
    ArithmeticOverflow {
        /// Name of the field or range being calculated.
        field: &'static str,
    },
    /// The DOS `MZ` signature was absent.
    BadDosMagic {
        /// Signature read from the image.
        found: u16,
    },
    /// `e_lfanew` points into the fixed DOS header.
    PeHeaderOverlapsDosHeader {
        /// Invalid PE header file offset.
        offset: u32,
    },
    /// The `PE\0\0` signature was absent at `e_lfanew`.
    BadPeSignature {
        /// Signature read from the image.
        found: u32,
    },
    /// The COFF machine is not AMD64.
    UnsupportedMachine {
        /// Unsupported COFF machine value.
        found: u16,
    },
    /// An executable image must contain at least one section.
    NoSections,
    /// The image exceeds Xenith's fixed section-count bound.
    TooManySections {
        /// Section count advertised by the COFF header.
        count: u16,
    },
    /// The optional header is too short for fixed PE32+ fields.
    OptionalHeaderTooSmall {
        /// COFF `SizeOfOptionalHeader` value.
        size: u16,
    },
    /// The optional-header magic is not PE32+ (`0x20b`).
    BadOptionalMagic {
        /// Optional-header magic read from the image.
        found: u16,
    },
    /// More than 16 data-directory entries were advertised.
    TooManyDataDirectories {
        /// Advertised directory count.
        count: u32,
    },
    /// The optional header does not contain all advertised directory entries.
    DataDirectoriesTruncated {
        /// Advertised directory count.
        count: u32,
        /// COFF optional-header byte size.
        optional_header_size: u16,
    },
    /// `FileAlignment` is not accepted for a PE image.
    InvalidFileAlignment {
        /// Invalid alignment value.
        value: u32,
    },
    /// `SectionAlignment` is zero or not a power of two.
    InvalidSectionAlignment {
        /// Invalid alignment value.
        value: u32,
    },
    /// Section and file alignments violate the PE image relationship.
    InvalidAlignmentRelationship {
        /// Section alignment.
        section_alignment: u32,
        /// File alignment.
        file_alignment: u32,
    },
    /// The preferred image base is not 64 KiB aligned.
    InvalidImageBase {
        /// Invalid image base.
        value: u64,
    },
    /// The preferred image range overflows `u64`.
    ImageAddressOverflow,
    /// `SizeOfImage` is zero or not section-aligned.
    InvalidSizeOfImage {
        /// Invalid image size.
        value: u32,
    },
    /// `SizeOfImage` exceeds the parser's explicit allocation bound.
    ImageTooLarge {
        /// Advertised image size.
        value: u32,
        /// Maximum accepted image size.
        maximum: u32,
    },
    /// `SizeOfHeaders` is zero, not file-aligned, or larger than the image.
    InvalidSizeOfHeaders {
        /// Invalid header size.
        value: u32,
    },
    /// The complete PE and section-header tables do not fit in `SizeOfHeaders`.
    SectionTableOutsideHeaders {
        /// End offset of the section table.
        section_table_end: usize,
        /// Advertised header size.
        size_of_headers: u32,
    },
    /// The entry-point RVA falls outside `SizeOfImage`.
    EntryPointOutsideImage {
        /// Invalid entry-point RVA.
        rva: u32,
    },
    /// A non-zero entry point does not fall in an executable section.
    EntryPointNotExecutable {
        /// Invalid entry-point RVA.
        rva: u32,
    },
    /// Stack commit size exceeds stack reserve size.
    InvalidStackSizes {
        /// Reserved stack bytes.
        reserve: u64,
        /// Initially committed stack bytes.
        commit: u64,
    },
    /// Heap commit size exceeds heap reserve size.
    InvalidHeapSizes {
        /// Reserved heap bytes.
        reserve: u64,
        /// Initially committed heap bytes.
        commit: u64,
    },
    /// A section RVA does not satisfy `SectionAlignment`.
    SectionVirtualAddressMisaligned {
        /// Section-table index.
        section: usize,
        /// Invalid RVA.
        value: u32,
    },
    /// A section's raw-data size does not satisfy `FileAlignment`.
    SectionRawSizeMisaligned {
        /// Section-table index.
        section: usize,
        /// Invalid raw-data size.
        value: u32,
    },
    /// A section's raw-data pointer does not satisfy `FileAlignment`.
    SectionRawPointerMisaligned {
        /// Section-table index.
        section: usize,
        /// Invalid file offset.
        value: u32,
    },
    /// A low-alignment image does not place raw section bytes at their RVA.
    ///
    /// PE images with `SectionAlignment` below 4 KiB must use identical
    /// in-file and in-memory offsets for every non-empty raw section.
    LowAlignmentSectionOffsetMismatch {
        /// Section-table index.
        section: usize,
        /// Section RVA.
        virtual_address: u32,
        /// Raw-data file offset.
        pointer_to_raw_data: u32,
    },
    /// A section's raw bytes overlap the PE headers.
    SectionRawDataOverlapsHeaders {
        /// Section-table index.
        section: usize,
        /// Raw-data file offset.
        offset: u32,
    },
    /// A section's raw byte range is outside the file.
    SectionRawDataOutsideFile {
        /// Section-table index.
        section: usize,
        /// Raw-data file offset.
        offset: u32,
        /// Raw-data size.
        size: u32,
    },
    /// A section's mapped virtual range overlaps the mapped headers.
    SectionVirtualRangeOverlapsHeaders {
        /// Section-table index.
        section: usize,
        /// Section virtual address.
        virtual_address: u32,
    },
    /// A section's mapped virtual range exceeds `SizeOfImage`.
    SectionVirtualRangeOutsideImage {
        /// Section-table index.
        section: usize,
        /// Section virtual address.
        virtual_address: u32,
        /// Aligned mapped size.
        mapped_size: u32,
    },
    /// Two aligned section virtual ranges overlap.
    VirtualSectionsOverlap {
        /// Earlier section-table index.
        first: usize,
        /// Later section-table index.
        second: usize,
    },
    /// Two non-empty section raw-data ranges overlap.
    RawSectionsOverlap {
        /// Earlier section-table index.
        first: usize,
        /// Later section-table index.
        second: usize,
    },
    /// A section asks for simultaneous write and execute permissions.
    WriteExecuteSection {
        /// Section-table index.
        section: usize,
    },
    /// `SizeOfImage` is not the aligned end of the declared headers and sections.
    SizeOfImageMismatch {
        /// Advertised size.
        declared: u32,
        /// Size required by the validated load ranges.
        required: u32,
    },
    /// A directory has only one of address and size set.
    IncompleteDataDirectory {
        /// Directory-table index.
        directory: usize,
        /// Directory address field.
        address: u32,
        /// Directory size field.
        size: u32,
    },
    /// A mapped data-directory RVA range exceeds the image.
    DataDirectoryOutsideImage {
        /// Directory-table index.
        directory: usize,
        /// Directory RVA.
        rva: u32,
        /// Directory byte size.
        size: u32,
    },
    /// A mapped data directory is not wholly backed by one file range.
    DataDirectoryNotFileBacked {
        /// Directory-table index.
        directory: usize,
        /// Directory RVA.
        rva: u32,
        /// Directory byte size.
        size: u32,
    },
    /// The certificate-table directory is not 8-byte file aligned.
    CertificateTableMisaligned {
        /// Certificate-table file offset.
        offset: u32,
    },
    /// The certificate-table directory points outside the file.
    CertificateTableOutsideFile {
        /// Certificate-table file offset.
        offset: u32,
        /// Certificate-table byte size.
        size: u32,
    },
    /// A caller-provided RVA range exceeds `SizeOfImage`.
    RvaOutsideImage {
        /// First RVA.
        rva: u32,
        /// Requested size.
        size: u32,
    },
    /// A caller-provided RVA range is mapped but not backed by contiguous file bytes.
    RvaNotFileBacked {
        /// First RVA.
        rva: u32,
        /// Requested size.
        size: u32,
    },
    /// A file-required RVA range lies outside all sections.
    RvaNotSectionBacked {
        /// First RVA.
        rva: u32,
        /// Requested size.
        size: u32,
    },
    /// A file-required RVA range touches a section's virtual zero-fill tail.
    RvaTouchesVirtualZeroFill {
        /// Section-table index.
        section: usize,
        /// First RVA.
        rva: u32,
        /// Requested size.
        size: u32,
    },
    /// The requested actual image base is not 64 KiB aligned.
    InvalidActualImageBase {
        /// Invalid actual image base.
        value: u64,
    },
    /// The actual loaded image range overflows `u64`.
    ActualImageAddressOverflow,
    /// Rebasing was requested but the image has no relocation directory.
    RelocationsRequiredButMissing {
        /// Preferred image base.
        preferred_image_base: u64,
        /// Requested actual image base.
        actual_image_base: u64,
    },
    /// A relocation directory ends before a complete block header.
    RelocationBlockHeaderTruncated {
        /// Byte offset within the relocation directory.
        directory_offset: u32,
        /// Bytes remaining at that offset.
        remaining: u32,
    },
    /// A relocation block size is too small, unaligned, or exceeds the directory.
    InvalidRelocationBlockSize {
        /// Byte offset within the relocation directory.
        directory_offset: u32,
        /// Advertised block size.
        block_size: u32,
        /// Bytes remaining in the directory.
        remaining: u32,
    },
    /// A relocation block's page RVA is not 4 KiB aligned.
    RelocationPageMisaligned {
        /// Invalid page RVA.
        page_rva: u32,
    },
    /// A relocation block's page begins outside the declared image.
    RelocationPageOutsideImage {
        /// Invalid page RVA.
        page_rva: u32,
    },
    /// Relocation blocks are not in strictly increasing page order.
    RelocationPagesNotIncreasing {
        /// Previous block page RVA.
        previous_page_rva: u32,
        /// Current block page RVA.
        page_rva: u32,
    },
    /// A relocation entry uses a kind outside ABSOLUTE and AMD64 DIR64.
    UnsupportedRelocationType {
        /// Unsupported four-bit relocation kind.
        relocation_type: u8,
        /// Relocation block page RVA.
        page_rva: u32,
        /// Twelve-bit offset within the block page.
        page_offset: u16,
    },
    /// A relocation target RVA cannot be represented.
    RelocationTargetOverflow {
        /// Relocation block page RVA.
        page_rva: u32,
        /// Twelve-bit offset within the block page.
        page_offset: u16,
    },
    /// A relocation directory exceeds the parser's work bound.
    TooManyBaseRelocations {
        /// Number of effective DIR64 entries encountered.
        count: usize,
        /// Maximum accepted effective entries.
        maximum: usize,
    },
    /// Applying the checked image-base delta would overflow the stored pointer.
    RelocatedValueOverflow {
        /// RVA of the pointer being adjusted.
        target_rva: u32,
        /// Pointer value stored in the file.
        original_value: u64,
    },
    /// The regular import directory size is not a sequence of 20-byte descriptors.
    InvalidImportDirectorySize {
        /// Advertised import directory size.
        size: u32,
    },
    /// The regular import directory exceeds its explicit byte bound.
    ImportDirectoryTooLarge {
        /// Advertised directory size.
        size: u32,
        /// Maximum accepted directory size.
        maximum: u32,
    },
    /// The regular import descriptor table has no all-zero terminator.
    UnterminatedImportDirectory,
    /// Bytes after the first null import descriptor are not all zero.
    NonZeroImportDirectoryTail {
        /// Byte offset within the import directory.
        directory_offset: u32,
    },
    /// The import descriptor count exceeds the parser's work bound.
    TooManyImportModules {
        /// Non-null module descriptor count encountered.
        count: usize,
        /// Maximum accepted module count.
        maximum: usize,
    },
    /// A non-null import descriptor omits its module name RVA.
    MissingImportModuleName {
        /// Descriptor-table index.
        descriptor: usize,
    },
    /// A non-null import descriptor omits its IAT RVA.
    MissingImportAddressTable {
        /// Descriptor-table index.
        descriptor: usize,
    },
    /// An import lookup or address table is not naturally 8-byte aligned.
    ImportThunkTableMisaligned {
        /// Descriptor-table index.
        descriptor: usize,
        /// Invalid table RVA.
        rva: u32,
    },
    /// A module descriptor has an empty lookup table.
    EmptyImportThunkTable {
        /// Descriptor-table index.
        descriptor: usize,
    },
    /// No null thunk was found within the per-module work bound.
    UnterminatedImportThunkTable {
        /// Descriptor-table index.
        descriptor: usize,
        /// Maximum entries scanned.
        maximum: usize,
    },
    /// The total import count exceeds the parser's work bound.
    TooManyImports {
        /// Effective import count encountered.
        count: usize,
        /// Maximum accepted import count.
        maximum: usize,
    },
    /// The IAT slot parallel to a null lookup thunk is not null.
    NonZeroImportAddressTerminator {
        /// Descriptor-table index.
        descriptor: usize,
        /// IAT terminator RVA.
        rva: u32,
        /// Non-zero value found in that slot.
        value: u64,
    },
    /// An ordinal thunk sets reserved bits outside the flag and low ordinal.
    InvalidOrdinalImportEncoding {
        /// Descriptor-table index.
        descriptor: usize,
        /// Thunk-table index.
        thunk: usize,
        /// Invalid raw thunk value.
        value: u64,
    },
    /// An ordinal import specifies ordinal zero.
    InvalidImportOrdinal {
        /// Descriptor-table index.
        descriptor: usize,
        /// Thunk-table index.
        thunk: usize,
    },
    /// A named-import thunk contains a value wider than an RVA.
    ImportNameRvaTooWide {
        /// Descriptor-table index.
        descriptor: usize,
        /// Thunk-table index.
        thunk: usize,
        /// Invalid raw thunk value.
        value: u64,
    },
    /// An import module or symbol name is empty.
    EmptyImportName {
        /// RVA of the empty string.
        rva: u32,
    },
    /// An import module or symbol name contains a non-printable/non-ASCII byte.
    InvalidImportNameByte {
        /// RVA of the string's first byte.
        rva: u32,
        /// Byte offset within the string.
        offset: usize,
        /// Invalid byte.
        byte: u8,
    },
    /// An import module or symbol name exceeds the explicit byte bound.
    ImportNameTooLong {
        /// RVA of the string's first byte.
        rva: u32,
        /// Maximum bytes allowed before the terminator.
        maximum: usize,
    },
    /// A TLS directory is present but unsupported by the initial loader policy.
    UnsupportedTlsDirectory {
        /// TLS directory RVA.
        rva: u32,
        /// TLS directory size.
        size: u32,
    },
    /// A delay-import directory is present but unsupported by the initial policy.
    UnsupportedDelayImportDirectory {
        /// Delay-import directory RVA.
        rva: u32,
        /// Delay-import directory size.
        size: u32,
    },
}

impl fmt::Display for PeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid PE32+ image: {self:?}")
    }
}
