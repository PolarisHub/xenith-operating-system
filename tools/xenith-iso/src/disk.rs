//! Xenith's raw BIOS disk container.
//!
//! Sector zero is supplied by the bootloader crate. Sector one is a compact,
//! checksummed manifest that tells stage1/stage2 where every variable-sized
//! payload lives. Keeping this contract independent of a filesystem makes the
//! earliest boot stages small and deterministic.

use crate::{payload_checksum, ImageError};

/// Logical sector size used by BIOS reads and the Xenith manifest.
pub const DISK_SECTOR_SIZE: usize = 512;
/// The manifest is always directly after the MBR.
pub const DISK_MANIFEST_LBA: u64 = 1;
/// Eight-byte header identifying a Xenith raw disk image.
pub const DISK_MANIFEST_MAGIC: [u8; 8] = *b"XENITHIM";
/// Current manifest schema version.
pub const DISK_MANIFEST_VERSION: u16 = 1;

const STAGE2_LBA: u64 = 2;
const PAYLOAD_ALIGNMENT_SECTORS: u64 = 8;
const STAGE1_MAX_STAGE2_SECTORS: u64 = 127;
const MANIFEST_FLAGS: u32 = 1;
const ENTRY_FLAGS_REQUIRED: u32 = 1;
const MANIFEST_CHECKSUM_OFFSET: usize = 32;
const MANIFEST_ENTRY_OFFSET: usize = 64;
const MANIFEST_ENTRY_SIZE: usize = 64;
const MANIFEST_TRAILER_OFFSET: usize = 504;
const MANIFEST_TRAILER: [u8; 6] = *b"XENITH";

/// Type tag stored in a manifest entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ManifestEntryKind {
    Stage2 = 1,
    Kernel = 2,
    Initrd = 3,
}

impl ManifestEntryKind {
    fn from_raw(value: u32) -> Result<Self, ImageError> {
        match value {
            1 => Ok(Self::Stage2),
            2 => Ok(Self::Kernel),
            3 => Ok(Self::Initrd),
            _ => Err(ImageError::InvalidManifest("unknown entry kind")),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Stage2 => "stage2",
            Self::Kernel => "kernel",
            Self::Initrd => "initrd",
        }
    }
}

/// One byte-accurate payload extent in the raw image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestEntry {
    pub kind: ManifestEntryKind,
    pub required: bool,
    pub start_lba: u64,
    pub sector_count: u64,
    pub byte_len: u64,
    pub checksum: u64,
    pub name: String,
}

impl ManifestEntry {
    /// LBA immediately following this entry's allocated sectors.
    #[must_use]
    pub fn end_lba(&self) -> u64 {
        self.start_lba.saturating_add(self.sector_count)
    }
}

/// Decoded contents of the manifest sector at LBA 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiskManifest {
    pub image_sectors: u64,
    pub checksum: u64,
    pub entries: [ManifestEntry; 3],
}

impl DiskManifest {
    /// Finds the fixed entry for a component kind.
    #[must_use]
    pub fn entry(&self, kind: ManifestEntryKind) -> &ManifestEntry {
        match kind {
            ManifestEntryKind::Stage2 => &self.entries[0],
            ManifestEntryKind::Kernel => &self.entries[1],
            ManifestEntryKind::Initrd => &self.entries[2],
        }
    }
}

/// Calculated raw-image positions returned to build orchestrators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiskLayout {
    pub manifest_lba: u64,
    pub stage2: ManifestEntry,
    pub kernel: ManifestEntry,
    pub initrd: ManifestEntry,
    pub total_sectors: u64,
}

/// Builds a raw MBR disk image.
///
/// `stage1` must occupy one complete 512-byte sector. Its last two bytes are
/// normalized to the mandatory MBR signature, allowing a linker-produced
/// stage1 binary to leave them as zero placeholders.
pub fn build_disk_image(
    stage1: &[u8],
    stage2: &[u8],
    kernel: &[u8],
    initrd: &[u8],
) -> Result<Vec<u8>, ImageError> {
    build_disk_image_with_layout(stage1, stage2, kernel, initrd).map(|(image, _)| image)
}

/// Builds a raw MBR image and returns its calculated extent map.
pub fn build_disk_image_with_layout(
    stage1: &[u8],
    stage2: &[u8],
    kernel: &[u8],
    initrd: &[u8],
) -> Result<(Vec<u8>, DiskLayout), ImageError> {
    validate_components(stage1, stage2, kernel, initrd)?;

    let stage2_entry = component_entry(ManifestEntryKind::Stage2, STAGE2_LBA, stage2)?;
    if stage2_entry.sector_count > STAGE1_MAX_STAGE2_SECTORS {
        return Err(ImageError::ImageTooLarge("stage2 (maximum is 127 sectors)"));
    }
    let kernel_lba = align_lba(stage2_entry.checked_end_lba()?)?;
    let kernel_entry = component_entry(ManifestEntryKind::Kernel, kernel_lba, kernel)?;
    let initrd_lba = align_lba(kernel_entry.checked_end_lba()?)?;
    let initrd_entry = component_entry(ManifestEntryKind::Initrd, initrd_lba, initrd)?;
    let image_sectors = align_lba(initrd_entry.checked_end_lba()?)?;

    let entries = [
        stage2_entry.clone(),
        kernel_entry.clone(),
        initrd_entry.clone(),
    ];
    let provisional_manifest = DiskManifest {
        image_sectors,
        checksum: 0,
        entries,
    };
    let manifest_sector = encode_manifest(&provisional_manifest)?;
    let manifest = parse_manifest(&manifest_sector)?;

    let total_bytes = sectors_to_bytes(image_sectors)?;
    let mut image = vec![0_u8; total_bytes];
    image[..DISK_SECTOR_SIZE].copy_from_slice(stage1);
    image[DISK_SECTOR_SIZE - 2..DISK_SECTOR_SIZE].copy_from_slice(&[0x55, 0xaa]);
    image[DISK_SECTOR_SIZE..DISK_SECTOR_SIZE * 2].copy_from_slice(&manifest_sector);

    write_payload(&mut image, &stage2_entry, stage2)?;
    write_payload(&mut image, &kernel_entry, kernel)?;
    write_payload(&mut image, &initrd_entry, initrd)?;

    let layout = DiskLayout {
        manifest_lba: DISK_MANIFEST_LBA,
        stage2: stage2_entry,
        kernel: kernel_entry,
        initrd: initrd_entry,
        total_sectors: image_sectors,
    };

    debug_assert_eq!(manifest.image_sectors, layout.total_sectors);
    Ok((image, layout))
}

/// Parses and structurally validates one 512-byte manifest sector.
pub fn parse_manifest(sector: &[u8]) -> Result<DiskManifest, ImageError> {
    if sector.len() != DISK_SECTOR_SIZE {
        return Err(ImageError::InvalidManifest(
            "manifest must be exactly one 512-byte sector",
        ));
    }
    if sector[..8] != DISK_MANIFEST_MAGIC {
        return Err(ImageError::InvalidManifest("bad header magic"));
    }
    if read_u16(sector, 8) != DISK_MANIFEST_VERSION {
        return Err(ImageError::InvalidManifest("unsupported version"));
    }
    if usize::from(read_u16(sector, 10)) != DISK_SECTOR_SIZE {
        return Err(ImageError::InvalidManifest("bad header length"));
    }
    if read_u32(sector, 12) != MANIFEST_FLAGS {
        return Err(ImageError::InvalidManifest("unsupported checksum flags"));
    }
    if usize::try_from(read_u32(sector, 16)).ok() != Some(DISK_SECTOR_SIZE) {
        return Err(ImageError::InvalidManifest("bad sector size"));
    }
    if read_u32(sector, 20) != 3 {
        return Err(ImageError::InvalidManifest("entry count must be three"));
    }
    if sector[MANIFEST_TRAILER_OFFSET..MANIFEST_TRAILER_OFFSET + 6] != MANIFEST_TRAILER {
        return Err(ImageError::InvalidManifest("bad trailer magic"));
    }
    if sector[510..512] != [0x55, 0xaa] {
        return Err(ImageError::InvalidManifest("missing trailer signature"));
    }

    let stored_checksum = read_u64(sector, MANIFEST_CHECKSUM_OFFSET);
    let mut checksum_input = [0_u8; DISK_SECTOR_SIZE];
    checksum_input.copy_from_slice(sector);
    checksum_input[MANIFEST_CHECKSUM_OFFSET..MANIFEST_CHECKSUM_OFFSET + 8].fill(0);
    if payload_checksum(&checksum_input) != stored_checksum {
        return Err(ImageError::InvalidManifest("manifest checksum mismatch"));
    }

    let image_sectors = read_u64(sector, 24);
    let entries = [
        parse_entry(sector, 0, ManifestEntryKind::Stage2)?,
        parse_entry(sector, 1, ManifestEntryKind::Kernel)?,
        parse_entry(sector, 2, ManifestEntryKind::Initrd)?,
    ];
    validate_manifest_layout(image_sectors, &entries)?;

    Ok(DiskManifest {
        image_sectors,
        checksum: stored_checksum,
        entries,
    })
}

/// Validates the MBR, manifest, extents, payload checksums, and zero padding.
pub fn validate_disk_image(image: &[u8]) -> Result<DiskManifest, ImageError> {
    if image.len() < DISK_SECTOR_SIZE * 3 || !image.len().is_multiple_of(DISK_SECTOR_SIZE) {
        return Err(ImageError::InvalidInput(
            "raw image must contain whole sectors for MBR, manifest, and stage2",
        ));
    }
    if image[510..512] != [0x55, 0xaa] {
        return Err(ImageError::InvalidInput("MBR signature is missing"));
    }

    let manifest = parse_manifest(&image[DISK_SECTOR_SIZE..DISK_SECTOR_SIZE * 2])?;
    let actual_sectors = u64::try_from(image.len() / DISK_SECTOR_SIZE)
        .map_err(|_| ImageError::ImageTooLarge("raw disk image"))?;
    if actual_sectors != manifest.image_sectors {
        return Err(ImageError::InvalidManifest(
            "image length does not match manifest",
        ));
    }

    let mut previous_end = STAGE2_LBA;
    for entry in &manifest.entries {
        validate_zero_sectors(image, previous_end, entry.start_lba)?;
        let start = sectors_to_bytes(entry.start_lba)?;
        let byte_len = usize::try_from(entry.byte_len)
            .map_err(|_| ImageError::ImageTooLarge("manifest payload"))?;
        let data_end = start
            .checked_add(byte_len)
            .ok_or(ImageError::ImageTooLarge("manifest payload"))?;
        if payload_checksum(&image[start..data_end]) != entry.checksum {
            return Err(ImageError::InvalidManifest("payload checksum mismatch"));
        }
        let allocation_end = sectors_to_bytes(entry.checked_end_lba()?)?;
        if image[data_end..allocation_end]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ImageError::InvalidManifest(
                "payload sector padding is not zero",
            ));
        }
        previous_end = entry.checked_end_lba()?;
    }
    validate_zero_sectors(image, previous_end, manifest.image_sectors)?;

    Ok(manifest)
}

impl ManifestEntry {
    fn checked_end_lba(&self) -> Result<u64, ImageError> {
        self.start_lba
            .checked_add(self.sector_count)
            .ok_or(ImageError::ImageTooLarge("raw disk extent"))
    }
}

fn validate_components(
    stage1: &[u8],
    stage2: &[u8],
    kernel: &[u8],
    initrd: &[u8],
) -> Result<(), ImageError> {
    if stage1.len() != DISK_SECTOR_SIZE {
        return Err(ImageError::InvalidInput("stage1 must be exactly 512 bytes"));
    }
    if stage2.is_empty() {
        return Err(ImageError::InvalidInput("stage2 must not be empty"));
    }
    if kernel.is_empty() {
        return Err(ImageError::InvalidInput("kernel must not be empty"));
    }
    if initrd.is_empty() {
        return Err(ImageError::InvalidInput("initrd must not be empty"));
    }
    Ok(())
}

fn component_entry(
    kind: ManifestEntryKind,
    start_lba: u64,
    bytes: &[u8],
) -> Result<ManifestEntry, ImageError> {
    let byte_len =
        u64::try_from(bytes.len()).map_err(|_| ImageError::ImageTooLarge(kind.label()))?;
    let sector_count = byte_len.div_ceil(DISK_SECTOR_SIZE as u64);
    Ok(ManifestEntry {
        kind,
        required: true,
        start_lba,
        sector_count,
        byte_len,
        checksum: payload_checksum(bytes),
        name: kind.label().to_owned(),
    })
}

fn align_lba(lba: u64) -> Result<u64, ImageError> {
    lba.checked_add(PAYLOAD_ALIGNMENT_SECTORS - 1)
        .map(|value| value / PAYLOAD_ALIGNMENT_SECTORS * PAYLOAD_ALIGNMENT_SECTORS)
        .ok_or(ImageError::ImageTooLarge("raw disk image"))
}

fn sectors_to_bytes(sectors: u64) -> Result<usize, ImageError> {
    let bytes = sectors
        .checked_mul(DISK_SECTOR_SIZE as u64)
        .ok_or(ImageError::ImageTooLarge("raw disk image"))?;
    usize::try_from(bytes).map_err(|_| ImageError::ImageTooLarge("raw disk image"))
}

fn write_payload(
    image: &mut [u8],
    entry: &ManifestEntry,
    payload: &[u8],
) -> Result<(), ImageError> {
    let start = sectors_to_bytes(entry.start_lba)?;
    let end = start
        .checked_add(payload.len())
        .ok_or(ImageError::ImageTooLarge(entry.kind.label()))?;
    image[start..end].copy_from_slice(payload);
    Ok(())
}

fn encode_manifest(manifest: &DiskManifest) -> Result<[u8; DISK_SECTOR_SIZE], ImageError> {
    let mut sector = [0_u8; DISK_SECTOR_SIZE];
    sector[..8].copy_from_slice(&DISK_MANIFEST_MAGIC);
    write_u16(&mut sector, 8, DISK_MANIFEST_VERSION);
    write_u16(&mut sector, 10, DISK_SECTOR_SIZE as u16);
    write_u32(&mut sector, 12, MANIFEST_FLAGS);
    write_u32(&mut sector, 16, DISK_SECTOR_SIZE as u32);
    write_u32(&mut sector, 20, 3);
    write_u64(&mut sector, 24, manifest.image_sectors);

    for (index, entry) in manifest.entries.iter().enumerate() {
        encode_entry(&mut sector, index, entry)?;
    }
    sector[MANIFEST_TRAILER_OFFSET..MANIFEST_TRAILER_OFFSET + 6].copy_from_slice(&MANIFEST_TRAILER);
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);

    let checksum = payload_checksum(&sector);
    write_u64(&mut sector, MANIFEST_CHECKSUM_OFFSET, checksum);
    Ok(sector)
}

fn encode_entry(sector: &mut [u8], index: usize, entry: &ManifestEntry) -> Result<(), ImageError> {
    if entry.name.len() > 23 || !entry.name.is_ascii() {
        return Err(ImageError::InvalidInput(
            "manifest entry name must be at most 23 ASCII bytes",
        ));
    }
    let offset = MANIFEST_ENTRY_OFFSET + index * MANIFEST_ENTRY_SIZE;
    write_u32(sector, offset, entry.kind as u32);
    write_u32(
        sector,
        offset + 4,
        if entry.required {
            ENTRY_FLAGS_REQUIRED
        } else {
            0
        },
    );
    write_u64(sector, offset + 8, entry.start_lba);
    write_u64(sector, offset + 16, entry.sector_count);
    write_u64(sector, offset + 24, entry.byte_len);
    write_u64(sector, offset + 32, entry.checksum);
    sector[offset + 40..offset + 40 + entry.name.len()].copy_from_slice(entry.name.as_bytes());
    Ok(())
}

fn parse_entry(
    sector: &[u8],
    index: usize,
    expected_kind: ManifestEntryKind,
) -> Result<ManifestEntry, ImageError> {
    let offset = MANIFEST_ENTRY_OFFSET + index * MANIFEST_ENTRY_SIZE;
    let kind = ManifestEntryKind::from_raw(read_u32(sector, offset))?;
    if kind != expected_kind {
        return Err(ImageError::InvalidManifest("entry order is invalid"));
    }
    let flags = read_u32(sector, offset + 4);
    if flags != ENTRY_FLAGS_REQUIRED {
        return Err(ImageError::InvalidManifest("entry flags are invalid"));
    }
    let raw_name = &sector[offset + 40..offset + 64];
    let name_len = raw_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(raw_name.len());
    if raw_name[name_len..].iter().any(|byte| *byte != 0) {
        return Err(ImageError::InvalidManifest("entry name is not NUL padded"));
    }
    let name = std::str::from_utf8(&raw_name[..name_len])
        .map_err(|_| ImageError::InvalidManifest("entry name is not UTF-8"))?;
    if name != kind.label() {
        return Err(ImageError::InvalidManifest(
            "entry name does not match kind",
        ));
    }

    Ok(ManifestEntry {
        kind,
        required: true,
        start_lba: read_u64(sector, offset + 8),
        sector_count: read_u64(sector, offset + 16),
        byte_len: read_u64(sector, offset + 24),
        checksum: read_u64(sector, offset + 32),
        name: name.to_owned(),
    })
}

fn validate_manifest_layout(
    image_sectors: u64,
    entries: &[ManifestEntry; 3],
) -> Result<(), ImageError> {
    if entries[0].start_lba != STAGE2_LBA {
        return Err(ImageError::InvalidManifest("stage2 must start at LBA 2"));
    }
    if entries[0].sector_count > STAGE1_MAX_STAGE2_SECTORS {
        return Err(ImageError::InvalidManifest(
            "stage2 exceeds the stage1 127-sector load limit",
        ));
    }
    if !entries[1]
        .start_lba
        .is_multiple_of(PAYLOAD_ALIGNMENT_SECTORS)
        || !entries[2]
            .start_lba
            .is_multiple_of(PAYLOAD_ALIGNMENT_SECTORS)
        || !image_sectors.is_multiple_of(PAYLOAD_ALIGNMENT_SECTORS)
    {
        return Err(ImageError::InvalidManifest("payload alignment is invalid"));
    }

    let mut previous_end = STAGE2_LBA;
    for entry in entries {
        if entry.byte_len == 0 || entry.sector_count == 0 {
            return Err(ImageError::InvalidManifest("empty payload extent"));
        }
        let expected_sectors = entry.byte_len.div_ceil(DISK_SECTOR_SIZE as u64);
        if entry.sector_count != expected_sectors {
            return Err(ImageError::InvalidManifest(
                "payload sector count is invalid",
            ));
        }
        if entry.start_lba < previous_end {
            return Err(ImageError::InvalidManifest("payload extents overlap"));
        }
        previous_end = entry
            .start_lba
            .checked_add(entry.sector_count)
            .ok_or(ImageError::InvalidManifest("payload extent overflows"))?;
        if previous_end > image_sectors {
            return Err(ImageError::InvalidManifest("payload exceeds image"));
        }
    }
    if image_sectors < previous_end {
        return Err(ImageError::InvalidManifest("image is truncated"));
    }
    Ok(())
}

fn validate_zero_sectors(image: &[u8], start_lba: u64, end_lba: u64) -> Result<(), ImageError> {
    let start = sectors_to_bytes(start_lba)?;
    let end = sectors_to_bytes(end_lba)?;
    if image[start..end].iter().any(|byte| *byte != 0) {
        return Err(ImageError::InvalidManifest("alignment padding is not zero"));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut value = [0_u8; 2];
    value.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(value)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0_u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            vec![0x31; DISK_SECTOR_SIZE],
            (0..700).map(|value| value as u8).collect(),
            vec![0x4b; 1_301],
            vec![0xc3; 777],
        )
    }

    #[test]
    fn raw_image_manifest_and_payload_layout_round_trip() {
        let (stage1, stage2, kernel, initrd) = fixture();
        let (image, layout) =
            build_disk_image_with_layout(&stage1, &stage2, &kernel, &initrd).unwrap();

        assert_eq!(&image[..510], &stage1[..510]);
        assert_eq!(&image[510..512], &[0x55, 0xaa]);
        assert_eq!(layout.manifest_lba, 1);
        assert_eq!(layout.stage2.start_lba, 2);
        assert_eq!(layout.kernel.start_lba % 8, 0);
        assert_eq!(layout.initrd.start_lba % 8, 0);
        assert_eq!(layout.total_sectors % 8, 0);
        assert_eq!(
            image.len(),
            layout.total_sectors as usize * DISK_SECTOR_SIZE
        );

        let manifest_sector = &image[DISK_SECTOR_SIZE..DISK_SECTOR_SIZE * 2];
        assert_eq!(&manifest_sector[..8], b"XENITHIM");
        assert_eq!(&manifest_sector[504..510], b"XENITH");
        assert_eq!(&manifest_sector[510..512], &[0x55, 0xaa]);

        let parsed = validate_disk_image(&image).unwrap();
        assert_eq!(parsed.image_sectors, layout.total_sectors);
        assert_eq!(parsed.entry(ManifestEntryKind::Stage2).byte_len, 700);
        assert_eq!(parsed.entry(ManifestEntryKind::Kernel).byte_len, 1_301);
        assert_eq!(parsed.entry(ManifestEntryKind::Initrd).byte_len, 777);
        assert_eq!(
            parsed.entry(ManifestEntryKind::Stage2).checksum,
            payload_checksum(&stage2)
        );

        assert_payload(&image, &parsed.entries[0], &stage2);
        assert_payload(&image, &parsed.entries[1], &kernel);
        assert_payload(&image, &parsed.entries[2], &initrd);
    }

    #[test]
    fn manifest_checksum_and_payload_checksum_detect_corruption() {
        let (stage1, stage2, kernel, initrd) = fixture();
        let image = build_disk_image(&stage1, &stage2, &kernel, &initrd).unwrap();

        let mut broken_manifest = image.clone();
        broken_manifest[DISK_SECTOR_SIZE + 200] ^= 1;
        assert!(matches!(
            validate_disk_image(&broken_manifest),
            Err(ImageError::InvalidManifest("manifest checksum mismatch"))
        ));

        let manifest = parse_manifest(&image[DISK_SECTOR_SIZE..DISK_SECTOR_SIZE * 2]).unwrap();
        let mut broken_payload = image;
        let kernel_offset = manifest.entries[1].start_lba as usize * DISK_SECTOR_SIZE;
        broken_payload[kernel_offset] ^= 1;
        assert!(matches!(
            validate_disk_image(&broken_payload),
            Err(ImageError::InvalidManifest("payload checksum mismatch"))
        ));
    }

    #[test]
    fn stage1_must_be_one_sector_and_components_must_exist() {
        let (_, stage2, kernel, initrd) = fixture();
        assert!(matches!(
            build_disk_image(&[0; 511], &stage2, &kernel, &initrd),
            Err(ImageError::InvalidInput("stage1 must be exactly 512 bytes"))
        ));
        assert!(matches!(
            build_disk_image(&[0; 512], &[], &kernel, &initrd),
            Err(ImageError::InvalidInput("stage2 must not be empty"))
        ));
    }

    fn assert_payload(image: &[u8], entry: &ManifestEntry, expected: &[u8]) {
        let start = entry.start_lba as usize * DISK_SECTOR_SIZE;
        assert_eq!(&image[start..start + expected.len()], expected);
        let allocation_end = entry.end_lba() as usize * DISK_SECTOR_SIZE;
        assert!(image[start + expected.len()..allocation_end]
            .iter()
            .all(|byte| *byte == 0));
    }
}
