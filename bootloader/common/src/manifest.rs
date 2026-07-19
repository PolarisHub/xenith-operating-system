//! Parser for the sector-sized `XENITHIM` raw-disk manifest.

use crate::{fnv1a64, fnv1a64_with_zeroed_range};

pub const DISK_MANIFEST_MAGIC: &[u8; 8] = b"XENITHIM";
pub const DISK_MANIFEST_VERSION: u16 = 1;
pub const DISK_MANIFEST_SIZE: usize = 512;
pub const DISK_MANIFEST_LBA: u64 = 1;
pub const DISK_SECTOR_SIZE: u32 = 512;
pub const DISK_ENTRY_SIZE: usize = 64;
pub const DISK_ENTRY_OFFSET: usize = 64;
pub const DISK_ENTRY_COUNT: usize = 3;
pub const MANIFEST_CHECKSUM_OFFSET: usize = 32;
pub const MANIFEST_CHECKSUM_SIZE: usize = 8;
pub const MAX_STAGE2_SECTORS: u64 = 127;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    TooShort,
    BadMagic,
    UnsupportedVersion,
    BadHeaderSize,
    BadFlags,
    BadSectorSize,
    BadEntryCount,
    BadFooter,
    BadManifestChecksum,
    BadEntryKind,
    MissingRequiredEntry,
    DuplicateEntry,
    EmptyPayload,
    PayloadOutsideImage,
    Stage2TooLarge,
    BadPayloadChecksum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DiskEntryKind {
    Stage2 = 1,
    Kernel = 2,
    Initrd = 3,
}

impl DiskEntryKind {
    fn parse(raw: u32) -> Result<Self, ManifestError> {
        match raw {
            1 => Ok(Self::Stage2),
            2 => Ok(Self::Kernel),
            3 => Ok(Self::Initrd),
            _ => Err(ManifestError::BadEntryKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskEntry {
    pub kind: DiskEntryKind,
    pub flags: u32,
    pub start_lba: u64,
    pub sector_count: u64,
    pub byte_len: u64,
    pub payload_checksum: u64,
    pub name: [u8; 24],
}

impl DiskEntry {
    pub const REQUIRED: u32 = 1;

    #[must_use]
    pub fn is_required(self) -> bool {
        self.flags & Self::REQUIRED != 0
    }

    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.name.len());
        &self.name[..end]
    }

    pub fn verify_payload(&self, payload: &[u8]) -> Result<(), ManifestError> {
        let byte_len = usize::try_from(self.byte_len).map_err(|_| ManifestError::EmptyPayload)?;
        let exact = payload.get(..byte_len).ok_or(ManifestError::EmptyPayload)?;
        if fnv1a64(exact) == self.payload_checksum {
            Ok(())
        } else {
            Err(ManifestError::BadPayloadChecksum)
        }
    }
}

#[derive(Clone, Copy)]
pub struct DiskManifest<'a> {
    sector: &'a [u8],
    image_sectors: u64,
}

impl<'a> DiskManifest<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ManifestError> {
        let sector = bytes
            .get(..DISK_MANIFEST_SIZE)
            .ok_or(ManifestError::TooShort)?;
        if sector.get(..8) != Some(DISK_MANIFEST_MAGIC.as_slice()) {
            return Err(ManifestError::BadMagic);
        }
        if read_u16(sector, 8) != Some(DISK_MANIFEST_VERSION) {
            return Err(ManifestError::UnsupportedVersion);
        }
        if read_u16(sector, 10) != Some(DISK_MANIFEST_SIZE as u16) {
            return Err(ManifestError::BadHeaderSize);
        }
        if read_u32(sector, 12) != Some(1) {
            return Err(ManifestError::BadFlags);
        }
        if read_u32(sector, 16) != Some(DISK_SECTOR_SIZE) {
            return Err(ManifestError::BadSectorSize);
        }
        if read_u32(sector, 20) != Some(DISK_ENTRY_COUNT as u32) {
            return Err(ManifestError::BadEntryCount);
        }
        if sector.get(504..510) != Some(b"XENITH".as_slice())
            || sector.get(510..512) != Some(&[0x55, 0xaa])
        {
            return Err(ManifestError::BadFooter);
        }
        let stored_checksum =
            read_u64(sector, MANIFEST_CHECKSUM_OFFSET).ok_or(ManifestError::TooShort)?;
        let actual_checksum =
            fnv1a64_with_zeroed_range(sector, MANIFEST_CHECKSUM_OFFSET, MANIFEST_CHECKSUM_SIZE);
        if actual_checksum != stored_checksum {
            return Err(ManifestError::BadManifestChecksum);
        }
        let image_sectors = read_u64(sector, 24).ok_or(ManifestError::TooShort)?;
        if image_sectors < 3 {
            return Err(ManifestError::PayloadOutsideImage);
        }

        let manifest = Self {
            sector,
            image_sectors,
        };
        manifest.validate_entries()?;
        Ok(manifest)
    }

    #[must_use]
    pub const fn image_sectors(&self) -> u64 {
        self.image_sectors
    }

    pub fn entry(&self, index: usize) -> Result<DiskEntry, ManifestError> {
        if index >= DISK_ENTRY_COUNT {
            return Err(ManifestError::BadEntryCount);
        }
        let start = DISK_ENTRY_OFFSET + index * DISK_ENTRY_SIZE;
        let raw = self
            .sector
            .get(start..start + DISK_ENTRY_SIZE)
            .ok_or(ManifestError::TooShort)?;
        let mut name = [0_u8; 24];
        name.copy_from_slice(raw.get(40..64).ok_or(ManifestError::TooShort)?);
        Ok(DiskEntry {
            kind: DiskEntryKind::parse(read_u32(raw, 0).ok_or(ManifestError::TooShort)?)?,
            flags: read_u32(raw, 4).ok_or(ManifestError::TooShort)?,
            start_lba: read_u64(raw, 8).ok_or(ManifestError::TooShort)?,
            sector_count: read_u64(raw, 16).ok_or(ManifestError::TooShort)?,
            byte_len: read_u64(raw, 24).ok_or(ManifestError::TooShort)?,
            payload_checksum: read_u64(raw, 32).ok_or(ManifestError::TooShort)?,
            name,
        })
    }

    pub fn find(&self, kind: DiskEntryKind) -> Result<DiskEntry, ManifestError> {
        for index in 0..DISK_ENTRY_COUNT {
            let entry = self.entry(index)?;
            if entry.kind == kind {
                return Ok(entry);
            }
        }
        Err(ManifestError::MissingRequiredEntry)
    }

    fn validate_entries(&self) -> Result<(), ManifestError> {
        let expected = [
            DiskEntryKind::Stage2,
            DiskEntryKind::Kernel,
            DiskEntryKind::Initrd,
        ];
        for (index, expected_kind) in expected.into_iter().enumerate() {
            let entry = self.entry(index)?;
            if entry.kind != expected_kind {
                return Err(if expected[..index].contains(&entry.kind) {
                    ManifestError::DuplicateEntry
                } else {
                    ManifestError::MissingRequiredEntry
                });
            }
            if !entry.is_required() {
                return Err(ManifestError::MissingRequiredEntry);
            }
            if entry.sector_count == 0 || entry.byte_len == 0 {
                return Err(ManifestError::EmptyPayload);
            }
            let covered_bytes = entry
                .sector_count
                .checked_mul(u64::from(DISK_SECTOR_SIZE))
                .ok_or(ManifestError::PayloadOutsideImage)?;
            if entry.byte_len > covered_bytes
                || entry
                    .start_lba
                    .checked_add(entry.sector_count)
                    .filter(|end| *end <= self.image_sectors)
                    .is_none()
            {
                return Err(ManifestError::PayloadOutsideImage);
            }
            if entry.kind == DiskEntryKind::Stage2 && entry.sector_count > MAX_STAGE2_SECTORS {
                return Err(ManifestError::Stage2TooLarge);
            }
        }
        Ok(())
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: u32, lba: u64, sectors: u64, bytes: u64, name: &[u8]) -> [u8; 64] {
        let mut raw = [0_u8; 64];
        raw[0..4].copy_from_slice(&kind.to_le_bytes());
        raw[4..8].copy_from_slice(&1_u32.to_le_bytes());
        raw[8..16].copy_from_slice(&lba.to_le_bytes());
        raw[16..24].copy_from_slice(&sectors.to_le_bytes());
        raw[24..32].copy_from_slice(&bytes.to_le_bytes());
        let zero_payload = [0_u8; 4096];
        raw[32..40].copy_from_slice(&fnv1a64(&zero_payload[..bytes as usize]).to_le_bytes());
        raw[40..40 + name.len()].copy_from_slice(name);
        raw
    }

    fn valid_manifest() -> [u8; 512] {
        let mut raw = [0_u8; 512];
        raw[..8].copy_from_slice(DISK_MANIFEST_MAGIC);
        raw[8..10].copy_from_slice(&1_u16.to_le_bytes());
        raw[10..12].copy_from_slice(&512_u16.to_le_bytes());
        raw[12..16].copy_from_slice(&1_u32.to_le_bytes());
        raw[16..20].copy_from_slice(&512_u32.to_le_bytes());
        raw[20..24].copy_from_slice(&3_u32.to_le_bytes());
        raw[24..32].copy_from_slice(&64_u64.to_le_bytes());
        raw[64..128].copy_from_slice(&entry(1, 2, 8, 3000, b"stage2"));
        raw[128..192].copy_from_slice(&entry(2, 16, 8, 3000, b"kernel"));
        raw[192..256].copy_from_slice(&entry(3, 24, 8, 3000, b"initrd"));
        raw[504..510].copy_from_slice(b"XENITH");
        raw[510..512].copy_from_slice(&[0x55, 0xaa]);
        let checksum = fnv1a64_with_zeroed_range(&raw, 32, 8);
        raw[32..40].copy_from_slice(&checksum.to_le_bytes());
        raw
    }

    #[test]
    fn parses_the_iso_builder_contract() {
        let raw = valid_manifest();
        let manifest = DiskManifest::parse(&raw).unwrap();
        assert_eq!(manifest.image_sectors(), 64);
        let kernel = manifest.find(DiskEntryKind::Kernel).unwrap();
        assert_eq!(kernel.start_lba, 16);
        assert_eq!(kernel.name_bytes(), b"kernel");
    }

    #[test]
    fn checksum_covers_reserved_bytes() {
        let mut raw = valid_manifest();
        raw[400] ^= 1;
        assert!(matches!(
            DiskManifest::parse(&raw),
            Err(ManifestError::BadManifestChecksum)
        ));
    }

    #[test]
    fn enforces_the_single_edd_read_limit() {
        let mut raw = valid_manifest();
        raw[80..88].copy_from_slice(&128_u64.to_le_bytes());
        raw[88..96].copy_from_slice(&(128 * 512_u64).to_le_bytes());
        raw[24..32].copy_from_slice(&256_u64.to_le_bytes());
        raw[32..40].fill(0);
        let checksum = fnv1a64_with_zeroed_range(&raw, 32, 8);
        raw[32..40].copy_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            DiskManifest::parse(&raw),
            Err(ManifestError::Stage2TooLarge)
        ));
    }
}
