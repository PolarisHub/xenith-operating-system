use xenith_mount::{EntryKind, Error, Explorer, FilesystemKind};

const BLOCK_SIZE: usize = 4096;

#[test]
fn explores_legacy_xenithfs_file() {
    let image = legacy_xenith_image();
    let explorer = Explorer::parse(&image).unwrap();
    let inspection = explorer.inspect();
    assert_eq!(inspection.filesystem, FilesystemKind::XenithFsLegacy);
    assert_eq!(inspection.label.as_deref(), Some("TEST"));

    let entries = explorer.list("/").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].kind, EntryKind::File);
    assert_eq!(explorer.read_file("/hello.txt").unwrap(), b"hello");
}

#[test]
fn explores_kernel_xenithfs_file() {
    let image = modern_xenith_image();
    let explorer = Explorer::parse(&image).unwrap();
    assert_eq!(explorer.inspect().filesystem, FilesystemKind::XenithFs);
    assert_eq!(explorer.inspect().label, None);

    let entries = explorer.list("/").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "/hello.txt");
    assert_eq!(explorer.read_file("hello.txt").unwrap(), b"hello");
}

#[test]
fn validates_kernel_xenithfs_inode_checksum() {
    let mut image = modern_xenith_image();
    image[BLOCK_SIZE + 252] ^= 1;
    let error = Explorer::parse(&image).unwrap().list("/").unwrap_err();
    assert!(matches!(error, Error::Corrupt("XenithFS inode checksum")));
}

#[test]
fn explores_fat32_long_filename() {
    let image = fat32_image(false);
    let explorer = Explorer::parse(&image).unwrap();
    let inspection = explorer.inspect();
    assert_eq!(inspection.filesystem, FilesystemKind::Fat32);
    assert_eq!(inspection.label.as_deref(), Some("TEST"));

    let entries = explorer.list("/").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "Long Name.txt");
    assert_eq!(explorer.read_file("/long name.txt").unwrap(), b"hello");
}

#[test]
fn rejects_a_cyclic_fat32_file_chain() {
    let image = fat32_image(true);
    let error = Explorer::parse(&image)
        .unwrap()
        .read_file("/Long Name.txt")
        .unwrap_err();
    assert!(matches!(error, Error::Corrupt("cyclic FAT32 file chain")));
}

#[test]
fn rejects_parent_path_components() {
    let image = legacy_xenith_image();
    let error = Explorer::parse(&image).unwrap().list("/../").unwrap_err();
    assert!(matches!(error, Error::InvalidPath(_)));
}

fn legacy_xenith_image() -> Vec<u8> {
    const BLOCKS: u64 = 2048;
    const BITMAP_START: u64 = 1;
    const BITMAP_BLOCKS: u64 = 1;
    const INODE_START: u64 = 2;
    const INODE_BLOCKS: u64 = 8;
    const DATA_START: u64 = 10;
    const ROOT_BLOCK: u64 = DATA_START;
    let mut image = vec![0u8; BLOCKS as usize * BLOCK_SIZE];
    image[..8].copy_from_slice(b"XENITHFS");
    put_u32(&mut image, 8, 1);
    put_u32(&mut image, 12, BLOCK_SIZE as u32);
    put_u64(&mut image, 16, BLOCKS);
    put_u64(&mut image, 24, BITMAP_START);
    put_u64(&mut image, 32, BITMAP_BLOCKS);
    put_u64(&mut image, 40, INODE_START);
    put_u64(&mut image, 48, INODE_BLOCKS);
    put_u64(&mut image, 56, DATA_START);
    put_u64(&mut image, 64, 128);
    put_u64(&mut image, 72, 1);
    image[80] = 4;
    image[81..85].copy_from_slice(b"TEST");

    let root_inode = INODE_START as usize * BLOCK_SIZE;
    put_u16(&mut image, root_inode, 0o040755);
    put_u16(&mut image, root_inode + 2, 2);
    put_u64(&mut image, root_inode + 16, BLOCK_SIZE as u64);
    put_u64(&mut image, root_inode + 24, 1);
    put_u64(&mut image, root_inode + 32, ROOT_BLOCK);
    put_u32(&mut image, root_inode + 40, 1);

    let root = ROOT_BLOCK as usize * BLOCK_SIZE;
    write_legacy_dirent(&mut image, root, 1, 2, ".");
    write_legacy_dirent(&mut image, root + 256, 1, 2, "..");

    let inode = INODE_START as usize * BLOCK_SIZE + 256;
    put_u16(&mut image, inode, 0o100644);
    put_u16(&mut image, inode + 2, 1);
    put_u64(&mut image, inode + 16, 5);
    put_u64(&mut image, inode + 24, 1);
    put_u64(&mut image, inode + 32, ROOT_BLOCK + 1);
    put_u32(&mut image, inode + 40, 1);

    write_legacy_dirent(&mut image, root + 2 * 256, 2, 1, "hello.txt");
    let data = (ROOT_BLOCK + 1) as usize * BLOCK_SIZE;
    image[data..data + 5].copy_from_slice(b"hello");

    for block in 0..=ROOT_BLOCK + 1 {
        let bitmap = BITMAP_START as usize * BLOCK_SIZE + (block / 8) as usize;
        image[bitmap] |= 1 << (block % 8);
    }
    let checksum = crc32(&image[..BLOCK_SIZE - 4]);
    put_u32(&mut image, BLOCK_SIZE - 4, checksum);
    image
}

fn write_legacy_dirent(image: &mut [u8], offset: usize, inode: u64, kind: u8, name: &str) {
    put_u64(image, offset, inode);
    image[offset + 8] = kind;
    image[offset + 9] = name.len() as u8;
    image[offset + 16..offset + 16 + name.len()].copy_from_slice(name.as_bytes());
}

fn modern_xenith_image() -> Vec<u8> {
    let mut image = vec![0u8; 64 * BLOCK_SIZE];
    image[..8].copy_from_slice(b"XENITHFS");
    put_u32(&mut image, 8, 1);
    put_u32(&mut image, 12, BLOCK_SIZE as u32);
    put_u64(&mut image, 16, 64);
    put_u64(&mut image, 24, 1);
    put_u64(&mut image, 32, 16);
    put_u64(&mut image, 40, 2);
    put_u32(&mut image, 48, 1);
    put_u64(&mut image, 52, 5);
    put_u64(&mut image, 60, 1);
    put_u64(&mut image, 68, 3);
    put_u32(&mut image, 76, 2);
    put_u64(&mut image, 88, 1);

    write_modern_inode(&mut image, 1, 2, 32, 5);
    write_modern_inode(&mut image, 2, 1, 5, 6);

    let directory = 5 * BLOCK_SIZE;
    put_u64(&mut image, directory, 2);
    put_u16(&mut image, directory + 8, 32);
    image[directory + 10] = 9;
    image[directory + 11] = 1;
    image[directory + 16..directory + 25].copy_from_slice(b"hello.txt");
    let checksum = crc32(&image[directory..directory + 32]);
    put_u32(&mut image, directory + 12, checksum);
    image[6 * BLOCK_SIZE..6 * BLOCK_SIZE + 5].copy_from_slice(b"hello");

    let checksum = crc32(&image[..512]);
    put_u32(&mut image, 96, checksum);
    image
}

fn write_modern_inode(image: &mut [u8], number: u64, kind: u8, size: u64, block: u64) {
    let offset = BLOCK_SIZE + (number as usize - 1) * 256;
    put_u32(image, offset, 0x4f4e_4958);
    put_u16(image, offset + 4, 1);
    image[offset + 6] = kind;
    put_u64(image, offset + 8, number);
    put_u64(image, offset + 16, 1);
    put_u32(image, offset + 24, if kind == 2 { 0o755 } else { 0o644 });
    put_u32(image, offset + 36, if kind == 2 { 2 } else { 1 });
    put_u64(image, offset + 40, size);
    put_u16(image, offset + 72, 1);
    put_u64(image, offset + 80, 0);
    put_u64(image, offset + 88, block);
    put_u32(image, offset + 96, 1);
    let checksum = crc32(&image[offset..offset + 256]);
    put_u32(image, offset + 252, checksum);
}

fn fat32_image(cyclic: bool) -> Vec<u8> {
    let mut image = xenith_mkfs::format_fat32(33 * 1024 * 1024, "TEST").unwrap();
    let bytes_per_sector = u16_at(&image, 11) as usize;
    let reserved = u16_at(&image, 14) as usize;
    let fat_count = image[16] as usize;
    let fat_sectors = u32_at(&image, 36) as usize;
    let sectors_per_cluster = image[13] as usize;
    let cluster_size = bytes_per_sector * sectors_per_cluster;
    let data = (reserved + fat_count * fat_sectors) * bytes_per_sector;

    let short_name = *b"LONGNA~1TXT";
    let mut lfn = [0xffu8; 32];
    lfn[0] = 0x41;
    lfn[11] = 0x0f;
    lfn[12] = 0;
    lfn[13] = short_checksum(&short_name);
    lfn[26] = 0;
    lfn[27] = 0;
    let units: Vec<u16> = "Long Name.txt".encode_utf16().collect();
    let offsets = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    for (offset, unit) in offsets.into_iter().zip(units) {
        lfn[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    image[data..data + 32].copy_from_slice(&lfn);
    let short = data + 32;
    image[short..short + 11].copy_from_slice(&short_name);
    image[short + 11] = 0x20;
    put_u16(&mut image, short + 26, 3);
    put_u32(
        &mut image,
        short + 28,
        if cyclic { (cluster_size + 1) as u32 } else { 5 },
    );
    image[data + 64] = 0;

    for fat_index in 0..fat_count {
        let fat = (reserved + fat_index * fat_sectors) * bytes_per_sector;
        put_u32(
            &mut image,
            fat + 3 * 4,
            if cyclic { 3 } else { 0x0fff_ffff },
        );
    }
    image[data + cluster_size..data + cluster_size + 5].copy_from_slice(b"hello");
    image
}

fn short_checksum(name: &[u8]) -> u8 {
    name.iter()
        .fold(0u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
