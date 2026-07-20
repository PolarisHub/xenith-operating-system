//! Deterministic PE32+ AMD64 console fixture used by conformance gates.
//!
//! The fixture contains real machine code which calls the bootstrap
//! `KERNEL32.dll!GetStdHandle`, `KERNEL32.dll!WriteFile`, and
//! `KERNEL32.dll!ExitProcess` imports. Keeping the constructor in source makes
//! the image reproducible and reviewable without committing an opaque
//! generated executable.

use xenith_pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, RELOCATION_TYPE_DIR64,
};

// Xenith user ELFs begin at 0x20_0000. Deliberately preferring that occupied
// address forces the booted conformance image through the checked rebase path.
const IMAGE_BASE: u64 = 0x0000_0000_0020_0000;
const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const OPTIONAL_SIZE: usize = 240;
const SECTION_TABLE_OFFSET: usize = OPTIONAL_OFFSET + OPTIONAL_SIZE;
const DIRECTORY_TABLE: usize = OPTIONAL_OFFSET + 112;
const IMAGE_SIZE: usize = 0x4000;
const IAT_GET_STD_HANDLE: u32 = 0x2180;
const IAT_WRITE_FILE: u32 = 0x2188;
const IAT_EXIT_PROCESS: u32 = 0x2190;
const RELOCATION_TARGET: u32 = 0x3010;
const MESSAGE_RVA: u32 = 0x2250;
const WRITTEN_RVA: u32 = 0x3018;

/// Exact file size of [`console_fixture`].
pub const CONSOLE_FIXTURE_SIZE: usize = 0xc00;

/// Preferred image base, chosen to collide with the Xenith host ELF.
pub const CONSOLE_FIXTURE_IMAGE_BASE: u64 = IMAGE_BASE;

/// Exact line emitted by the fixture through `KERNEL32.dll!WriteFile`.
pub const CONSOLE_FIXTURE_MESSAGE: &[u8] = b"Xenith Win64 fixture\r\n";

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn section(
    bytes: &mut [u8],
    index: usize,
    name: &[u8],
    virtual_layout: (u32, u32),
    file_layout: (u32, u32),
    characteristics: u32,
) {
    let offset = SECTION_TABLE_OFFSET + index * 40;
    bytes[offset..offset + name.len()].copy_from_slice(name);
    put_u32(bytes, offset + 8, virtual_layout.0);
    put_u32(bytes, offset + 12, virtual_layout.1);
    put_u32(bytes, offset + 16, file_layout.0);
    put_u32(bytes, offset + 20, file_layout.1);
    put_u32(bytes, offset + 36, characteristics);
}

fn directory(bytes: &mut [u8], index: usize, address: u32, size: u32) {
    let offset = DIRECTORY_TABLE + index * 8;
    put_u32(bytes, offset, address);
    put_u32(bytes, offset + 4, size);
}

#[allow(clippy::panic)] // An invalid RVA is a fixture-construction bug.
fn file_offset(rva: u32) -> usize {
    match rva {
        0x0000..=0x01ff => rva as usize,
        0x1000..=0x11ff => 0x200 + (rva - 0x1000) as usize,
        0x2000..=0x25ff => 0x400 + (rva - 0x2000) as usize,
        0x3000..=0x31ff => 0xa00 + (rva - 0x3000) as usize,
        _ => panic!("fixture RVA is not file-backed: {rva:#x}"),
    }
}

fn put_rva_u16(bytes: &mut [u8], rva: u32, value: u16) {
    put_u16(bytes, file_offset(rva), value);
}

fn put_rva_u32(bytes: &mut [u8], rva: u32, value: u32) {
    put_u32(bytes, file_offset(rva), value);
}

fn put_rva_u64(bytes: &mut [u8], rva: u32, value: u64) {
    put_u64(bytes, file_offset(rva), value);
}

fn put_rva_bytes(bytes: &mut [u8], rva: u32, value: &[u8]) {
    let offset = file_offset(rva);
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

/// Build the deterministic Win64 console executable used by tests and images.
#[must_use]
pub fn console_fixture() -> [u8; CONSOLE_FIXTURE_SIZE] {
    let mut bytes = [0u8; CONSOLE_FIXTURE_SIZE];
    put_u16(&mut bytes, 0, 0x5a4d);
    put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
    put_u32(&mut bytes, PE_OFFSET, 0x0000_4550);
    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 3);
    put_u16(&mut bytes, COFF_OFFSET + 16, OPTIONAL_SIZE as u16);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x0022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 4, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 8, 0x800);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 20, 0x1000);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 24, IMAGE_BASE);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 40, 6);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 48, 6);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, IMAGE_SIZE as u32);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 72, 0x10_0000);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 80, 0x1000);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 88, 0x10_0000);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 96, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);

    section(
        &mut bytes,
        0,
        b".text",
        (0x180, 0x1000),
        (0x200, 0x200),
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | 0x20,
    );
    section(
        &mut bytes,
        1,
        b".rdata",
        (0x600, 0x2000),
        (0x600, 0x400),
        IMAGE_SCN_MEM_READ | 0x40,
    );
    section(
        &mut bytes,
        2,
        b".data",
        (0x200, 0x3000),
        (0x200, 0xa00),
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
    );

    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x2000, 40);
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x2300, 12);
    directory(&mut bytes, 12, IAT_GET_STD_HANDLE, 32);

    // One KERNEL32 descriptor followed by its all-zero terminator.
    put_rva_u32(&mut bytes, 0x2000, 0x2100);
    put_rva_u32(&mut bytes, 0x200c, 0x2080);
    put_rva_u32(&mut bytes, 0x2010, IAT_GET_STD_HANDLE);
    put_rva_bytes(&mut bytes, 0x2080, b"KERNEL32.dll\0");
    put_rva_u64(&mut bytes, 0x2100, 0x2200);
    put_rva_u64(&mut bytes, 0x2108, 0x2220);
    put_rva_u64(&mut bytes, 0x2110, 0x2240);
    put_rva_u64(&mut bytes, 0x2118, 0);
    put_rva_u64(&mut bytes, IAT_GET_STD_HANDLE, 0x2200);
    put_rva_u64(&mut bytes, IAT_WRITE_FILE, 0x2220);
    put_rva_u64(&mut bytes, IAT_EXIT_PROCESS, 0x2240);
    put_rva_u64(&mut bytes, 0x2198, 0);
    put_rva_u16(&mut bytes, 0x2200, 0);
    put_rva_bytes(&mut bytes, 0x2202, b"GetStdHandle\0");
    put_rva_u16(&mut bytes, 0x2220, 0);
    put_rva_bytes(&mut bytes, 0x2222, b"WriteFile\0");
    put_rva_u16(&mut bytes, 0x2240, 0);
    put_rva_bytes(&mut bytes, 0x2242, b"ExitProcess\0");
    put_rva_bytes(&mut bytes, MESSAGE_RVA, CONSOLE_FIXTURE_MESSAGE);

    put_rva_u32(&mut bytes, 0x2300, 0x3000);
    put_rva_u32(&mut bytes, 0x2304, 12);
    put_rva_u16(
        &mut bytes,
        0x2308,
        (u16::from(RELOCATION_TYPE_DIR64) << 12) | 0x10,
    );
    put_rva_u16(&mut bytes, 0x230a, 0);
    // Entry code compares this relocated absolute pointer with a RIP-relative
    // address of the same message before it calls any shim. The success line
    // is therefore unreachable unless the runtime applies the DIR64 patch.
    put_rva_u64(
        &mut bytes,
        RELOCATION_TARGET,
        IMAGE_BASE + u64::from(MESSAGE_RVA),
    );

    // Real entry code: verify the relocated message pointer, GetStdHandle(-11),
    // WriteFile(handle, message, len, &written, NULL), then ExitProcess(0).
    // All calls are RIP-relative through the fixture IAT.
    let text = file_offset(0x1000);
    bytes[text..text + 4].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]);
    bytes[text + 4..text + 7].copy_from_slice(&[0x48, 0x8b, 0x05]);
    put_i32(&mut bytes, text + 7, RELOCATION_TARGET as i32 - 0x100b_i32);
    bytes[text + 11..text + 14].copy_from_slice(&[0x48, 0x8d, 0x15]);
    put_i32(&mut bytes, text + 14, MESSAGE_RVA as i32 - 0x1012_i32);
    bytes[text + 18..text + 21].copy_from_slice(&[0x48, 0x39, 0xd0]);
    bytes[text + 21..text + 23].copy_from_slice(&[0x75, 0x3a]);
    bytes[text + 23..text + 28].copy_from_slice(&[0xb9, 0xf5, 0xff, 0xff, 0xff]);
    bytes[text + 28..text + 30].copy_from_slice(&[0xff, 0x15]);
    put_i32(
        &mut bytes,
        text + 30,
        IAT_GET_STD_HANDLE as i32 - 0x1022_i32,
    );
    bytes[text + 34..text + 37].copy_from_slice(&[0x48, 0x89, 0xc1]);
    bytes[text + 37..text + 40].copy_from_slice(&[0x48, 0x8d, 0x15]);
    put_i32(&mut bytes, text + 40, MESSAGE_RVA as i32 - 0x102c_i32);
    bytes[text + 44..text + 46].copy_from_slice(&[0x41, 0xb8]);
    put_u32(&mut bytes, text + 46, CONSOLE_FIXTURE_MESSAGE.len() as u32);
    bytes[text + 50..text + 53].copy_from_slice(&[0x4c, 0x8d, 0x0d]);
    put_i32(&mut bytes, text + 53, WRITTEN_RVA as i32 - 0x1039_i32);
    bytes[text + 57..text + 66].copy_from_slice(&[0x48, 0xc7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
    bytes[text + 66..text + 68].copy_from_slice(&[0xff, 0x15]);
    put_i32(&mut bytes, text + 68, IAT_WRITE_FILE as i32 - 0x1048_i32);
    bytes[text + 72..text + 74].copy_from_slice(&[0x31, 0xc9]);
    bytes[text + 74..text + 76].copy_from_slice(&[0xff, 0x15]);
    put_i32(&mut bytes, text + 76, IAT_EXIT_PROCESS as i32 - 0x1050_i32);
    bytes[text + 80] = 0xcc;
    bytes[text + 81..text + 86].copy_from_slice(&[0xb9, 0x55, 0, 0, 0]);
    bytes[text + 86..text + 88].copy_from_slice(&[0xff, 0x15]);
    put_i32(&mut bytes, text + 88, IAT_EXIT_PROCESS as i32 - 0x105c_i32);
    bytes[text + 92] = 0xcc;
    bytes
}
