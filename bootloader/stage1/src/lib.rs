//! A tiny purpose-built encoder keeps the MBR reproducible without NASM or GAS.

use std::fmt;

pub const BOOT_SECTOR_SIZE: usize = 512;
pub const PARTITION_TABLE_OFFSET: usize = 446;
pub const BOOT_SIGNATURE_OFFSET: usize = 510;
pub const LOAD_ADDRESS: u16 = 0x8000;
pub const MANIFEST_BUFFER: u16 = 0x0600;

const ORIGIN: u16 = 0x7c00;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
enum Label {
    Fail = 0,
    Print = 1,
    Hang = 2,
    Dap = 3,
    Drive = 4,
    Message = 5,
    ChsSetup = 6,
    DiskReady = 7,
    ChsManifest = 8,
    ManifestLoaded = 9,
    ChsStage2 = 10,
    Transfer = 11,
    ChsRead = 12,
    ChsLoop = 13,
    ChsReadFail = 14,
    DiskMode = 15,
    SectorsPerTrack = 16,
    HeadCount = 17,
}

const LABEL_COUNT: usize = 18;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    CodeTooLarge(usize),
    MissingLabel(&'static str),
    RelativeBranchOutOfRange,
    AddressOverflow,
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CodeTooLarge(size) => write!(formatter, "stage1 is {size} bytes before padding"),
            Self::MissingLabel(label) => write!(formatter, "missing stage1 label {label}"),
            Self::RelativeBranchOutOfRange => {
                formatter.write_str("stage1 branch exceeds rel8 range")
            },
            Self::AddressOverflow => formatter.write_str("stage1 absolute address exceeds 16 bits"),
        }
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Copy)]
enum FixupKind {
    Absolute16,
    Relative8,
    Relative16,
}

#[derive(Clone, Copy)]
struct Fixup {
    offset: usize,
    label: Label,
    kind: FixupKind,
    addend: u16,
}

struct Encoder {
    bytes: Vec<u8>,
    labels: [Option<usize>; LABEL_COUNT],
    fixups: Vec<Fixup>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(BOOT_SECTOR_SIZE),
            labels: [None; LABEL_COUNT],
            fixups: Vec::new(),
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn label(&mut self, label: Label) {
        self.labels[label as usize] = Some(self.bytes.len());
    }

    fn abs16(&mut self, label: Label) {
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(&[0, 0]);
        self.fixups.push(Fixup {
            offset,
            label,
            kind: FixupKind::Absolute16,
            addend: 0,
        });
    }

    fn rel8(&mut self, opcode: u8, label: Label) {
        self.bytes.push(opcode);
        let offset = self.bytes.len();
        self.bytes.push(0);
        self.fixups.push(Fixup {
            offset,
            label,
            kind: FixupKind::Relative8,
            addend: 0,
        });
    }

    fn jcc16(&mut self, opcode: u8, label: Label) {
        self.bytes.extend_from_slice(&[0x0f, opcode]);
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(&[0, 0]);
        self.fixups.push(Fixup {
            offset,
            label,
            kind: FixupKind::Relative16,
            addend: 0,
        });
    }

    fn jump16(&mut self, label: Label) {
        self.bytes.push(0xe9);
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(&[0, 0]);
        self.fixups.push(Fixup {
            offset,
            label,
            kind: FixupKind::Relative16,
            addend: 0,
        });
    }

    fn call16(&mut self, label: Label) {
        self.bytes.push(0xe8);
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(&[0, 0]);
        self.fixups.push(Fixup {
            offset,
            label,
            kind: FixupKind::Relative16,
            addend: 0,
        });
    }

    fn resolve(mut self) -> Result<Vec<u8>, BuildError> {
        for fixup in self.fixups {
            let target = self.labels[fixup.label as usize]
                .ok_or(BuildError::MissingLabel(label_name(fixup.label)))?;
            match fixup.kind {
                FixupKind::Absolute16 => {
                    let address = usize::from(ORIGIN)
                        .checked_add(target)
                        .and_then(|value| value.checked_add(usize::from(fixup.addend)))
                        .ok_or(BuildError::AddressOverflow)?;
                    let address =
                        u16::try_from(address).map_err(|_| BuildError::AddressOverflow)?;
                    self.bytes[fixup.offset..fixup.offset + 2]
                        .copy_from_slice(&address.to_le_bytes());
                },
                FixupKind::Relative8 => {
                    let next = fixup.offset + 1;
                    let displacement =
                        isize::try_from(target).unwrap() - isize::try_from(next).unwrap();
                    let displacement = i8::try_from(displacement)
                        .map_err(|_| BuildError::RelativeBranchOutOfRange)?;
                    self.bytes[fixup.offset] = displacement as u8;
                },
                FixupKind::Relative16 => {
                    let next = fixup.offset + 2;
                    let displacement =
                        isize::try_from(target).unwrap() - isize::try_from(next).unwrap();
                    let displacement = i16::try_from(displacement)
                        .map_err(|_| BuildError::RelativeBranchOutOfRange)?;
                    self.bytes[fixup.offset..fixup.offset + 2]
                        .copy_from_slice(&displacement.to_le_bytes());
                },
            }
        }
        Ok(self.bytes)
    }
}

/// Build the exact sector installed at raw-disk LBA 0.
///
/// It prefers EDD packet reads and falls back to geometry-validated CHS reads, validates
/// the `XENITHIM` magic at LBA 1, and loads the first manifest entry to physical `0x8000`.
/// The transfer is bounded to 64 sectors so it ends at, but never crosses, the 64-KiB DMA
/// boundary at physical `0x10000`; the image builder enforces the same limit.
pub fn build_boot_sector() -> Result<[u8; BOOT_SECTOR_SIZE], BuildError> {
    let mut code = Encoder::new();
    code.bytes(&[
        0xfa, // cli
        0x31, 0xc0, // xor ax, ax
        0x8e, 0xd8, // mov ds, ax
        0x8e, 0xc0, // mov es, ax
        0x8e, 0xd0, // mov ss, ax
        0xbc, 0x00, 0x7c, // mov sp, 0x7c00
        0xfc, // cld
        0xfb, // sti
        0x88, 0x16, // mov [drive], dl
    ]);
    code.abs16(Label::Drive);

    // Prefer INT 13h extensions, but El Torito hard-disk emulation on older
    // firmware may expose only the original CHS interface.
    code.bytes(&[0xbb, 0xaa, 0x55, 0xb4, 0x41, 0xcd, 0x13]);
    code.jcc16(0x82, Label::ChsSetup); // jc
    code.bytes(&[0x81, 0xfb, 0x55, 0xaa]);
    code.jcc16(0x85, Label::ChsSetup); // jne
    code.bytes(&[0xf7, 0xc1, 0x01, 0x00]);
    code.jcc16(0x84, Label::ChsSetup); // jz
    code.bytes(&[0xc6, 0x06]);
    code.abs16(Label::DiskMode);
    code.bytes(&[1]);
    code.jump16(Label::DiskReady);

    code.label(Label::ChsSetup);
    code.bytes(&[0xc6, 0x06]);
    code.abs16(Label::DiskMode);
    code.bytes(&[0]);
    code.bytes(&[0x8a, 0x16]);
    code.abs16(Label::Drive);
    code.bytes(&[0xb4, 0x08, 0xcd, 0x13]);
    code.jcc16(0x82, Label::Fail);
    code.bytes(&[0x88, 0xc8, 0x24, 0x3f]); // mov al, cl; and al, 63
    code.jcc16(0x84, Label::Fail);
    code.bytes(&[0xa2]);
    code.abs16(Label::SectorsPerTrack);
    code.bytes(&[0x31, 0xc0, 0x88, 0xf0, 0x40]); // xor ax, ax; mov al, dh; inc ax
    code.bytes(&[0xa3]);
    code.abs16(Label::HeadCount);

    code.label(Label::DiskReady);
    code.bytes(&[0x80, 0x3e]);
    code.abs16(Label::DiskMode);
    code.bytes(&[1]);
    code.jcc16(0x85, Label::ChsManifest);

    // The DAP initially describes one sector from LBA 1 into 0000:0600.
    code.bytes(&[0xbe]);
    code.abs16(Label::Dap);
    code.bytes(&[0x8a, 0x16]);
    code.abs16(Label::Drive);
    code.bytes(&[0xb4, 0x42, 0xcd, 0x13]);
    code.jcc16(0x82, Label::ChsSetup);
    code.jump16(Label::ManifestLoaded);

    code.label(Label::ChsManifest);
    code.bytes(&[
        0x31, 0xc0, // xor ax, ax
        0x8e, 0xc0, // mov es, ax
        0xb8, 0x01, 0x00, // mov ax, 1
        0xb9, 0x01, 0x00, // mov cx, 1
        0xbb, 0x00, 0x06, // mov bx, 0x600
    ]);
    code.call16(Label::ChsRead);
    code.jcc16(0x82, Label::Fail);

    code.label(Label::ManifestLoaded);

    // Compare the two little-endian dwords spelling XENITHIM.
    code.bytes(&[0x66, 0x81, 0x3e, 0x00, 0x06, 0x58, 0x45, 0x4e, 0x49]);
    code.jcc16(0x85, Label::Fail);
    code.bytes(&[0x66, 0x81, 0x3e, 0x04, 0x06, 0x54, 0x48, 0x49, 0x4d]);
    code.jcc16(0x85, Label::Fail);
    // Entry zero at offset 64 must be the stage2 kind.
    code.bytes(&[0x66, 0x83, 0x3e, 0x40, 0x06, 0x01]);
    code.jcc16(0x85, Label::Fail);

    // sector_count is a u64 at 0600+64+16. The BIOS DAP count is a u16.
    code.bytes(&[0x66, 0xa1, 0x50, 0x06, 0x66, 0x85, 0xc0]);
    code.jcc16(0x84, Label::Fail);
    code.bytes(&[0x66, 0x3d, 0x40, 0x00, 0x00, 0x00]);
    code.jcc16(0x87, Label::Fail); // ja
    code.bytes(&[0x66, 0x83, 0x3e, 0x54, 0x06, 0x00]);
    code.jcc16(0x85, Label::Fail);

    code.bytes(&[0x80, 0x3e]);
    code.abs16(Label::DiskMode);
    code.bytes(&[1]);
    code.jcc16(0x85, Label::ChsStage2);

    code.bytes(&[0xa1, 0x50, 0x06, 0xa3]);
    code.abs16_offset(Label::Dap, 2);
    // The raw-image contract fixes stage2 at LBA 2; stage2 later validates the
    // checksummed manifest before trusting any other payload extent.
    code.bytes(&[0xc7, 0x06]);
    code.abs16_offset(Label::Dap, 8);
    code.bytes(&[0x02, 0x00]);
    code.bytes(&[0xc7, 0x06]);
    code.abs16_offset(Label::Dap, 4);
    code.bytes(&[0x00, 0x00]);
    code.bytes(&[0xc7, 0x06]);
    code.abs16_offset(Label::Dap, 6);
    code.bytes(&(LOAD_ADDRESS >> 4).to_le_bytes());
    code.bytes(&[0xbe]);
    code.abs16(Label::Dap);
    code.bytes(&[0x8a, 0x16]);
    code.abs16(Label::Drive);
    code.bytes(&[0xb4, 0x42, 0xcd, 0x13]);
    code.jcc16(0x82, Label::ChsSetup);
    code.jump16(Label::Transfer);

    code.label(Label::ChsStage2);
    code.bytes(&[
        0xb8, 0x00, 0x08, // mov ax, 0x800
        0x8e, 0xc0, // mov es, ax
        0x31, 0xdb, // xor bx, bx
        0xb8, 0x02, 0x00, // mov ax, 2
        0x8b, 0x0e, 0x50, 0x06, // mov cx, [0x650]
    ]);
    code.call16(Label::ChsRead);
    code.jcc16(0x82, Label::Fail);

    code.label(Label::Transfer);
    code.bytes(&[0x31, 0xc0, 0x8e, 0xc0]); // xor ax, ax; mov es, ax
    code.bytes(&[0x8a, 0x16]);
    code.abs16(Label::Drive);
    code.bytes(&[0xea, 0x00, 0x80, 0x00, 0x00]); // jmp 0000:8000

    // AX=LBA, CX=count, ES:BX=destination. One-sector reads cannot cross a
    // track or a 64-KiB DMA boundary; stage2 is capped at 64 sectors.
    code.label(Label::ChsRead);
    code.bytes(&[
        0x89, 0xc6, // mov si, ax
        0x89, 0xcf, // mov di, cx
    ]);
    code.label(Label::ChsLoop);
    code.bytes(&[
        0x89, 0xf0, // mov ax, si
        0x31, 0xd2, // xor dx, dx
        0x0f, 0xb6, 0x0e, // movzx cx, byte [spt]
    ]);
    code.abs16(Label::SectorsPerTrack);
    code.bytes(&[
        0xf7, 0xf1, // div cx
        0xfe, 0xc2, // inc dl
        0x88, 0xd1, // mov cl, dl
        0x31, 0xd2, // xor dx, dx
        0x8b, 0x2e, // mov bp, word [heads]
    ]);
    code.abs16(Label::HeadCount);
    code.bytes(&[0xf7, 0xf5, 0x3d, 0xff, 0x03]); // div bp; cmp ax, 1023
    code.jcc16(0x87, Label::ChsReadFail);
    code.bytes(&[
        0x88, 0xd6, // mov dh, dl
        0x88, 0xc5, // mov ch, al
        0xc1, 0xe8, 0x02, // shr ax, 2
        0x24, 0xc0, // and al, 0xc0
        0x08, 0xc1, // or cl, al
        0xb8, 0x01, 0x02, // mov ax, 0x0201
        0x8a, 0x16, // mov dl, [drive]
    ]);
    code.abs16(Label::Drive);
    code.bytes(&[0xcd, 0x13]);
    code.jcc16(0x82, Label::ChsReadFail);
    code.bytes(&[
        0x81, 0xc3, 0x00, 0x02, // add bx, 512
        0x46, // inc si
        0x4f, // dec di
    ]);
    code.rel8(0x75, Label::ChsLoop);
    code.bytes(&[0xf8, 0xc3]); // clc; ret
    code.label(Label::ChsReadFail);
    code.bytes(&[0xf9, 0xc3]); // stc; ret

    code.label(Label::Fail);
    code.bytes(&[0xbe]);
    code.abs16(Label::Message);
    code.label(Label::Print);
    code.bytes(&[0xac, 0x84, 0xc0]);
    code.rel8(0x74, Label::Hang);
    code.bytes(&[0xb4, 0x0e, 0xbb, 0x07, 0x00, 0xcd, 0x10]);
    code.rel8(0xeb, Label::Print);
    code.label(Label::Hang);
    code.bytes(&[0xfa, 0xf4]);
    code.rel8(0xeb, Label::Hang);

    while !code.bytes.len().is_multiple_of(4) {
        code.bytes.push(0);
    }
    code.label(Label::Dap);
    code.bytes(&[
        0x10, 0x00, // packet size, reserved
        0x01, 0x00, // sector count
        0x00, 0x06, // destination offset
        0x00, 0x00, // destination segment
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // LBA 1
    ]);
    code.label(Label::Drive);
    code.bytes(&[0]);
    code.label(Label::DiskMode);
    code.bytes(&[0]);
    code.label(Label::SectorsPerTrack);
    code.bytes(&[0]);
    code.label(Label::HeadCount);
    code.bytes(&[0, 0]);
    code.label(Label::Message);
    code.bytes(b"Xenith: boot failed\r\n\0");

    let code = code.resolve()?;
    if code.len() > PARTITION_TABLE_OFFSET {
        return Err(BuildError::CodeTooLarge(code.len()));
    }
    let mut sector = [0_u8; BOOT_SECTOR_SIZE];
    sector[..code.len()].copy_from_slice(&code);
    sector[BOOT_SIGNATURE_OFFSET..].copy_from_slice(&[0x55, 0xaa]);
    Ok(sector)
}

impl Encoder {
    fn abs16_offset(&mut self, label: Label, addend: u16) {
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(&addend.to_le_bytes());
        self.fixups.push(Fixup {
            offset,
            label,
            kind: FixupKind::Absolute16,
            addend,
        });
    }
}

fn label_name(label: Label) -> &'static str {
    match label {
        Label::Fail => "fail",
        Label::Print => "print",
        Label::Hang => "hang",
        Label::Dap => "dap",
        Label::Drive => "drive",
        Label::Message => "message",
        Label::ChsSetup => "chs setup",
        Label::DiskReady => "disk ready",
        Label::ChsManifest => "CHS manifest read",
        Label::ManifestLoaded => "manifest loaded",
        Label::ChsStage2 => "CHS stage2 read",
        Label::Transfer => "stage2 transfer",
        Label::ChsRead => "CHS read",
        Label::ChsLoop => "CHS loop",
        Label::ChsReadFail => "CHS read failure",
        Label::DiskMode => "disk mode",
        Label::SectorsPerTrack => "sectors per track",
        Label::HeadCount => "head count",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_an_exact_boot_sector() {
        let sector = build_boot_sector().unwrap();
        assert_eq!(sector.len(), 512);
        assert_eq!(&sector[510..], &[0x55, 0xaa]);
        assert_eq!(sector[0], 0xfa);
        assert!(sector[PARTITION_TABLE_OFFSET..BOOT_SIGNATURE_OFFSET]
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn embeds_the_manifest_contract_and_failure_text() {
        let sector = build_boot_sector().unwrap();
        assert!(sector.windows(4).any(|window| window == b"XENI"));
        assert!(sector.windows(4).any(|window| window == b"THIM"));
        assert!(sector
            .windows(b"Xenith: boot failed".len())
            .any(|window| window == b"Xenith: boot failed"));
    }

    #[test]
    fn includes_chs_geometry_and_single_sector_fallback_without_debug_ports() {
        let sector = build_boot_sector().unwrap();
        assert!(sector
            .windows(4)
            .any(|window| window == [0xb4, 0x08, 0xcd, 0x13]));
        assert!(sector.windows(3).any(|window| window == [0xb8, 0x01, 0x02]));
        assert!(sector
            .windows(6)
            .any(|window| window == [0x66, 0x3d, 0x40, 0x00, 0x00, 0x00]));
        assert!(!sector.windows(2).any(|window| window == [0xe6, 0xe9]));
    }

    #[test]
    fn build_is_deterministic() {
        assert_eq!(build_boot_sector().unwrap(), build_boot_sector().unwrap());
    }
}
