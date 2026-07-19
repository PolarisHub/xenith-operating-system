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
}

const LABEL_COUNT: usize = 6;

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
/// It uses EDD packet reads, validates the `XENITHIM` magic at LBA 1, and loads the
/// first manifest entry to physical `0x8000`. The one-call BIOS transfer is deliberately
/// bounded to 127 sectors; the image builder enforces the same limit.
pub fn build_boot_sector() -> Result<[u8; BOOT_SECTOR_SIZE], BuildError> {
    let mut code = Encoder::new();
    code.bytes(&[
        0xfa, // cli
        0x31, 0xc0, // xor ax, ax
        0x8e, 0xd8, // mov ds, ax
        0x8e, 0xc0, // mov es, ax
        0x8e, 0xd0, // mov ss, ax
        0xbc, 0x00, 0x7c, // mov sp, 0x7c00
        0xfb, // sti
        0x88, 0x16, // mov [drive], dl
    ]);
    code.abs16(Label::Drive);

    // Require INT 13h extensions before relying on the 64-bit DAP LBA.
    code.bytes(&[0xbb, 0xaa, 0x55, 0xb4, 0x41, 0xcd, 0x13]);
    code.jcc16(0x82, Label::Fail); // jc
    code.bytes(&[0x81, 0xfb, 0x55, 0xaa]);
    code.jcc16(0x85, Label::Fail); // jne
    code.bytes(&[0xf7, 0xc1, 0x01, 0x00]);
    code.jcc16(0x84, Label::Fail); // jz

    // The DAP initially describes one sector from LBA 1 into 0000:0600.
    code.bytes(&[0xbe]);
    code.abs16(Label::Dap);
    code.bytes(&[0x8a, 0x16]);
    code.abs16(Label::Drive);
    code.bytes(&[0xb4, 0x42, 0xcd, 0x13]);
    code.jcc16(0x82, Label::Fail);

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
    code.bytes(&[0x66, 0x3d, 0x7f, 0x00, 0x00, 0x00]);
    code.jcc16(0x87, Label::Fail); // ja
    code.bytes(&[0x66, 0x83, 0x3e, 0x54, 0x06, 0x00]);
    code.jcc16(0x85, Label::Fail);

    code.bytes(&[0xa1, 0x50, 0x06, 0xa3]);
    code.abs16_offset(Label::Dap, 2);
    // Copy the manifest's 64-bit start_lba into DAP+8, one word at a time.
    for word in 0..4_u16 {
        let source = 0x0648_u16 + word * 2;
        code.bytes(&[0xa1]);
        code.bytes(&source.to_le_bytes());
        code.bytes(&[0xa3]);
        code.abs16_offset(Label::Dap, 8 + word * 2);
    }
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
    code.jcc16(0x82, Label::Fail);
    code.bytes(&[0xea, 0x00, 0x80, 0x00, 0x00]); // jmp 0000:8000

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

    while !code.bytes.len().is_multiple_of(16) {
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
    code.label(Label::Message);
    code.bytes(b"Xenith: disk boot failed\r\n\0");

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
            .windows(b"Xenith: disk boot failed".len())
            .any(|window| window == b"Xenith: disk boot failed"));
    }

    #[test]
    fn build_is_deterministic() {
        assert_eq!(build_boot_sector().unwrap(), build_boot_sector().unwrap());
    }
}
