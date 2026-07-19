//! Strict ELF64 symbol parsing plus an optional owned DWARF line index.

use std::collections::BTreeMap;
use std::path::Path;
use std::{fmt, fs};

use crate::{SourceLocation, SourceLookupError, SourceMap};

const ELF_HEADER_SIZE: usize = 64;
const SECTION_HEADER_SIZE: usize = 64;
const SYMBOL_SIZE: usize = 24;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;
const SHN_UNDEF: u16 = 0;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolKind {
    Unspecified,
    Object,
    Function,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub global: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SymbolTable {
    by_name: BTreeMap<String, Symbol>,
    by_address: Vec<Symbol>,
    sources: SourceMap,
    position_independent: bool,
    load_bias: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SymbolError {
    Io(String),
    Truncated,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedType,
    UnsupportedMachine,
    InvalidHeader,
    InvalidSection,
    InvalidString,
    Dwarf(String),
    AddressOverflow,
    NoSymbols,
}

impl fmt::Display for SymbolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Truncated => formatter.write_str("truncated ELF"),
            Self::BadMagic => formatter.write_str("not an ELF file"),
            Self::UnsupportedClass => formatter.write_str("ELF is not 64-bit"),
            Self::UnsupportedEndian => formatter.write_str("ELF is not little-endian"),
            Self::UnsupportedType => {
                formatter.write_str("ELF is neither an ET_EXEC nor ET_DYN image")
            },
            Self::UnsupportedMachine => formatter.write_str("ELF is not x86_64"),
            Self::InvalidHeader => formatter.write_str("invalid ELF header"),
            Self::InvalidSection => formatter.write_str("invalid ELF section table"),
            Self::InvalidString => formatter.write_str("invalid ELF symbol string"),
            Self::Dwarf(error) => write!(formatter, "invalid DWARF: {error}"),
            Self::AddressOverflow => formatter.write_str("load bias overflows an ELF address"),
            Self::NoSymbols => formatter.write_str("ELF has no defined symbols"),
        }
    }
}

impl std::error::Error for SymbolError {}

impl SymbolTable {
    pub fn from_symbols(symbols: impl IntoIterator<Item = Symbol>) -> Self {
        let mut by_name = BTreeMap::new();
        for symbol in symbols {
            by_name.insert(symbol.name.clone(), symbol);
        }
        let mut by_address: Vec<_> = by_name.values().cloned().collect();
        by_address.sort_by(|left, right| {
            left.address
                .cmp(&right.address)
                .then_with(|| left.name.cmp(&right.name))
        });
        Self {
            by_name,
            by_address,
            sources: SourceMap::default(),
            position_independent: false,
            load_bias: 0,
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, SymbolError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|error| SymbolError::Io(error.to_string()))?;
        let mut table = Self::parse(&bytes)?;
        table.sources =
            SourceMap::load(path).map_err(|error| SymbolError::Dwarf(error.to_string()))?;
        Ok(table)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, SymbolError> {
        let header = bytes.get(..ELF_HEADER_SIZE).ok_or(SymbolError::Truncated)?;
        if header.get(..4) != Some(b"\x7fELF") {
            return Err(SymbolError::BadMagic);
        }
        if header[4] != 2 {
            return Err(SymbolError::UnsupportedClass);
        }
        if header[5] != 1 {
            return Err(SymbolError::UnsupportedEndian);
        }
        let elf_type = read_u16(header, 16)?;
        if !matches!(elf_type, ET_EXEC | ET_DYN) {
            return Err(SymbolError::UnsupportedType);
        }
        if read_u16(header, 18)? != 62 {
            return Err(SymbolError::UnsupportedMachine);
        }
        let section_offset =
            usize::try_from(read_u64(header, 40)?).map_err(|_| SymbolError::InvalidHeader)?;
        let section_size = usize::from(read_u16(header, 58)?);
        let section_count = usize::from(read_u16(header, 60)?);
        if section_count == 0 || section_size < SECTION_HEADER_SIZE {
            return Err(SymbolError::NoSymbols);
        }
        let section_bytes = section_size
            .checked_mul(section_count)
            .ok_or(SymbolError::InvalidHeader)?;
        bytes
            .get(
                section_offset
                    ..section_offset
                        .checked_add(section_bytes)
                        .ok_or(SymbolError::InvalidHeader)?,
            )
            .ok_or(SymbolError::Truncated)?;

        let mut selected: BTreeMap<String, (Symbol, u8)> = BTreeMap::new();
        for index in 0..section_count {
            let symbol_section = section(bytes, section_offset, section_size, index)?;
            if !matches!(symbol_section.kind, SHT_SYMTAB | SHT_DYNSYM) {
                continue;
            }
            let string_index =
                usize::try_from(symbol_section.link).map_err(|_| SymbolError::InvalidSection)?;
            if string_index >= section_count {
                return Err(SymbolError::InvalidSection);
            }
            let strings = section(bytes, section_offset, section_size, string_index)?;
            if strings.kind != SHT_STRTAB {
                return Err(SymbolError::InvalidSection);
            }
            let string_bytes = range(bytes, strings.offset, strings.size)?;
            let entry_size = if symbol_section.entry_size == 0 {
                SYMBOL_SIZE
            } else {
                usize::try_from(symbol_section.entry_size)
                    .map_err(|_| SymbolError::InvalidSection)?
            };
            if entry_size < SYMBOL_SIZE || symbol_section.size % entry_size as u64 != 0 {
                return Err(SymbolError::InvalidSection);
            }
            let symbol_bytes = range(bytes, symbol_section.offset, symbol_section.size)?;
            for raw in symbol_bytes.chunks_exact(entry_size) {
                let name_offset =
                    usize::try_from(read_u32(raw, 0)?).map_err(|_| SymbolError::InvalidString)?;
                let info = *raw.get(4).ok_or(SymbolError::Truncated)?;
                let symbol_type = info & 0x0f;
                let binding = info >> 4;
                let section_index = read_u16(raw, 6)?;
                if name_offset == 0
                    || section_index == SHN_UNDEF
                    || usize::from(section_index) >= section_count
                    || !matches!(symbol_type, 0..=2)
                {
                    continue;
                }
                let name = read_string(string_bytes, name_offset)?.to_string();
                if name.is_empty() {
                    continue;
                }
                let symbol = Symbol {
                    name: name.clone(),
                    address: read_u64(raw, 8)?,
                    size: read_u64(raw, 16)?,
                    kind: match symbol_type {
                        1 => SymbolKind::Object,
                        2 => SymbolKind::Function,
                        _ => SymbolKind::Unspecified,
                    },
                    global: matches!(binding, 1 | 2),
                };
                let quality =
                    u8::from(symbol_section.kind == SHT_SYMTAB) * 2 + u8::from(symbol.global);
                match selected.get(&name) {
                    Some((_, current_quality)) if *current_quality > quality => {},
                    _ => {
                        selected.insert(name, (symbol, quality));
                    },
                }
            }
        }
        if selected.is_empty() {
            return Err(SymbolError::NoSymbols);
        }
        let symbols = selected
            .into_iter()
            .map(|(_, (symbol, _))| symbol)
            .collect::<Vec<_>>();
        let mut table = Self::from_symbols(symbols);
        table.position_independent = elf_type == ET_DYN;
        Ok(table)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Symbol> {
        self.by_name.get(name)
    }

    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<u64> {
        self.get(name).map(|symbol| symbol.address)
    }

    #[must_use]
    pub fn nearest(&self, address: u64) -> Option<(&Symbol, u64)> {
        let index = self
            .by_address
            .partition_point(|symbol| symbol.address <= address)
            .checked_sub(1)?;
        let symbol = &self.by_address[index];
        Some((symbol, address - symbol.address))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Symbol> {
        self.by_address.iter()
    }

    #[must_use]
    pub const fn sources(&self) -> &SourceMap {
        &self.sources
    }

    #[must_use]
    pub fn source_at(&self, address: u64) -> Option<&SourceLocation> {
        self.sources.lookup(address)
    }

    pub fn resolve_source(&self, spec: &str) -> Result<Option<u64>, SourceLookupError> {
        self.sources.resolve(spec)
    }

    #[must_use]
    pub const fn is_position_independent(&self) -> bool {
        self.position_independent
    }

    #[must_use]
    pub const fn load_bias(&self) -> u64 {
        self.load_bias
    }

    pub fn with_load_bias(mut self, bias: u64) -> Result<Self, SymbolError> {
        if bias == 0 {
            return Ok(self);
        }
        let load_bias = self
            .load_bias
            .checked_add(bias)
            .ok_or(SymbolError::AddressOverflow)?;
        if self
            .by_address
            .iter()
            .any(|symbol| symbol.address.checked_add(bias).is_none())
        {
            return Err(SymbolError::AddressOverflow);
        }
        self.sources
            .apply_load_bias(bias)
            .map_err(|()| SymbolError::AddressOverflow)?;
        for symbol in self.by_name.values_mut() {
            symbol.address += bias;
        }
        for symbol in &mut self.by_address {
            symbol.address += bias;
        }
        self.load_bias = load_bias;
        Ok(self)
    }

    #[must_use]
    pub fn with_sources(mut self, sources: SourceMap) -> Self {
        self.sources = sources;
        self
    }
}

#[derive(Clone, Copy)]
struct Section {
    kind: u32,
    offset: u64,
    size: u64,
    link: u32,
    entry_size: u64,
}

fn section(
    bytes: &[u8],
    table_offset: usize,
    entry_size: usize,
    index: usize,
) -> Result<Section, SymbolError> {
    let start = table_offset
        .checked_add(
            index
                .checked_mul(entry_size)
                .ok_or(SymbolError::InvalidSection)?,
        )
        .ok_or(SymbolError::InvalidSection)?;
    let raw = bytes
        .get(start..start + SECTION_HEADER_SIZE)
        .ok_or(SymbolError::Truncated)?;
    Ok(Section {
        kind: read_u32(raw, 4)?,
        offset: read_u64(raw, 24)?,
        size: read_u64(raw, 32)?,
        link: read_u32(raw, 40)?,
        entry_size: read_u64(raw, 56)?,
    })
}

fn range(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8], SymbolError> {
    let start = usize::try_from(offset).map_err(|_| SymbolError::InvalidSection)?;
    let length = usize::try_from(size).map_err(|_| SymbolError::InvalidSection)?;
    bytes
        .get(
            start
                ..start
                    .checked_add(length)
                    .ok_or(SymbolError::InvalidSection)?,
        )
        .ok_or(SymbolError::Truncated)
}

fn read_string(bytes: &[u8], offset: usize) -> Result<&str, SymbolError> {
    let tail = bytes.get(offset..).ok_or(SymbolError::InvalidString)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(SymbolError::InvalidString)?;
    std::str::from_utf8(&tail[..end]).map_err(|_| SymbolError::InvalidString)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, SymbolError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(SymbolError::Truncated)?
        .try_into()
        .map_err(|_| SymbolError::Truncated)?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SymbolError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(SymbolError::Truncated)?
        .try_into()
        .map_err(|_| SymbolError::Truncated)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, SymbolError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or(SymbolError::Truncated)?
        .try_into()
        .map_err(|_| SymbolError::Truncated)?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let section_offset = 64_usize;
        let strings = b"\0_start\0counter\0";
        let strings_offset = 320_usize;
        let symbols_offset = 352_usize;
        let mut elf = vec![0_u8; symbols_offset + SYMBOL_SIZE * 3];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[40..48].copy_from_slice(&(section_offset as u64).to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[58..60].copy_from_slice(&(SECTION_HEADER_SIZE as u16).to_le_bytes());
        elf[60..62].copy_from_slice(&4_u16.to_le_bytes());

        let strtab = section_offset + SECTION_HEADER_SIZE;
        elf[strtab + 4..strtab + 8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
        elf[strtab + 24..strtab + 32].copy_from_slice(&(strings_offset as u64).to_le_bytes());
        elf[strtab + 32..strtab + 40].copy_from_slice(&(strings.len() as u64).to_le_bytes());

        let symtab = section_offset + SECTION_HEADER_SIZE * 2;
        elf[symtab + 4..symtab + 8].copy_from_slice(&SHT_SYMTAB.to_le_bytes());
        elf[symtab + 24..symtab + 32].copy_from_slice(&(symbols_offset as u64).to_le_bytes());
        elf[symtab + 32..symtab + 40].copy_from_slice(&(SYMBOL_SIZE as u64 * 3).to_le_bytes());
        elf[symtab + 40..symtab + 44].copy_from_slice(&1_u32.to_le_bytes());
        elf[symtab + 56..symtab + 64].copy_from_slice(&(SYMBOL_SIZE as u64).to_le_bytes());

        elf[strings_offset..strings_offset + strings.len()].copy_from_slice(strings);
        let start = symbols_offset + SYMBOL_SIZE;
        elf[start..start + 4].copy_from_slice(&1_u32.to_le_bytes());
        elf[start + 4] = 0x12;
        elf[start + 6..start + 8].copy_from_slice(&3_u16.to_le_bytes());
        elf[start + 8..start + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[start + 16..start + 24].copy_from_slice(&16_u64.to_le_bytes());
        let counter = symbols_offset + SYMBOL_SIZE * 2;
        elf[counter..counter + 4].copy_from_slice(&8_u32.to_le_bytes());
        elf[counter + 4] = 0x11;
        elf[counter + 6..counter + 8].copy_from_slice(&3_u16.to_le_bytes());
        elf[counter + 8..counter + 16].copy_from_slice(&0x2000_u64.to_le_bytes());
        elf[counter + 16..counter + 24].copy_from_slice(&8_u64.to_le_bytes());
        elf
    }

    #[test]
    fn loads_defined_function_and_object_symbols() {
        let table = SymbolTable::parse(&fixture()).unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(table.resolve("_start"), Some(0x1000));
        assert_eq!(table.get("counter").unwrap().kind, SymbolKind::Object);
        let (symbol, offset) = table.nearest(0x1007).unwrap();
        assert_eq!(symbol.name, "_start");
        assert_eq!(offset, 7);
    }

    #[test]
    fn rejects_truncated_section_tables() {
        let mut elf = fixture();
        elf.truncate(100);
        assert_eq!(SymbolTable::parse(&elf).err(), Some(SymbolError::Truncated));
    }

    #[test]
    fn accepts_pie_and_applies_load_bias_to_symbols_and_lines() {
        let mut elf = fixture();
        elf[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        let sources = SourceMap::from_ranges([crate::SourceRange {
            start: 0x1000,
            end: 0x1010,
            location: SourceLocation {
                file: "src/main.rs".to_owned(),
                line: 7,
                column: None,
            },
        }]);
        let table = SymbolTable::parse(&elf)
            .unwrap()
            .with_sources(sources)
            .with_load_bias(0x400000)
            .unwrap();

        assert!(table.is_position_independent());
        assert_eq!(table.load_bias(), 0x400000);
        assert_eq!(table.resolve("_start"), Some(0x401000));
        assert_eq!(table.source_at(0x401004).unwrap().line, 7);
        assert_eq!(table.resolve_source("src/main.rs:7"), Ok(Some(0x401000)));
    }

    #[test]
    fn rejects_overflowing_load_bias() {
        let table = SymbolTable::parse(&fixture()).unwrap();
        assert_eq!(
            table.with_load_bias(u64::MAX).unwrap_err(),
            SymbolError::AddressOverflow
        );
    }
}
