use crate::{PeError, PeImage, IMAGE_DIRECTORY_ENTRY_IMPORT};

/// Maximum non-null regular import descriptors accepted per image.
pub const MAX_IMPORT_MODULES: usize = 256;
/// Maximum non-null imports accepted from one module lookup table.
///
/// The following 4,096th thunk slot is reserved for the required null
/// terminator, keeping both the effective-import and scan bounds explicit.
pub const MAX_IMPORTS_PER_MODULE: usize = 4_095;
/// Maximum effective imports accepted across the complete image.
pub const MAX_IMPORTS_TOTAL: usize = 16_384;
/// Maximum printable ASCII bytes in a module or imported-symbol name.
pub const MAX_IMPORT_NAME_BYTES: usize = 256;

const IMPORT_DESCRIPTOR_SIZE: usize = 20;
/// Maximum regular import-directory byte size, including its null descriptor.
pub const MAX_IMPORT_DIRECTORY_BYTES: u32 =
    ((MAX_IMPORT_MODULES + 1) * IMPORT_DESCRIPTOR_SIZE) as u32;
const IMPORT_THUNK_SIZE: u32 = 8;
const ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
const ORDINAL_RESERVED_MASK64: u64 = 0x7fff_ffff_ffff_0000;

/// One regular 20-byte PE import descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportDescriptor {
    /// Import Lookup Table RVA. Zero selects `first_thunk` as the lookup table.
    pub original_first_thunk: u32,
    /// Binding timestamp retained as image metadata.
    pub time_date_stamp: u32,
    /// Forwarder-chain field retained as image metadata.
    pub forwarder_chain: u32,
    /// RVA of the NUL-terminated module name.
    pub name_rva: u32,
    /// Import Address Table RVA.
    pub first_thunk: u32,
}

impl ImportDescriptor {
    const fn is_null(self) -> bool {
        self.original_first_thunk == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name_rva == 0
            && self.first_thunk == 0
    }
}

/// Validated target encoded by one PE32+ lookup thunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportTarget<'data> {
    /// Import by 16-bit ordinal.
    Ordinal(u16),
    /// Import by printable ASCII name and optional linker hint.
    Name {
        /// Export-table lookup hint.
        hint: u16,
        /// Borrowed name bytes without the trailing NUL.
        name: &'data [u8],
    },
}

/// One validated regular import suitable for a later resolver plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportRecord<'data> {
    /// Descriptor-table index.
    pub descriptor_index: usize,
    /// Thunk index within this module.
    pub thunk_index: usize,
    /// Original descriptor fields.
    pub descriptor: ImportDescriptor,
    /// Printable ASCII module name without the trailing NUL.
    pub module_name: &'data [u8],
    /// RVA of this lookup-table slot.
    pub lookup_rva: u32,
    /// RVA of the parallel IAT slot to replace later.
    pub iat_rva: u32,
    /// Named or ordinal import target.
    pub target: ImportTarget<'data>,
}

/// Bounded counts from a fully validated regular import table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportSummary {
    /// Number of non-null module descriptors.
    pub module_count: usize,
    /// Total number of non-null lookup thunks.
    pub import_count: usize,
}

impl<'data> PeImage<'data> {
    /// Fully validates the regular import descriptor and thunk graph.
    pub fn import_summary(&self) -> Result<ImportSummary, PeError> {
        scan_imports(self, &mut |_| {})
    }

    /// Visits validated regular imports without allocating or changing an IAT.
    ///
    /// A complete validation pass runs before `visitor` is called, preventing a
    /// malformed later descriptor from producing a partial resolver plan.
    pub fn visit_imports<F>(&self, mut visitor: F) -> Result<ImportSummary, PeError>
    where
        F: FnMut(ImportRecord<'data>),
    {
        let validated = self.import_summary()?;
        let emitted = scan_imports(self, &mut visitor)?;
        debug_assert_eq!(validated, emitted);
        Ok(validated)
    }
}

fn scan_imports<'data, F>(image: &PeImage<'data>, visitor: &mut F) -> Result<ImportSummary, PeError>
where
    F: FnMut(ImportRecord<'data>),
{
    let directory = image
        .directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
        .filter(|directory| !directory.is_empty());
    let Some(directory) = directory else {
        return Ok(ImportSummary {
            module_count: 0,
            import_count: 0,
        });
    };
    if directory.size == 0 || directory.size % IMPORT_DESCRIPTOR_SIZE as u32 != 0 {
        return Err(PeError::InvalidImportDirectorySize {
            size: directory.size,
        });
    }
    if directory.size > MAX_IMPORT_DIRECTORY_BYTES {
        return Err(PeError::ImportDirectoryTooLarge {
            size: directory.size,
            maximum: MAX_IMPORT_DIRECTORY_BYTES,
        });
    }

    let bytes = image.section_bytes(directory.address, directory.size)?;
    let descriptor_slots = bytes.len() / IMPORT_DESCRIPTOR_SIZE;

    let mut module_count = 0_usize;
    let mut import_count = 0_usize;
    let mut terminated = false;
    for descriptor_index in 0..descriptor_slots {
        let offset = descriptor_index * IMPORT_DESCRIPTOR_SIZE;
        let descriptor = parse_descriptor(&bytes[offset..offset + IMPORT_DESCRIPTOR_SIZE]);
        if descriptor.is_null() {
            if let Some(tail_offset) = bytes[offset + IMPORT_DESCRIPTOR_SIZE..]
                .iter()
                .position(|byte| *byte != 0)
            {
                return Err(PeError::NonZeroImportDirectoryTail {
                    directory_offset: u32::try_from(offset + IMPORT_DESCRIPTOR_SIZE + tail_offset)
                        .map_err(|_| PeError::ArithmeticOverflow {
                            field: "import directory tail offset",
                        })?,
                });
            }
            terminated = true;
            break;
        }

        module_count += 1;
        if module_count > MAX_IMPORT_MODULES {
            return Err(PeError::TooManyImportModules {
                count: module_count,
                maximum: MAX_IMPORT_MODULES,
            });
        }
        validate_descriptor_fields(descriptor, descriptor_index)?;
        let module_name = read_ascii_name(image, descriptor.name_rva)?;
        let lookup_table_rva = if descriptor.original_first_thunk == 0 {
            descriptor.first_thunk
        } else {
            descriptor.original_first_thunk
        };

        let mut module_imports = 0_usize;
        loop {
            if module_imports > MAX_IMPORTS_PER_MODULE {
                return Err(PeError::UnterminatedImportThunkTable {
                    descriptor: descriptor_index,
                    maximum: MAX_IMPORTS_PER_MODULE,
                });
            }
            let lookup_rva = thunk_rva(lookup_table_rva, module_imports)?;
            let iat_rva = thunk_rva(descriptor.first_thunk, module_imports)?;
            let lookup_value = read_u64(image.section_bytes(lookup_rva, IMPORT_THUNK_SIZE)?);
            let iat_value = read_u64(image.section_bytes(iat_rva, IMPORT_THUNK_SIZE)?);
            if lookup_value == 0 {
                if module_imports == 0 {
                    return Err(PeError::EmptyImportThunkTable {
                        descriptor: descriptor_index,
                    });
                }
                if iat_value != 0 {
                    return Err(PeError::NonZeroImportAddressTerminator {
                        descriptor: descriptor_index,
                        rva: iat_rva,
                        value: iat_value,
                    });
                }
                break;
            }
            if module_imports == MAX_IMPORTS_PER_MODULE {
                return Err(PeError::UnterminatedImportThunkTable {
                    descriptor: descriptor_index,
                    maximum: MAX_IMPORTS_PER_MODULE,
                });
            }

            import_count = import_count.checked_add(1).ok_or(PeError::TooManyImports {
                count: usize::MAX,
                maximum: MAX_IMPORTS_TOTAL,
            })?;
            if import_count > MAX_IMPORTS_TOTAL {
                return Err(PeError::TooManyImports {
                    count: import_count,
                    maximum: MAX_IMPORTS_TOTAL,
                });
            }
            let target = parse_target(image, descriptor_index, module_imports, lookup_value)?;
            visitor(ImportRecord {
                descriptor_index,
                thunk_index: module_imports,
                descriptor,
                module_name,
                lookup_rva,
                iat_rva,
                target,
            });
            module_imports += 1;
        }
    }

    if !terminated {
        return Err(PeError::UnterminatedImportDirectory);
    }
    Ok(ImportSummary {
        module_count,
        import_count,
    })
}

fn parse_descriptor(bytes: &[u8]) -> ImportDescriptor {
    debug_assert_eq!(bytes.len(), IMPORT_DESCRIPTOR_SIZE);
    ImportDescriptor {
        original_first_thunk: read_u32(&bytes[0..4]),
        time_date_stamp: read_u32(&bytes[4..8]),
        forwarder_chain: read_u32(&bytes[8..12]),
        name_rva: read_u32(&bytes[12..16]),
        first_thunk: read_u32(&bytes[16..20]),
    }
}

fn validate_descriptor_fields(descriptor: ImportDescriptor, index: usize) -> Result<(), PeError> {
    if descriptor.name_rva == 0 {
        return Err(PeError::MissingImportModuleName { descriptor: index });
    }
    if descriptor.first_thunk == 0 {
        return Err(PeError::MissingImportAddressTable { descriptor: index });
    }
    let lookup_rva = if descriptor.original_first_thunk == 0 {
        descriptor.first_thunk
    } else {
        descriptor.original_first_thunk
    };
    if lookup_rva & (IMPORT_THUNK_SIZE - 1) != 0 {
        return Err(PeError::ImportThunkTableMisaligned {
            descriptor: index,
            rva: lookup_rva,
        });
    }
    if descriptor.first_thunk & (IMPORT_THUNK_SIZE - 1) != 0 {
        return Err(PeError::ImportThunkTableMisaligned {
            descriptor: index,
            rva: descriptor.first_thunk,
        });
    }
    Ok(())
}

fn thunk_rva(table_rva: u32, index: usize) -> Result<u32, PeError> {
    let byte_offset = u32::try_from(index)
        .ok()
        .and_then(|value| value.checked_mul(IMPORT_THUNK_SIZE))
        .ok_or(PeError::ArithmeticOverflow {
            field: "import thunk byte offset",
        })?;
    table_rva
        .checked_add(byte_offset)
        .ok_or(PeError::ArithmeticOverflow {
            field: "import thunk RVA",
        })
}

fn parse_target<'data>(
    image: &PeImage<'data>,
    descriptor: usize,
    thunk: usize,
    value: u64,
) -> Result<ImportTarget<'data>, PeError> {
    if value & ORDINAL_FLAG64 != 0 {
        if value & ORDINAL_RESERVED_MASK64 != 0 {
            return Err(PeError::InvalidOrdinalImportEncoding {
                descriptor,
                thunk,
                value,
            });
        }
        let ordinal = value as u16;
        if ordinal == 0 {
            return Err(PeError::InvalidImportOrdinal { descriptor, thunk });
        }
        return Ok(ImportTarget::Ordinal(ordinal));
    }

    let name_rva = u32::try_from(value).map_err(|_| PeError::ImportNameRvaTooWide {
        descriptor,
        thunk,
        value,
    })?;
    let hint = read_u16(image.section_bytes(name_rva, 2)?);
    let string_rva = name_rva.checked_add(2).ok_or(PeError::RvaOutsideImage {
        rva: name_rva,
        size: 2,
    })?;
    let name = read_ascii_name(image, string_rva)?;
    Ok(ImportTarget::Name { hint, name })
}

fn read_ascii_name<'data>(image: &PeImage<'data>, rva: u32) -> Result<&'data [u8], PeError> {
    for length in 0..=MAX_IMPORT_NAME_BYTES {
        let offset = u32::try_from(length).map_err(|_| PeError::ArithmeticOverflow {
            field: "import name byte offset",
        })?;
        let byte_rva = rva.checked_add(offset).ok_or(PeError::RvaOutsideImage {
            rva,
            size: u32::MAX,
        })?;
        let byte = image.section_bytes(byte_rva, 1)?[0];
        if byte == 0 {
            if length == 0 {
                return Err(PeError::EmptyImportName { rva });
            }
            let size = u32::try_from(length).map_err(|_| PeError::ArithmeticOverflow {
                field: "import name size",
            })?;
            return image.section_bytes(rva, size);
        }
        if !(0x20..=0x7e).contains(&byte) {
            return Err(PeError::InvalidImportNameByte {
                rva,
                offset: length,
                byte,
            });
        }
    }
    Err(PeError::ImportNameTooLong {
        rva,
        maximum: MAX_IMPORT_NAME_BYTES,
    })
}

fn read_u16(bytes: &[u8]) -> u16 {
    debug_assert_eq!(bytes.len(), 2);
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    debug_assert_eq!(bytes.len(), 4);
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    debug_assert_eq!(bytes.len(), 8);
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}
