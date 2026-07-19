//! Bounded AML namespace loader and byte cursor.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::namespace::{
    canonical_from_segments, split_canonical, valid_name_char, BuiltinMethod, FieldUnit, Method,
    Namespace, NamespaceObject, OperationRegion,
};
use super::region::RegionSpace;
use super::value::AmlValue;
use super::AmlError;

pub(crate) const MAX_PACKAGE_ELEMENTS: usize = 1024;
pub(crate) const MAX_BUFFER_SIZE: usize = 1024 * 1024;
const MAX_PARSE_DEPTH: usize = 64;

#[derive(Clone)]
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
    base: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            base: 0,
        }
    }

    fn with_base(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            position: 0,
            base,
        }
    }

    pub(crate) fn offset(&self) -> usize {
        self.base + self.position
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    pub(crate) fn rewind_one(&mut self) {
        debug_assert!(self.position != 0);
        self.position -= 1;
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, AmlError> {
        let offset = self.offset();
        let byte = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or(AmlError::UnexpectedEof(offset))?;
        self.position += 1;
        Ok(byte)
    }

    pub(crate) fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], AmlError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(AmlError::InvalidPackageLength(self.offset()))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(AmlError::UnexpectedEof(self.offset()))?;
        self.position = end;
        Ok(bytes)
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, AmlError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, AmlError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64, AmlError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(crate) fn package(&mut self) -> Result<Cursor<'a>, AmlError> {
        let start = self.position;
        let absolute = self.offset();
        let first = self.read_u8()?;
        let follow = usize::from(first >> 6);
        let mut length = if follow == 0 {
            usize::from(first & 0x3f)
        } else {
            usize::from(first & 0x0f)
        };
        for index in 0..follow {
            let byte = usize::from(self.read_u8()?);
            length |= byte << (4 + index * 8);
        }
        let encoded = self.position - start;
        if length < encoded {
            return Err(AmlError::InvalidPackageLength(absolute));
        }
        let content = length - encoded;
        let body_base = self.offset();
        let bytes = self.read_bytes(content)?;
        Ok(Cursor::with_base(bytes, body_base))
    }

    pub(crate) fn tail(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }
}

fn name_segment(cursor: &mut Cursor<'_>) -> Result<String, AmlError> {
    let bytes = cursor.read_bytes(4)?;
    if !(bytes[0] == b'_' || bytes[0].is_ascii_uppercase())
        || !bytes.iter().copied().all(valid_name_char)
    {
        return Err(AmlError::InvalidName);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| AmlError::InvalidName)?;
    Ok(text.to_string())
}

pub(crate) fn is_name_start(byte: u8) -> bool {
    byte == b'\\'
        || byte == b'^'
        || byte == 0x2e
        || byte == 0x2f
        || byte == b'_'
        || byte.is_ascii_uppercase()
}

/// Parse a NameString and resolve it relative to `scope`.
pub(crate) fn name_string(cursor: &mut Cursor<'_>, scope: &str) -> Result<String, AmlError> {
    let mut absolute = false;
    let mut parents = 0usize;
    if cursor.peek() == Some(b'\\') {
        cursor.read_u8()?;
        absolute = true;
    } else {
        while cursor.peek() == Some(b'^') {
            cursor.read_u8()?;
            parents += 1;
        }
    }

    let count = match cursor
        .peek()
        .ok_or(AmlError::UnexpectedEof(cursor.offset()))?
    {
        0x00 => {
            cursor.read_u8()?;
            0
        },
        0x2e => {
            cursor.read_u8()?;
            2
        },
        0x2f => {
            cursor.read_u8()?;
            usize::from(cursor.read_u8()?)
        },
        byte if is_name_start(byte) && byte != b'\\' && byte != b'^' => 1,
        _ => return Err(AmlError::InvalidName),
    };
    if count > 255 {
        return Err(AmlError::LimitExceeded("name segments"));
    }

    let mut segments: Vec<String> = if absolute {
        Vec::new()
    } else {
        split_canonical(scope)
            .into_iter()
            .map(ToString::to_string)
            .collect()
    };
    if parents > segments.len() {
        return Err(AmlError::InvalidName);
    }
    segments.truncate(segments.len() - parents);
    for _ in 0..count {
        segments.push(name_segment(cursor)?);
    }
    Ok(canonical_from_segments(&segments))
}

fn constant_integer(cursor: &mut Cursor<'_>, scope: &str, depth: usize) -> Result<u64, AmlError> {
    let value = data_value(cursor, scope, depth)?;
    value
        .as_integer()
        .ok_or(AmlError::TypeMismatch("integer constant"))
}

pub(crate) fn data_value(
    cursor: &mut Cursor<'_>,
    scope: &str,
    depth: usize,
) -> Result<AmlValue, AmlError> {
    if depth >= MAX_PARSE_DEPTH {
        return Err(AmlError::LimitExceeded("package nesting"));
    }
    let opcode = cursor.read_u8()?;
    match opcode {
        0x00 => Ok(AmlValue::Integer(0)),
        0x01 => Ok(AmlValue::Integer(1)),
        0xff => Ok(AmlValue::Integer(u64::MAX)),
        0x0a => Ok(AmlValue::Integer(u64::from(cursor.read_u8()?))),
        0x0b => Ok(AmlValue::Integer(u64::from(cursor.read_u16()?))),
        0x0c => Ok(AmlValue::Integer(u64::from(cursor.read_u32()?))),
        0x0e => Ok(AmlValue::Integer(cursor.read_u64()?)),
        0x0d => {
            let start = cursor.offset();
            let mut bytes = Vec::new();
            loop {
                let byte = cursor.read_u8()?;
                if byte == 0 {
                    break;
                }
                if !byte.is_ascii() || bytes.len() >= 4096 {
                    return Err(AmlError::InvalidString(start));
                }
                bytes.push(byte);
            }
            let string = String::from_utf8(bytes).map_err(|_| AmlError::InvalidString(start))?;
            Ok(AmlValue::String(string))
        },
        0x11 => {
            let mut package = cursor.package()?;
            let size = usize::try_from(constant_integer(&mut package, scope, depth + 1)?)
                .map_err(|_| AmlError::LimitExceeded("buffer size"))?;
            if size > MAX_BUFFER_SIZE {
                return Err(AmlError::LimitExceeded("buffer size"));
            }
            let initializer = package.tail();
            let mut buffer = alloc::vec![0; size];
            let copied = initializer.len().min(size);
            buffer[..copied].copy_from_slice(&initializer[..copied]);
            Ok(AmlValue::Buffer(buffer))
        },
        0x12 | 0x13 => {
            let mut package = cursor.package()?;
            let count = if opcode == 0x12 {
                usize::from(package.read_u8()?)
            } else {
                usize::try_from(constant_integer(&mut package, scope, depth + 1)?)
                    .map_err(|_| AmlError::LimitExceeded("package elements"))?
            };
            if count > MAX_PACKAGE_ELEMENTS {
                return Err(AmlError::LimitExceeded("package elements"));
            }
            let mut values = Vec::with_capacity(count);
            while values.len() < count && !package.is_empty() {
                values.push(data_value(&mut package, scope, depth + 1)?);
            }
            values.resize(count, AmlValue::Uninitialized);
            Ok(AmlValue::Package(values))
        },
        byte if is_name_start(byte) => {
            cursor.position -= 1;
            Ok(AmlValue::Reference(name_string(cursor, scope)?))
        },
        _ => Err(AmlError::UnsupportedOpcode(opcode, cursor.offset() - 1)),
    }
}

pub(crate) struct Loader {
    namespace: Namespace,
}

impl Loader {
    pub(crate) fn load(bytes: &[u8]) -> Result<Namespace, AmlError> {
        Self::load_blocks(core::iter::once(bytes))
    }

    /// Load a DSDT followed by its SSDT definition blocks into one namespace.
    pub(crate) fn load_blocks<'a>(
        blocks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Namespace, AmlError> {
        let mut loader = Self {
            namespace: Namespace::default(),
        };
        loader.namespace.insert(
            "\\_REV".to_string(),
            NamespaceObject::Value(AmlValue::Integer(2)),
        )?;
        loader.namespace.insert(
            "\\_OS_".to_string(),
            NamespaceObject::Value(AmlValue::String("Xenith".to_string())),
        )?;
        loader.namespace.insert(
            "\\_OSI".to_string(),
            NamespaceObject::BuiltinMethod(BuiltinMethod::Osi),
        )?;
        for bytes in blocks {
            let mut cursor = Cursor::new(bytes);
            loader.term_list(&mut cursor, "\\", 0)?;
        }
        Ok(loader.namespace)
    }

    fn term_list(
        &mut self,
        cursor: &mut Cursor<'_>,
        scope: &str,
        depth: usize,
    ) -> Result<(), AmlError> {
        if depth >= MAX_PARSE_DEPTH {
            return Err(AmlError::LimitExceeded("namespace scope depth"));
        }
        while !cursor.is_empty() {
            let offset = cursor.offset();
            match cursor.read_u8()? {
                0x06 => {
                    let source = name_string(cursor, scope)?;
                    let target = name_string(cursor, scope)?;
                    self.namespace
                        .define(target, NamespaceObject::Alias(source))?;
                },
                0x08 => {
                    let name = name_string(cursor, scope)?;
                    let value = data_value(cursor, scope, depth + 1)?;
                    self.namespace.define(name, NamespaceObject::Value(value))?;
                },
                0x10 => {
                    let mut package = cursor.package()?;
                    let name = name_string(&mut package, scope)?;
                    self.term_list(&mut package, &name, depth + 1)?;
                },
                0x14 => {
                    let mut package = cursor.package()?;
                    let name = name_string(&mut package, scope)?;
                    let flags = package.read_u8()?;
                    let method = Method {
                        arg_count: flags & 0x07,
                        serialized: flags & 0x08 != 0,
                        sync_level: flags >> 4,
                        scope: super::namespace::parent_scope(&name),
                        body: package.tail().to_vec(),
                    };
                    self.namespace
                        .define(name, NamespaceObject::Method(method))?;
                },
                0x15 => {
                    let name = name_string(cursor, scope)?;
                    let object_type = cursor.read_u8()?;
                    let arg_count = cursor.read_u8()?;
                    if self.namespace.get(&name).is_none() {
                        self.namespace.insert(name, NamespaceObject::External {
                            object_type,
                            arg_count,
                        })?;
                    }
                },
                0x5b => self.extended(cursor, scope, depth, offset)?,
                // Definition-block conditionals require dynamic namespace
                // loading. Keep the outer parser synchronized and retain all
                // unconditional objects; objects declared only in the skipped
                // branch remain deterministically absent.
                0xa0 => {
                    cursor.package()?;
                    if cursor.peek() == Some(0xa1) {
                        cursor.read_u8()?;
                        cursor.package()?;
                    }
                },
                // Noop and Breakpoint are harmless in a definition block.
                0xa3 | 0xcc => {},
                opcode => return Err(AmlError::UnsupportedOpcode(opcode, offset)),
            }
        }
        Ok(())
    }

    fn extended(
        &mut self,
        cursor: &mut Cursor<'_>,
        scope: &str,
        depth: usize,
        offset: usize,
    ) -> Result<(), AmlError> {
        let opcode = cursor.read_u8()?;
        match opcode {
            0x01 => {
                let name = name_string(cursor, scope)?;
                cursor.read_u8()?; // SyncLevel
                self.namespace.define(name, NamespaceObject::External {
                    object_type: 0x09,
                    arg_count: 0,
                })?;
            },
            0x02 => {
                let name = name_string(cursor, scope)?;
                self.namespace.define(name, NamespaceObject::External {
                    object_type: 0x07,
                    arg_count: 0,
                })?;
            },
            0x80 => {
                let name = name_string(cursor, scope)?;
                let space = RegionSpace::from(cursor.read_u8()?);
                let region_scope = super::namespace::parent_scope(&name);
                let offset = self.static_integer(cursor, &region_scope, depth + 1)?;
                let length = self.static_integer(cursor, &region_scope, depth + 1)?;
                if length == 0 {
                    return Err(AmlError::InvalidRegion);
                }
                self.namespace.define(
                    name,
                    NamespaceObject::OperationRegion(OperationRegion {
                        space,
                        offset,
                        length,
                    }),
                )?;
            },
            0x81 => self.field(cursor, scope)?,
            0x82 => self.named_scope(cursor, scope, depth, NamespaceObject::Device, 0)?,
            0x83 => self.named_scope(cursor, scope, depth, NamespaceObject::Processor, 6)?,
            0x84 => self.named_scope(cursor, scope, depth, NamespaceObject::PowerResource, 3)?,
            0x85 => self.named_scope(cursor, scope, depth, NamespaceObject::ThermalZone, 0)?,
            // IndexField and BankField are package-delimited. Their register
            // selection semantics are not used by discovery methods yet, so
            // skip the complete object without desynchronizing later terms.
            0x86 | 0x87 => {
                cursor.package()?;
            },
            _ => return Err(AmlError::UnsupportedExtendedOpcode(opcode, offset)),
        }
        Ok(())
    }

    fn static_integer(
        &self,
        cursor: &mut Cursor<'_>,
        scope: &str,
        depth: usize,
    ) -> Result<u64, AmlError> {
        let mut value = data_value(cursor, scope, depth)?;
        for _ in 0..16 {
            match value {
                AmlValue::Integer(integer) => return Ok(integer),
                AmlValue::Reference(ref path) => {
                    let resolved = self.namespace.resolve_alias(path)?;
                    value = match self.namespace.get(resolved) {
                        Some(NamespaceObject::Value(value)) => value.clone(),
                        _ => return Err(AmlError::TypeMismatch("static integer")),
                    };
                },
                _ => return Err(AmlError::TypeMismatch("static integer")),
            }
        }
        Err(AmlError::LimitExceeded("static reference depth"))
    }

    fn named_scope(
        &mut self,
        cursor: &mut Cursor<'_>,
        scope: &str,
        depth: usize,
        object: NamespaceObject,
        prefix_bytes: usize,
    ) -> Result<(), AmlError> {
        let mut package = cursor.package()?;
        let name = name_string(&mut package, scope)?;
        package.read_bytes(prefix_bytes)?;
        self.namespace.define(name.clone(), object)?;
        self.term_list(&mut package, &name, depth + 1)
    }

    fn field(&mut self, cursor: &mut Cursor<'_>, scope: &str) -> Result<(), AmlError> {
        let mut package = cursor.package()?;
        let region = name_string(&mut package, scope)?;
        let flags = package.read_u8()?;
        let mut bit_offset = 0u64;
        while !package.is_empty() {
            match package
                .peek()
                .ok_or(AmlError::UnexpectedEof(package.offset()))?
            {
                0x00 => {
                    package.read_u8()?;
                    bit_offset = bit_offset
                        .checked_add(
                            u64::try_from(package_length_value(&mut package)?).unwrap_or(u64::MAX),
                        )
                        .ok_or(AmlError::InvalidField)?;
                },
                0x01 => {
                    package.read_bytes(3)?; // opcode, access type, attribute
                },
                0x02 => {
                    package.read_u8()?;
                    if package.peek() == Some(0x11) {
                        data_value(&mut package, scope, 0)?;
                    } else {
                        name_string(&mut package, scope)?;
                    }
                },
                0x03 => {
                    package.read_bytes(4)?;
                },
                byte if byte == b'_' || byte.is_ascii_uppercase() => {
                    let segment = name_segment(&mut package)?;
                    let length = u64::try_from(package_length_value(&mut package)?)
                        .map_err(|_| AmlError::InvalidField)?;
                    if length == 0 || length > 64 {
                        return Err(AmlError::InvalidField);
                    }
                    let name = super::namespace::join_path(scope, &segment);
                    self.namespace.define(
                        name,
                        NamespaceObject::Field(FieldUnit {
                            region: region.clone(),
                            bit_offset,
                            bit_length: length,
                            flags,
                        }),
                    )?;
                    bit_offset = bit_offset
                        .checked_add(length)
                        .ok_or(AmlError::InvalidField)?;
                },
                opcode => return Err(AmlError::UnsupportedOpcode(opcode, package.offset())),
            }
        }
        Ok(())
    }
}

fn package_length_value(cursor: &mut Cursor<'_>) -> Result<usize, AmlError> {
    let offset = cursor.offset();
    let first = cursor.read_u8()?;
    let follow = usize::from(first >> 6);
    let mut value = if follow == 0 {
        usize::from(first & 0x3f)
    } else {
        usize::from(first & 0x0f)
    };
    for index in 0..follow {
        value |= usize::from(cursor.read_u8()?) << (4 + index * 8);
    }
    if value > (1 << 28) {
        return Err(AmlError::InvalidPackageLength(offset));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multisegment_names() {
        let mut cursor = Cursor::new(b"\\\x2e_SB_PCI0");
        assert_eq!(name_string(&mut cursor, "\\").unwrap(), "\\_SB_.PCI0");
    }

    #[test]
    fn loads_device_status_method() {
        // Device (DEV0) { Method (_STA, 0) { Return (0x0f) } }
        let aml = [
            0x5b, 0x82, 0x0f, b'D', b'E', b'V', b'0', 0x14, 0x09, b'_', b'S', b'T', b'A', 0x00,
            0xa4, 0x0a, 0x0f,
        ];
        let namespace = Loader::load(&aml).unwrap();
        assert!(matches!(
            namespace.get("\\DEV0._STA"),
            Some(NamespaceObject::Method(_))
        ));
    }

    #[test]
    fn malformed_package_is_rejected() {
        assert!(matches!(
            Loader::load(&[0x10, 0x3f]),
            Err(AmlError::UnexpectedEof(_))
        ));
    }

    #[test]
    fn secondary_block_resolves_primary_external() {
        let dsdt = [0x15, b'D', b'E', b'V', b'0', 0x01, 0x00];
        let ssdt = [0x08, b'D', b'E', b'V', b'0', 0x0a, 42];
        let namespace = Loader::load_blocks([dsdt.as_slice(), ssdt.as_slice()]).unwrap();
        assert!(matches!(
            namespace.get("\\DEV0"),
            Some(NamespaceObject::Value(AmlValue::Integer(42)))
        ));
    }
}
