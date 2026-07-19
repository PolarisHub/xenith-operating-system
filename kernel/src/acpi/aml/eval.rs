//! Bounded AML method evaluator.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::namespace::{
    canonical_from_segments, split_canonical, BuiltinMethod, Method, Namespace, NamespaceObject,
};
use super::parser::{data_value, is_name_start, name_string, Cursor, MAX_BUFFER_SIZE};
use super::region::RegionHandler;
use super::value::AmlValue;
use super::AmlError;

const MAX_METHOD_DEPTH: usize = 32;
const MAX_EXECUTION_STEPS: usize = 100_000;
const MAX_LOOP_ITERATIONS: usize = 4096;

struct Frame {
    scope: String,
    args: [AmlValue; 7],
    locals: [AmlValue; 8],
}

impl Frame {
    fn new(scope: String, supplied: &[AmlValue]) -> Self {
        let mut args = core::array::from_fn(|_| AmlValue::Uninitialized);
        for (target, value) in args.iter_mut().zip(supplied.iter()) {
            *target = value.clone();
        }
        Self {
            scope,
            args,
            locals: core::array::from_fn(|_| AmlValue::Uninitialized),
        }
    }
}

enum Control {
    Continue,
    Return(AmlValue),
    Break,
}

enum Target {
    Discard,
    Local(usize),
    Arg(usize),
    Name(String),
}

pub(crate) struct Evaluator<'a> {
    namespace: &'a mut Namespace,
    handler: &'a dyn RegionHandler,
    steps: usize,
    depth: usize,
}

impl<'a> Evaluator<'a> {
    pub(crate) fn new(namespace: &'a mut Namespace, handler: &'a dyn RegionHandler) -> Self {
        Self {
            namespace,
            handler,
            steps: 0,
            depth: 0,
        }
    }

    pub(crate) fn evaluate(&mut self, path: &str, args: &[AmlValue]) -> Result<AmlValue, AmlError> {
        let path = self
            .resolve_existing(path)
            .ok_or_else(|| AmlError::NotFound(path.to_string()))?;
        self.evaluate_object(&path, args)
    }

    fn tick(&mut self) -> Result<(), AmlError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > MAX_EXECUTION_STEPS {
            Err(AmlError::ExecutionLimit)
        } else {
            Ok(())
        }
    }

    fn resolve_existing(&self, candidate: &str) -> Option<String> {
        if self.namespace.get(candidate).is_some() {
            return Some(candidate.to_string());
        }
        let mut segments: Vec<String> = split_canonical(candidate)
            .into_iter()
            .map(ToString::to_string)
            .collect();
        let leaf = segments.pop()?;
        while !segments.is_empty() {
            segments.pop();
            let mut next = segments.clone();
            next.push(leaf.clone());
            let path = canonical_from_segments(&next);
            if self.namespace.get(&path).is_some() {
                return Some(path);
            }
        }
        let root = alloc::format!("\\{leaf}");
        self.namespace.get(&root).map(|_| root)
    }

    fn evaluate_object(&mut self, path: &str, args: &[AmlValue]) -> Result<AmlValue, AmlError> {
        let resolved = self.namespace.resolve_alias(path)?.to_string();
        let object = self
            .namespace
            .get(&resolved)
            .cloned()
            .ok_or_else(|| AmlError::NotFound(resolved.clone()))?;
        match object {
            NamespaceObject::Value(value) => {
                if args.is_empty() {
                    Ok(value)
                } else {
                    Err(AmlError::ArgumentCount)
                }
            },
            NamespaceObject::Method(method) => self.invoke_method(method, args),
            NamespaceObject::BuiltinMethod(BuiltinMethod::Osi) => {
                if args.len() != 1 {
                    return Err(AmlError::ArgumentCount);
                }
                let AmlValue::String(interface) = &args[0] else {
                    return Err(AmlError::TypeMismatch("_OSI string"));
                };
                Ok(boolean(interface == "Xenith"))
            },
            NamespaceObject::Field(field) => {
                if args.is_empty() {
                    self.read_field(&field)
                } else {
                    Err(AmlError::ArgumentCount)
                }
            },
            NamespaceObject::Device
            | NamespaceObject::Processor
            | NamespaceObject::ThermalZone
            | NamespaceObject::PowerResource
            | NamespaceObject::OperationRegion(_) => Ok(AmlValue::Reference(resolved)),
            NamespaceObject::Alias(_) => unreachable!("alias was resolved"),
            NamespaceObject::External {
                object_type,
                arg_count,
            } => {
                let _ = (object_type, arg_count);
                Err(AmlError::UnresolvedExternal(resolved))
            },
        }
    }

    fn invoke_method(&mut self, method: Method, args: &[AmlValue]) -> Result<AmlValue, AmlError> {
        if args.len() != usize::from(method.arg_count) {
            return Err(AmlError::ArgumentCount);
        }
        if self.depth >= MAX_METHOD_DEPTH {
            return Err(AmlError::RecursionLimit);
        }
        // The global AML context lock serializes evaluations, which is
        // stronger than AML's Serialized flag and sync-level requirement.
        let _serialized_contract = (method.serialized, method.sync_level);
        self.depth += 1;
        let mut frame = Frame::new(method.scope, args);
        let mut cursor = Cursor::new(&method.body);
        let result = match self.execute(&mut cursor, &mut frame)? {
            Control::Return(value) => value,
            Control::Continue => AmlValue::Integer(0),
            Control::Break => return Err(AmlError::UnexpectedBreak),
        };
        self.depth -= 1;
        Ok(result)
    }

    fn execute(&mut self, cursor: &mut Cursor<'_>, frame: &mut Frame) -> Result<Control, AmlError> {
        while !cursor.is_empty() {
            self.tick()?;
            match cursor
                .peek()
                .ok_or(AmlError::UnexpectedEof(cursor.offset()))?
            {
                0xa0 => {
                    cursor.read_u8()?;
                    let mut package = cursor.package()?;
                    let predicate = self.term(&mut package, frame)?.truthy();
                    let branch = if predicate {
                        self.execute(&mut package, frame)?
                    } else {
                        Control::Continue
                    };
                    if !matches!(branch, Control::Continue) {
                        return Ok(branch);
                    }
                    if cursor.peek() == Some(0xa1) {
                        cursor.read_u8()?;
                        let mut otherwise = cursor.package()?;
                        if !predicate {
                            let control = self.execute(&mut otherwise, frame)?;
                            if !matches!(control, Control::Continue) {
                                return Ok(control);
                            }
                        }
                    }
                },
                0xa2 => {
                    cursor.read_u8()?;
                    let package = cursor.package()?;
                    let mut completed = false;
                    for _ in 0..MAX_LOOP_ITERATIONS {
                        let mut iteration = package.clone();
                        if !self.term(&mut iteration, frame)?.truthy() {
                            completed = true;
                            break;
                        }
                        match self.execute(&mut iteration, frame)? {
                            Control::Continue => {},
                            Control::Break => {
                                completed = true;
                                break;
                            },
                            control @ Control::Return(_) => return Ok(control),
                        }
                    }
                    if !completed {
                        return Err(AmlError::LoopLimit);
                    }
                },
                0xa4 => {
                    cursor.read_u8()?;
                    return Ok(Control::Return(self.term(cursor, frame)?));
                },
                0xa5 => {
                    cursor.read_u8()?;
                    return Ok(Control::Break);
                },
                0xa3 | 0xcc => {
                    cursor.read_u8()?;
                },
                _ => {
                    self.term(cursor, frame)?;
                },
            }
        }
        Ok(Control::Continue)
    }

    fn integer(&mut self, cursor: &mut Cursor<'_>, frame: &mut Frame) -> Result<u64, AmlError> {
        to_integer(self.term(cursor, frame)?)
    }

    fn binary_integer(
        &mut self,
        cursor: &mut Cursor<'_>,
        frame: &mut Frame,
        operation: impl FnOnce(u64, u64) -> u64,
    ) -> Result<AmlValue, AmlError> {
        let left = self.integer(cursor, frame)?;
        let right = self.integer(cursor, frame)?;
        let value = AmlValue::Integer(operation(left, right));
        let target = self.target(cursor, frame)?;
        self.store(target, value.clone(), frame)?;
        Ok(value)
    }

    fn term(&mut self, cursor: &mut Cursor<'_>, frame: &mut Frame) -> Result<AmlValue, AmlError> {
        self.tick()?;
        let opcode = cursor.read_u8()?;
        match opcode {
            0x00 => Ok(AmlValue::Integer(0)),
            0x01 => Ok(AmlValue::Integer(1)),
            0xff => Ok(AmlValue::Integer(u64::MAX)),
            0x0a => Ok(AmlValue::Integer(u64::from(cursor.read_u8()?))),
            0x0b => Ok(AmlValue::Integer(u64::from(cursor.read_u16()?))),
            0x0c => Ok(AmlValue::Integer(u64::from(cursor.read_u32()?))),
            0x0e => Ok(AmlValue::Integer(cursor.read_u64()?)),
            0x0d | 0x11 | 0x12 | 0x13 => {
                cursor.rewind_one();
                data_value(cursor, &frame.scope, 0)
            },
            0x60..=0x67 => Ok(frame.locals[usize::from(opcode - 0x60)].clone()),
            0x68..=0x6e => Ok(frame.args[usize::from(opcode - 0x68)].clone()),
            0x70 => {
                let source = self.term(cursor, frame)?;
                let target = self.target(cursor, frame)?;
                self.store(target, source.clone(), frame)?;
                Ok(source)
            },
            0x72 => self.binary_integer(cursor, frame, u64::wrapping_add),
            0x73 => {
                let left = self.term(cursor, frame)?;
                let right = self.term(cursor, frame)?;
                let value = concat(left, right)?;
                let target = self.target(cursor, frame)?;
                self.store(target, value.clone(), frame)?;
                Ok(value)
            },
            0x74 => self.binary_integer(cursor, frame, u64::wrapping_sub),
            0x75 | 0x76 => {
                let target = self.target(cursor, frame)?;
                let current = self.load_target(&target, frame)?;
                let value = if opcode == 0x75 {
                    current.wrapping_add(1)
                } else {
                    current.wrapping_sub(1)
                };
                self.store(target, AmlValue::Integer(value), frame)?;
                Ok(AmlValue::Integer(value))
            },
            0x77 => self.binary_integer(cursor, frame, u64::wrapping_mul),
            0x78 => {
                let dividend = self.integer(cursor, frame)?;
                let divisor = self.integer(cursor, frame)?;
                if divisor == 0 {
                    return Err(AmlError::DivideByZero);
                }
                let remainder = AmlValue::Integer(dividend % divisor);
                let quotient = AmlValue::Integer(dividend / divisor);
                let remainder_target = self.target(cursor, frame)?;
                let quotient_target = self.target(cursor, frame)?;
                self.store(remainder_target, remainder, frame)?;
                self.store(quotient_target, quotient.clone(), frame)?;
                Ok(quotient)
            },
            0x79 => self.binary_integer(cursor, frame, |left, right| {
                left.wrapping_shl((right & 63) as u32)
            }),
            0x7a => self.binary_integer(cursor, frame, |left, right| {
                left.wrapping_shr((right & 63) as u32)
            }),
            0x7b => self.binary_integer(cursor, frame, |left, right| left & right),
            0x7d => self.binary_integer(cursor, frame, |left, right| left | right),
            0x7f => self.binary_integer(cursor, frame, |left, right| left ^ right),
            0x80 => {
                let value = AmlValue::Integer(!self.integer(cursor, frame)?);
                let target = self.target(cursor, frame)?;
                self.store(target, value.clone(), frame)?;
                Ok(value)
            },
            0x83 => {
                let value = self.term(cursor, frame)?;
                match value {
                    AmlValue::Reference(path) => self.evaluate_object(&path, &[]),
                    other => Ok(other),
                }
            },
            0x85 => {
                let left = self.integer(cursor, frame)?;
                let right = self.integer(cursor, frame)?;
                if right == 0 {
                    return Err(AmlError::DivideByZero);
                }
                let value = AmlValue::Integer(left % right);
                let target = self.target(cursor, frame)?;
                self.store(target, value.clone(), frame)?;
                Ok(value)
            },
            0x86 => {
                self.term(cursor, frame)?;
                self.term(cursor, frame)?;
                Ok(AmlValue::Integer(0))
            },
            0x87 => Ok(AmlValue::Integer(self.term(cursor, frame)?.size() as u64)),
            0x88 => {
                let source = self.term(cursor, frame)?;
                let index = usize::try_from(self.integer(cursor, frame)?)
                    .map_err(|_| AmlError::IndexOutOfBounds)?;
                let value = match source {
                    AmlValue::Buffer(bytes) => bytes
                        .get(index)
                        .copied()
                        .map(|byte| AmlValue::Integer(u64::from(byte))),
                    AmlValue::Package(values) => values.get(index).cloned(),
                    AmlValue::String(value) => value
                        .as_bytes()
                        .get(index)
                        .copied()
                        .map(|byte| AmlValue::Integer(u64::from(byte))),
                    _ => return Err(AmlError::TypeMismatch("indexable value")),
                }
                .ok_or(AmlError::IndexOutOfBounds)?;
                let target = self.target(cursor, frame)?;
                self.store(target, value.clone(), frame)?;
                Ok(value)
            },
            0x90 => {
                let left = self.term(cursor, frame)?.truthy();
                let right = self.term(cursor, frame)?.truthy();
                Ok(boolean(left && right))
            },
            0x91 => {
                let left = self.term(cursor, frame)?.truthy();
                let right = self.term(cursor, frame)?.truthy();
                Ok(boolean(left || right))
            },
            0x92 => Ok(boolean(!self.term(cursor, frame)?.truthy())),
            0x93 => {
                let left = self.term(cursor, frame)?;
                let right = self.term(cursor, frame)?;
                Ok(boolean(left == right))
            },
            0x94 => {
                let left = self.integer(cursor, frame)?;
                let right = self.integer(cursor, frame)?;
                Ok(boolean(left > right))
            },
            0x95 => {
                let left = self.integer(cursor, frame)?;
                let right = self.integer(cursor, frame)?;
                Ok(boolean(left < right))
            },
            0x96 => {
                let value = to_buffer(self.term(cursor, frame)?)?;
                let target = self.target(cursor, frame)?;
                self.store(target, value.clone(), frame)?;
                Ok(value)
            },
            0x99 => {
                let value = AmlValue::Integer(to_integer(self.term(cursor, frame)?)?);
                let target = self.target(cursor, frame)?;
                self.store(target, value.clone(), frame)?;
                Ok(value)
            },
            0x9d => {
                let value = self.term(cursor, frame)?;
                let target = self.target(cursor, frame)?;
                self.store(target, value.clone(), frame)?;
                Ok(value)
            },
            0x9e => {
                let source = self.term(cursor, frame)?;
                let index = usize::try_from(self.integer(cursor, frame)?)
                    .map_err(|_| AmlError::IndexOutOfBounds)?;
                let length = usize::try_from(self.integer(cursor, frame)?)
                    .map_err(|_| AmlError::IndexOutOfBounds)?;
                let value = mid(source, index, length)?;
                let target = self.target(cursor, frame)?;
                self.store(target, value.clone(), frame)?;
                Ok(value)
            },
            byte if is_name_start(byte) => {
                cursor.rewind_one();
                let candidate = name_string(cursor, &frame.scope)?;
                let path = self
                    .resolve_existing(&candidate)
                    .ok_or_else(|| AmlError::NotFound(candidate.clone()))?;
                let arg_count = match self.namespace.get(&path) {
                    Some(NamespaceObject::Method(method)) => method.arg_count,
                    Some(NamespaceObject::BuiltinMethod(BuiltinMethod::Osi)) => 1,
                    Some(NamespaceObject::External { arg_count, .. }) => *arg_count,
                    _ => 0,
                };
                let mut args = Vec::with_capacity(usize::from(arg_count));
                for _ in 0..arg_count {
                    args.push(self.term(cursor, frame)?);
                }
                self.evaluate_object(&path, &args)
            },
            _ => Err(AmlError::UnsupportedOpcode(opcode, cursor.offset() - 1)),
        }
    }

    fn target(&mut self, cursor: &mut Cursor<'_>, frame: &Frame) -> Result<Target, AmlError> {
        let opcode = cursor.read_u8()?;
        match opcode {
            0x00 => Ok(Target::Discard),
            0x60..=0x67 => Ok(Target::Local(usize::from(opcode - 0x60))),
            0x68..=0x6e => Ok(Target::Arg(usize::from(opcode - 0x68))),
            byte if is_name_start(byte) => {
                cursor.rewind_one();
                Ok(Target::Name(name_string(cursor, &frame.scope)?))
            },
            _ => Err(AmlError::InvalidTarget),
        }
    }

    fn load_target(&mut self, target: &Target, frame: &Frame) -> Result<u64, AmlError> {
        let value = match target {
            Target::Discard => AmlValue::Integer(0),
            Target::Local(index) => frame.locals[*index].clone(),
            Target::Arg(index) => frame.args[*index].clone(),
            Target::Name(path) => {
                let path = self
                    .resolve_existing(path)
                    .ok_or_else(|| AmlError::NotFound(path.clone()))?;
                self.evaluate_object(&path, &[])?
            },
        };
        to_integer(value)
    }

    fn store(
        &mut self,
        target: Target,
        value: AmlValue,
        frame: &mut Frame,
    ) -> Result<(), AmlError> {
        match target {
            Target::Discard => Ok(()),
            Target::Local(index) => {
                frame.locals[index] = value;
                Ok(())
            },
            Target::Arg(index) => {
                frame.args[index] = value;
                Ok(())
            },
            Target::Name(candidate) => {
                let path = self.resolve_existing(&candidate).unwrap_or(candidate);
                let object = self.namespace.get(&path).cloned();
                match object {
                    Some(NamespaceObject::Field(field)) => {
                        self.write_field(&field, to_integer(value)?)
                    },
                    Some(NamespaceObject::Value(_)) => {
                        *self.namespace.get_mut(&path).expect("object disappeared") =
                            NamespaceObject::Value(value);
                        Ok(())
                    },
                    None => self.namespace.define(path, NamespaceObject::Value(value)),
                    _ => Err(AmlError::InvalidTarget),
                }
            },
        }
    }

    fn read_field(&self, field: &super::namespace::FieldUnit) -> Result<AmlValue, AmlError> {
        let region = match self.namespace.get(&field.region) {
            Some(NamespaceObject::OperationRegion(region)) => *region,
            _ => return Err(AmlError::InvalidRegion),
        };
        let end = field
            .bit_offset
            .checked_add(field.bit_length)
            .ok_or(AmlError::InvalidField)?;
        if field.bit_length == 0 || field.bit_length > 64 || end > region.length.saturating_mul(8) {
            return Err(AmlError::InvalidField);
        }
        let mut value = 0u64;
        for output_bit in 0..field.bit_length {
            let region_bit = field.bit_offset + output_bit;
            let address = region
                .offset
                .checked_add(region_bit / 8)
                .ok_or(AmlError::InvalidRegion)?;
            let byte = self.handler.read(region.space, address, 8)? as u8;
            value |= u64::from((byte >> (region_bit % 8)) & 1) << output_bit;
        }
        Ok(AmlValue::Integer(value))
    }

    fn write_field(&self, field: &super::namespace::FieldUnit, value: u64) -> Result<(), AmlError> {
        let region = match self.namespace.get(&field.region) {
            Some(NamespaceObject::OperationRegion(region)) => *region,
            _ => return Err(AmlError::InvalidRegion),
        };
        let end = field
            .bit_offset
            .checked_add(field.bit_length)
            .ok_or(AmlError::InvalidField)?;
        if field.bit_length == 0 || field.bit_length > 64 || end > region.length.saturating_mul(8) {
            return Err(AmlError::InvalidField);
        }
        // UpdateRule is FieldFlags bits 6:5. Preserve (0) performs a byte RMW;
        // WriteAsOnes/WriteAsZeros choose the initial byte accordingly.
        let update_rule = (field.flags >> 5) & 0x03;
        let first_byte = field.bit_offset / 8;
        let last_byte = (end - 1) / 8;
        for byte_index in first_byte..=last_byte {
            let address = region
                .offset
                .checked_add(byte_index)
                .ok_or(AmlError::InvalidRegion)?;
            let mut byte = match update_rule {
                0 => self.handler.read(region.space, address, 8)? as u8,
                1 => 0xff,
                2 => 0,
                _ => return Err(AmlError::InvalidField),
            };
            for bit in 0..8u64 {
                let absolute = byte_index * 8 + bit;
                if absolute < field.bit_offset || absolute >= end {
                    continue;
                }
                let source = absolute - field.bit_offset;
                let mask = 1u8 << bit;
                if value & (1u64 << source) != 0 {
                    byte |= mask;
                } else {
                    byte &= !mask;
                }
            }
            self.handler
                .write(region.space, address, 8, u64::from(byte))?;
        }
        Ok(())
    }
}

fn boolean(value: bool) -> AmlValue {
    AmlValue::Integer(if value { u64::MAX } else { 0 })
}

fn to_integer(value: AmlValue) -> Result<u64, AmlError> {
    match value {
        AmlValue::Integer(value) => Ok(value),
        AmlValue::Buffer(bytes) if bytes.len() <= 8 => {
            let mut array = [0u8; 8];
            array[..bytes.len()].copy_from_slice(&bytes);
            Ok(u64::from_le_bytes(array))
        },
        AmlValue::String(value) => {
            let value = value.strip_prefix("0x").unwrap_or(&value);
            u64::from_str_radix(value, 16).map_err(|_| AmlError::TypeMismatch("integer"))
        },
        _ => Err(AmlError::TypeMismatch("integer")),
    }
}

fn to_buffer(value: AmlValue) -> Result<AmlValue, AmlError> {
    let bytes = match value {
        AmlValue::Buffer(bytes) => bytes,
        AmlValue::Integer(value) => value.to_le_bytes().to_vec(),
        AmlValue::String(value) => value.into_bytes(),
        _ => return Err(AmlError::TypeMismatch("buffer")),
    };
    if bytes.len() > MAX_BUFFER_SIZE {
        return Err(AmlError::LimitExceeded("buffer size"));
    }
    Ok(AmlValue::Buffer(bytes))
}

fn concat(left: AmlValue, right: AmlValue) -> Result<AmlValue, AmlError> {
    match (left, right) {
        (AmlValue::String(mut left), AmlValue::String(right)) => {
            if left.len().saturating_add(right.len()) > MAX_BUFFER_SIZE {
                return Err(AmlError::LimitExceeded("string size"));
            }
            left.push_str(&right);
            Ok(AmlValue::String(left))
        },
        (left, right) => {
            let AmlValue::Buffer(mut left) = to_buffer(left)? else {
                unreachable!()
            };
            let AmlValue::Buffer(right) = to_buffer(right)? else {
                unreachable!()
            };
            if left.len().saturating_add(right.len()) > MAX_BUFFER_SIZE {
                return Err(AmlError::LimitExceeded("buffer size"));
            }
            left.extend_from_slice(&right);
            Ok(AmlValue::Buffer(left))
        },
    }
}

fn mid(value: AmlValue, index: usize, length: usize) -> Result<AmlValue, AmlError> {
    match value {
        AmlValue::Buffer(value) => {
            let start = index.min(value.len());
            let end = start.saturating_add(length).min(value.len());
            Ok(AmlValue::Buffer(value[start..end].to_vec()))
        },
        AmlValue::String(value) => {
            let bytes = value.into_bytes();
            let start = index.min(bytes.len());
            let end = start.saturating_add(length).min(bytes.len());
            let text = String::from_utf8(bytes[start..end].to_vec())
                .map_err(|_| AmlError::TypeMismatch("ASCII string"))?;
            Ok(AmlValue::String(text))
        },
        _ => Err(AmlError::TypeMismatch("buffer or string")),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::acpi::aml::namespace::NamespaceObject;
    use crate::acpi::aml::region::DenyRegionHandler;

    #[test]
    fn evaluates_arithmetic_method() {
        let mut namespace = Namespace::default();
        namespace
            .insert(
                "\\TEST".to_string(),
                NamespaceObject::Method(Method {
                    arg_count: 0,
                    serialized: false,
                    sync_level: 0,
                    scope: "\\".to_string(),
                    body: vec![0xa4, 0x72, 0x0a, 2, 0x0a, 3, 0x00],
                }),
            )
            .unwrap();
        let mut evaluator = Evaluator::new(&mut namespace, &DenyRegionHandler);
        assert_eq!(
            evaluator.evaluate("\\TEST", &[]).unwrap(),
            AmlValue::Integer(5)
        );
    }
}
