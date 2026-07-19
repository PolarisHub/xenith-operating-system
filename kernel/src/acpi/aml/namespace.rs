//! AML namespace objects and canonical path handling.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::region::RegionSpace;
use super::value::AmlValue;
use super::AmlError;

#[derive(Clone, Debug)]
pub struct Method {
    pub(crate) arg_count: u8,
    pub(crate) serialized: bool,
    pub(crate) sync_level: u8,
    pub(crate) scope: String,
    pub(crate) body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegionTerm {
    Integer(u64),
    Reference(String),
    Add {
        left: alloc::boxed::Box<Self>,
        right: alloc::boxed::Box<Self>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationRegionBounds {
    Resolved {
        offset: u64,
        length: u64,
    },
    Deferred {
        offset: RegionTerm,
        length: RegionTerm,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRegion {
    pub space: RegionSpace,
    pub bounds: OperationRegionBounds,
}

#[derive(Clone, Debug)]
pub struct FieldUnit {
    pub region: String,
    pub bit_offset: u64,
    pub bit_length: u64,
    pub flags: u8,
}

#[derive(Clone, Copy, Debug)]
pub enum BuiltinMethod {
    Osi,
}

#[derive(Clone, Debug)]
pub enum NamespaceObject {
    Value(AmlValue),
    Method(Method),
    Device,
    Processor,
    ThermalZone,
    PowerResource,
    OperationRegion(OperationRegion),
    Field(FieldUnit),
    BuiltinMethod(BuiltinMethod),
    Alias(String),
    External { object_type: u8, arg_count: u8 },
}

#[derive(Clone, Debug, Default)]
pub struct Namespace {
    objects: BTreeMap<String, NamespaceObject>,
}

impl Namespace {
    pub const MAX_OBJECTS: usize = 16_384;

    pub fn insert(&mut self, path: String, object: NamespaceObject) -> Result<(), AmlError> {
        if self.objects.len() >= Self::MAX_OBJECTS {
            return Err(AmlError::LimitExceeded("namespace objects"));
        }
        if self.objects.insert(path.clone(), object).is_some() {
            return Err(AmlError::DuplicateName(path));
        }
        Ok(())
    }

    /// Firmware frequently repeats `External` declarations. A real definition
    /// replaces an external declaration, while two real definitions remain an
    /// error so malformed tables cannot silently shadow objects.
    pub fn define(&mut self, path: String, object: NamespaceObject) -> Result<(), AmlError> {
        match self.objects.get(&path) {
            Some(NamespaceObject::External { .. }) => {
                self.objects.insert(path, object);
                Ok(())
            },
            None => self.insert(path, object),
            Some(_) => Err(AmlError::DuplicateName(path)),
        }
    }

    pub fn get(&self, path: &str) -> Option<&NamespaceObject> {
        self.objects.get(path)
    }

    pub fn get_mut(&mut self, path: &str) -> Option<&mut NamespaceObject> {
        self.objects.get_mut(path)
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.objects.keys().map(String::as_str)
    }

    pub(crate) fn resolve_alias<'a>(&'a self, path: &'a str) -> Result<&'a str, AmlError> {
        let mut current = path;
        for _ in 0..16 {
            match self.get(current) {
                Some(NamespaceObject::Alias(target)) => current = target,
                _ => return Ok(current),
            }
        }
        Err(AmlError::LimitExceeded("alias depth"))
    }

    /// Resolve an AML name reference using the namespace's upward-search
    /// rules. `candidate` is the canonical path produced relative to the
    /// current scope; if it is absent, progressively enclosing scopes are
    /// searched for the same final NameSeg.
    pub(crate) fn search_existing(&self, candidate: &str) -> Option<String> {
        if self.get(candidate).is_some() {
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
            if self.get(&path).is_some() {
                return Some(path);
            }
        }
        let root = alloc::format!("\\{leaf}");
        self.get(&root).map(|_| root)
    }
}

pub(crate) fn split_canonical(path: &str) -> Vec<&str> {
    path.trim_start_matches('\\')
        .split('.')
        .filter(|part| !part.is_empty())
        .collect()
}

pub(crate) fn canonical_from_segments(segments: &[String]) -> String {
    if segments.is_empty() {
        return "\\".to_string();
    }
    let mut path = String::from("\\");
    for (index, segment) in segments.iter().enumerate() {
        if index != 0 {
            path.push('.');
        }
        path.push_str(segment);
    }
    path
}

pub(crate) fn parent_scope(path: &str) -> String {
    let mut segments: Vec<String> = split_canonical(path)
        .into_iter()
        .map(ToString::to_string)
        .collect();
    segments.pop();
    canonical_from_segments(&segments)
}

pub(crate) fn join_path(scope: &str, segment: &str) -> String {
    if scope == "\\" {
        alloc::format!("\\{segment}")
    } else {
        alloc::format!("{scope}.{segment}")
    }
}

/// Normalize a human-written path. Segments shorter than four bytes are
/// underscore-padded, matching ACPI's NameSeg representation.
pub fn normalize_path(path: &str) -> Result<String, AmlError> {
    if path.is_empty() {
        return Err(AmlError::InvalidName);
    }
    let mut segments = Vec::new();
    for raw in path.trim_start_matches('\\').split('.') {
        if raw.is_empty() {
            continue;
        }
        if raw.len() > 4 || !raw.bytes().all(valid_name_char) {
            return Err(AmlError::InvalidName);
        }
        let mut segment = raw.to_ascii_uppercase();
        while segment.len() < 4 {
            segment.push('_');
        }
        segments.push(segment);
    }
    Ok(canonical_from_segments(&segments))
}

pub(crate) fn valid_name_char(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upward_search_finds_previously_declared_enclosing_name() {
        let mut namespace = Namespace::default();
        namespace
            .insert(
                "\\_SB_.ECFG".into(),
                NamespaceObject::Value(AmlValue::Integer(0xffc0_0000)),
            )
            .unwrap();

        assert_eq!(
            namespace.search_existing("\\_SB_.PCI0.ISA_.ECFG"),
            Some("\\_SB_.ECFG".into())
        );
    }
}
