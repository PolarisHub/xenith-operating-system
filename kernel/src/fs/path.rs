//! Allocation-backed, `no_std` path parsing and working-directory state.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use super::vfs::{self, FsError, NodeRef};
use crate::sync::SpinLock;

pub const MAX_PATH: usize = 4096;
pub const MAX_NAME: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path<'a> {
    inner: &'a str,
}

impl<'a> Path<'a> {
    pub const fn new(path: &'a str) -> Self {
        Self { inner: path }
    }

    pub const fn as_str(self) -> &'a str {
        self.inner
    }

    pub fn is_absolute(self) -> bool {
        self.inner.as_bytes().first().copied() == Some(b'/')
    }

    pub fn components(self) -> Components<'a> {
        Components {
            parts: self.inner.split('/'),
        }
    }

    pub fn resolve(self) -> Result<NodeRef, FsError> {
        vfs::resolve(&self)
    }
}

impl fmt::Display for Path<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.inner)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component<'a> {
    CurDir,
    ParentDir,
    Normal(&'a str),
}

pub struct Components<'a> {
    parts: core::str::Split<'a, char>,
}

impl<'a> Iterator for Components<'a> {
    type Item = Component<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.parts.next()? {
                "" | "." => continue,
                ".." => return Some(Component::ParentDir),
                name => return Some(Component::Normal(name)),
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathBuf {
    inner: String,
}

impl PathBuf {
    pub fn root() -> Self {
        Self {
            inner: "/".to_string(),
        }
    }

    pub fn normalize(path: &str) -> Result<Self, FsError> {
        normalize_with_base(path, "/")
    }

    pub fn from_absolute(path: &str) -> Result<Self, FsError> {
        if !path.starts_with('/') {
            return Err(FsError::InvalidInput);
        }
        normalize_with_base(path, "/")
    }

    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    pub fn as_path(&self) -> Path<'_> {
        Path::new(self.as_str())
    }

    pub fn is_root(&self) -> bool {
        self.inner == "/"
    }

    pub fn join(&self, child: &str) -> Result<Self, FsError> {
        normalize_with_base(child, self.as_str())
    }

    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        let split = self.inner.rfind('/').unwrap_or(0);
        if split == 0 {
            Some(Self::root())
        } else {
            Some(Self {
                inner: self.inner[..split].to_string(),
            })
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        if self.is_root() {
            None
        } else {
            self.inner.rsplit('/').next()
        }
    }
}

impl fmt::Display for PathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn validate_name(name: &str) -> Result<(), FsError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(FsError::InvalidInput);
    }
    if name.len() > MAX_NAME {
        return Err(FsError::NameTooLong);
    }
    Ok(())
}

fn push_components(parts: &mut Vec<String>, input: &str) -> Result<(), FsError> {
    for raw in input.split('/') {
        match raw {
            "" | "." => {},
            ".." => {
                parts.pop();
            },
            name => {
                validate_name(name)?;
                parts.push(name.to_string());
            },
        }
    }
    Ok(())
}

fn normalize_with_base(path: &str, base: &str) -> Result<PathBuf, FsError> {
    if path.is_empty() || path.contains('\0') {
        return Err(FsError::InvalidInput);
    }
    if path.len() > MAX_PATH {
        return Err(FsError::NameTooLong);
    }

    let mut parts = Vec::new();
    if !path.starts_with('/') {
        push_components(&mut parts, base)?;
    }
    push_components(&mut parts, path)?;

    let mut normalized = String::from("/");
    for (index, part) in parts.iter().enumerate() {
        if index != 0 {
            normalized.push('/');
        }
        normalized.push_str(part);
    }
    if normalized.len() > MAX_PATH {
        return Err(FsError::NameTooLong);
    }
    Ok(PathBuf { inner: normalized })
}

static CURRENT_DIR: SpinLock<Option<PathBuf>> = SpinLock::new(None);

pub fn current_dir() -> PathBuf {
    CURRENT_DIR.lock().clone().unwrap_or_else(PathBuf::root)
}

pub fn set_current_dir(path: PathBuf) {
    *CURRENT_DIR.lock() = Some(path);
}

pub fn absolutize(path: &Path<'_>) -> Result<PathBuf, FsError> {
    if path.is_absolute() {
        PathBuf::from_absolute(path.as_str())
    } else {
        normalize_with_base(path.as_str(), current_dir().as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_dot_and_parent_components() {
        let path = normalize_with_base("../bin/./sh", "/usr/local").unwrap();
        assert_eq!(path.as_str(), "/usr/bin/sh");
    }

    #[test]
    fn parent_never_escapes_root() {
        assert_eq!(PathBuf::normalize("/../../etc").unwrap().as_str(), "/etc");
    }
}
