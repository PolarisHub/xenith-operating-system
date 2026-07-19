//! Process start block shared by the loader and freestanding programs.

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Startup {
    pub argc: usize,
    pub argv: *const *const u8,
    pub envc: usize,
    pub envp: *const *const u8,
}

/// Validated view over the loader-provided environment vector.
pub struct Environment<'a> {
    startup: &'a Startup,
}

impl Startup {
    /// Read one NUL-terminated argument supplied by the kernel loader.
    ///
    /// # Safety
    /// The start block and all pointers must have been validated and mapped by the loader.
    pub unsafe fn argument(&self, index: usize) -> Option<&'static [u8]> {
        if index >= self.argc || self.argv.is_null() {
            return None;
        }
        // SAFETY: bounded by argc under the caller's loader contract.
        let ptr = unsafe { *self.argv.add(index) };
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        // SAFETY: argv entries are NUL-terminated within mapped user memory.
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: the preceding scan established a readable range.
        Some(unsafe { core::slice::from_raw_parts(ptr, len) })
    }

    /// Establish a safe environment accessor after validating the loader block once.
    ///
    /// # Safety
    /// `self`, `envp`, and every entry through `envc` must remain mapped and each
    /// entry must be NUL-terminated for the returned view's lifetime.
    pub unsafe fn environment(&self) -> Environment<'_> {
        Environment { startup: self }
    }
}

impl<'a> Environment<'a> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.startup.envc
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return one complete `NAME=value` entry.
    #[must_use]
    pub fn entry(&self, index: usize) -> Option<&'a [u8]> {
        if index >= self.startup.envc || self.startup.envp.is_null() {
            return None;
        }
        // SAFETY: Environment's constructor establishes the vector and string contract.
        let ptr = unsafe { *self.startup.envp.add(index) };
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        // SAFETY: constructor contract guarantees a mapped, NUL-terminated entry.
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: the scan above proved this readable range.
        Some(unsafe { core::slice::from_raw_parts(ptr, len) })
    }

    /// Look up an environment variable without exposing the raw `envp` pointers.
    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<&'a [u8]> {
        for index in 0..self.len() {
            let Some(entry) = self.entry(index) else {
                continue;
            };
            if entry.starts_with(name) && entry.get(name.len()) == Some(&b'=') {
                return Some(&entry[name.len() + 1..]);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_environment_view_indexes_and_looks_up_entries() {
        let first = b"HOME=/\0";
        let second = b"TERM=xenith\0";
        let pointers = [first.as_ptr(), second.as_ptr()];
        let startup = Startup {
            argc: 0,
            argv: core::ptr::null(),
            envc: pointers.len(),
            envp: pointers.as_ptr(),
        };
        // SAFETY: both local entries remain alive and NUL-terminated for the view.
        let environment = unsafe { startup.environment() };
        assert_eq!(environment.len(), 2);
        assert_eq!(environment.entry(0), Some(&b"HOME=/"[..]));
        assert_eq!(environment.get(b"TERM"), Some(&b"xenith"[..]));
        assert_eq!(environment.get(b"MISSING"), None);
    }
}
