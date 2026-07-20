//! # xenith-boot
//!
//! Safe wrappers around the boot information the Limine bootloader hands to
//! the Xenith kernel.
//!
//! Limine populates a `limine::BootInfo` structure at boot time and leaves a
//! `'static` reference to it for the kernel entry point. The raw struct uses
//! raw pointers and small integer tags, which are easy to misuse; this crate
//! wraps it in [`BootInfo`], a safe accessor surface that yields strongly
//! typed [`MemoryRegion`]s, [`Module`]s, framebuffer descriptors, and the
//! higher-half direct-map offset.
//!
//! The wrapper never copies the memory map into an allocator — it reads the
//! Limine arrays in place. Callers that need to retain entries past boot-info
//! reclamation should copy the returned [`MemoryRegion`]s out (they are
//! `Copy`).

#![no_std]

use core::ffi::CStr;

use xenith_types::{PhysAddr, VirtAddr};

pub mod region;

pub use region::{MemoryRegion, RegionKind};

/// A loaded kernel module, as reported by Limine.
///
/// Modules are arbitrary blobs the bootloader placed in physical memory at
/// the kernel's request (for example, an initial ramdisk or a userspace
/// init binary). The `start` address is physical; convert it to a virtual
/// address via [`BootInfo::phys_to_virt`] when you need to read the bytes
/// through the higher-half direct map.
#[derive(Clone, Copy, Debug)]
pub struct Module<'a> {
    /// Physical start address of the module bytes.
    pub start: PhysAddr,
    /// Length of the module in bytes.
    pub len: u64,
    /// The module's path string, as given on the boot command line. May be
    /// empty if the bootloader did not supply one.
    pub path: &'a str,
    /// Optional per-module command line. Most modules have none; the field
    /// is an empty string in that case.
    pub cmdline: &'a str,
}

impl Module<'_> {
    /// Returns the physical address one past the last byte of the module.
    #[inline]
    pub fn end(&self) -> Option<PhysAddr> {
        let e = self.start.as_u64().checked_add(self.len)?;
        PhysAddr::new(e)
    }
}

/// A framebuffer descriptor, safe to read from ring 0.
///
/// This is a thin copy of the relevant fields of `limine::Framebuffer`. We
/// copy out the address and geometry so callers do not have to touch the raw
/// boot-info structure (which lives in bootloader-reclaimable memory).
#[derive(Clone, Copy, Debug)]
pub struct Framebuffer {
    /// Physical address of the pixel buffer.
    pub phys_addr: PhysAddr,
    /// Pitch in bytes per row.
    pub pitch: u16,
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
    /// Bits per pixel.
    pub bpp: u16,
    /// Least-significant bit of the red channel.
    pub red_shift: u8,
    /// Number of bits in the red channel.
    pub red_size: u8,
    /// Least-significant bit of the green channel.
    pub green_shift: u8,
    /// Number of bits in the green channel.
    pub green_size: u8,
    /// Least-significant bit of the blue channel.
    pub blue_shift: u8,
    /// Number of bits in the blue channel.
    pub blue_size: u8,
    /// Total byte size of the visible buffer (`pitch * height`).
    pub size: usize,
}

/// Safe wrapper around the Limine boot info.
///
/// Constructed once at kernel entry from the `'static` reference Limine
/// leaves in a well-known location. All accessors are safe and perform the
/// raw-pointer juggling internally.
#[derive(Clone, Copy)]
pub struct BootInfo {
    inner: &'static limine::BootInfo,
}

impl BootInfo {
    /// Wrap a static Limine boot info reference.
    ///
    /// The caller is responsible for ensuring `inner` points at a valid,
    /// fully-populated `limine::BootInfo` for the lifetime of the program
    /// (Limine guarantees this for the reference it hands the kernel).
    #[inline]
    pub const fn new(inner: &'static limine::BootInfo) -> Self {
        Self { inner }
    }

    /// Borrow the underlying Limine boot info for access to features this
    /// wrapper does not yet expose.
    #[inline]
    pub const fn raw(&self) -> &'static limine::BootInfo {
        self.inner
    }

    /// Returns the first framebuffer, if the bootloader provided one.
    ///
    /// Xenith currently drives a single console framebuffer; this accessor
    /// returns the first entry of Limine's framebuffer array. Callers that
    /// need every framebuffer can use [`framebuffers`](Self::framebuffers).
    pub fn framebuffer(&self) -> Option<Framebuffer> {
        self.framebuffers().next()
    }

    /// Iterates over all framebuffers the bootloader reported.
    ///
    /// Each entry is copied out into a [`Framebuffer`] value so the caller
    /// does not hold a reference into bootloader-reclaimable memory.
    pub fn framebuffers(&self) -> FramebufferIter {
        FramebufferIter {
            ptr: self.inner.framebuffer,
            count: self.inner.framebuffer_count,
            index: 0,
        }
    }

    /// Iterates over the physical memory map, yielding safe [`MemoryRegion`]s.
    ///
    /// The iterator reads the raw Limine `MemmapEntry` array in place and
    /// converts each entry into a [`MemoryRegion`] with a resolved
    /// [`RegionKind`]. Entries are yielded in bootloader order; the kernel
    /// page allocator is expected to filter to [`RegionKind::Usable`].
    pub fn memory_map(&self) -> MemoryMapIter {
        MemoryMapIter {
            ptr: self.inner.memmap,
            count: self.inner.memmap_count,
            index: 0,
        }
    }

    /// Returns the higher-half direct-map offset Limine configured.
    ///
    /// Every physical address `p` is mapped at `hhdm_offset + p`, so the
    /// kernel can reach any physical byte without allocating page tables.
    /// Use [`phys_to_virt`](Self::phys_to_virt) for the arithmetic.
    pub fn hhdm_offset(&self) -> VirtAddr {
        // Limine guarantees the HHDM offset is a valid canonical virtual
        // address in the upper half; new_truncate is appropriate because the
        // value is already a complete, aligned virtual address.
        VirtAddr::new_truncate(self.inner.hhdm_offset)
    }

    /// Returns the ACPI RSDP physical address, if the bootloader found one.
    ///
    /// Returns `None` when no ACPI tables are present (for example on some
    /// non-PC platforms or when booted via a legacy path). The kernel ACPI
    /// layer treats `None` as "fall back to PCI IO-port probing".
    pub fn rsdp(&self) -> Option<PhysAddr> {
        let p = self.inner.rsdp;
        if p == 0 {
            None
        } else {
            PhysAddr::new(p)
        }
    }

    /// Iterates over the modules the bootloader loaded at kernel request.
    pub fn modules(&self) -> ModuleIter {
        ModuleIter {
            ptr: self.inner.modules,
            count: self.inner.modules_count,
            index: 0,
        }
    }

    /// Returns the kernel command line, if the bootloader supplied one.
    ///
    /// The string is borrowed directly from the boot info and lives for the
    /// lifetime of the program (Limine keeps the cmdline in
    /// bootloader-reclaimable memory, but Xenith never reclaims that range,
    /// so the borrow is `'static`). Returns `None` if no command line was
    /// provided or the pointer is null.
    pub fn kernel_cmdline(&self) -> Option<&'static str> {
        let ptr = self.inner.kernel_cmdline;
        if ptr.is_null() {
            return None;
        }
        // SAFETY: Limine guarantees `kernel_cmdline` is a valid NUL-terminated
        // C string residing in memory that persists for the kernel's lifetime.
        // We only borrow it read-only, so the shared aliasing is fine.
        let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
        core::str::from_utf8(bytes).ok()
    }

    /// Translate a physical address to a virtual address through the
    /// higher-half direct map.
    ///
    /// This is pure arithmetic: `virt = hhdm_offset + phys`. It does not
    /// allocate page tables and presumes the HHDM direct map covers the full
    /// physical address space, which Limine guarantees for the regions the
    /// kernel will touch.
    #[inline]
    pub fn phys_to_virt(&self, phys: PhysAddr) -> VirtAddr {
        // Adding the physical offset to the HHDM base yields the canonical
        // direct-mapped virtual address. new_truncate keeps the result valid
        // even if the addition wraps within the 64-bit space (it never does
        // for canonical HHDM bases below the upper-half boundary).
        VirtAddr::new_truncate(self.inner.hhdm_offset + phys.as_u64())
    }
}

impl core::fmt::Debug for BootInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BootInfo")
            .field(
                "hhdm_offset",
                &format_args!("0x{:016x}", self.inner.hhdm_offset),
            )
            .field("framebuffer_count", &self.inner.framebuffer_count)
            .field("memmap_count", &self.inner.memmap_count)
            .field("modules_count", &self.inner.modules_count)
            .field("rsdp", &format_args!("0x{:016x}", self.inner.rsdp))
            .finish()
    }
}

/// Iterator over the Limine memory map yielding [`MemoryRegion`]s.
///
/// Created by [`BootInfo::memory_map`]. The iterator walks the raw
/// `MemmapEntry` array in place; each entry is converted to a safe
/// `MemoryRegion` on the fly.
#[derive(Clone, Debug)]
pub struct MemoryMapIter {
    ptr: *const limine::MemmapEntry,
    count: u64,
    index: u64,
}

impl Iterator for MemoryMapIter {
    type Item = MemoryRegion;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        // SAFETY: `ptr` points at an array of `count` valid `MemmapEntry`
        // records supplied by the bootloader. We index within bounds
        // (`index < count`) and read a `Copy` value, so the shared read is
        // sound. Limine guarantees the array is valid for the kernel's
        // lifetime, but we only borrow it transiently here and copy the
        // fields out into a `MemoryRegion`.
        let entry = unsafe { &*self.ptr.add(self.index as usize) };
        self.index += 1;
        let start = PhysAddr::new_truncate(entry.base);
        let len = entry.length;
        let kind = RegionKind::from_raw(entry.kind);
        Some(MemoryRegion { start, len, kind })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.count - self.index) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for MemoryMapIter {
    fn len(&self) -> usize {
        (self.count - self.index) as usize
    }
}

impl core::iter::FusedIterator for MemoryMapIter {}

/// Iterator over the Limine modules yielding [`Module`]s.
///
/// Created by [`BootInfo::modules`].
#[derive(Clone, Debug)]
pub struct ModuleIter {
    ptr: *const limine::Module,
    count: u64,
    index: u64,
}

impl Iterator for ModuleIter {
    type Item = Module<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        // SAFETY: `ptr` points at an array of `count` valid `Module`
        // records supplied by the bootloader. We index in bounds and read
        // fields. The `path` and `cmdline` C strings are also bootloader-
        // owned and valid for the kernel's lifetime; Xenith never reclaims
        // the module metadata region, so the `'static` borrow is sound.
        let entry = unsafe { &*self.ptr.add(self.index as usize) };
        self.index += 1;

        let start = PhysAddr::new_truncate(entry.base as u64);
        let len = entry.length;

        let path = cstr_to_str(entry.path);
        let cmdline = cstr_to_str(entry.cmdline);

        Some(Module {
            start,
            len,
            path,
            cmdline,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.count - self.index) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ModuleIter {
    fn len(&self) -> usize {
        (self.count - self.index) as usize
    }
}

impl core::iter::FusedIterator for ModuleIter {}

/// Iterator over the Limine framebuffers yielding [`Framebuffer`]s.
///
/// Created by [`BootInfo::framebuffers`]. Limine exposes the framebuffer list
/// as a pointer-to-pointer array; the iterator dereferences each slot and
/// copies the geometry out.
#[derive(Clone, Debug)]
pub struct FramebufferIter {
    ptr: *const *const limine::Framebuffer,
    count: u64,
    index: u64,
}

impl Iterator for FramebufferIter {
    type Item = Framebuffer;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        // SAFETY: `ptr` points at an array of `count` pointers, each either
        // null or pointing at a valid `Framebuffer`. We skip null slots so a
        // partially-populated array does not yield invalid entries.
        let slot = unsafe { *self.ptr.add(self.index as usize) };
        self.index += 1;
        if slot.is_null() {
            return self.next();
        }
        // SAFETY: the slot points at a valid, populated Framebuffer owned by
        // the bootloader. We read its fields by shared reference and copy
        // them out; no mutation occurs.
        let fb = unsafe { &*slot };
        Some(Framebuffer {
            phys_addr: PhysAddr::new_truncate(fb.address as u64),
            pitch: fb.pitch,
            width: fb.width,
            height: fb.height,
            bpp: fb.bpp,
            red_shift: fb.red_shift,
            red_size: fb.red_size,
            green_shift: fb.green_shift,
            green_size: fb.green_size,
            blue_shift: fb.blue_shift,
            blue_size: fb.blue_size,
            size: (fb.pitch as usize) * (fb.height as usize),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.count - self.index) as usize;
        (remaining, Some(remaining))
    }
}

impl core::iter::FusedIterator for FramebufferIter {}

/// Convert a raw Limine C string pointer into a Rust `&'static str`.
///
/// Returns an empty string for a null pointer rather than `None` so callers
/// can use the field directly without a double option. Non-UTF8 strings also
/// fall back to empty — Limine paths are conventionally ASCII, so this is
/// only a defensive measure.
///
/// # Safety
///
/// `ptr` must either be null or point at a NUL-terminated C string that
/// remains valid for the kernel's lifetime (the boot info guarantees this).
fn cstr_to_str(ptr: *const core::ffi::c_char) -> &'static str {
    if ptr.is_null() {
        return "";
    }
    // SAFETY: caller (and the boot info contract) guarantees the pointer is
    // either null (handled above) or a valid NUL-terminated C string valid
    // for `'static`. We read it read-only.
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    core::str::from_utf8(bytes).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::FramebufferIter;

    #[test]
    fn framebuffer_iterator_preserves_native_channel_layout() {
        let raw = limine::Framebuffer {
            address: 0x1000 as *mut u8,
            width: 320,
            height: 200,
            pitch: 1280,
            bpp: 32,
            red_shift: 0,
            red_size: 10,
            green_shift: 10,
            green_size: 10,
            blue_shift: 20,
            blue_size: 10,
        };
        let slots = [&raw as *const limine::Framebuffer];
        let mut iter = FramebufferIter {
            ptr: slots.as_ptr(),
            count: 1,
            index: 0,
        };

        let framebuffer = iter.next().expect("one framebuffer");
        assert_eq!(framebuffer.red_shift, 0);
        assert_eq!(framebuffer.red_size, 10);
        assert_eq!(framebuffer.green_shift, 10);
        assert_eq!(framebuffer.green_size, 10);
        assert_eq!(framebuffer.blue_shift, 20);
        assert_eq!(framebuffer.blue_size, 10);
        assert_eq!(framebuffer.size, 1280 * 200);
    }
}
