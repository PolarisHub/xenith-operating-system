//! Legacy boot-handoff records accepted by Xenith's optional Limine path.
//!
//! The active Xenith loader uses `xenith_abi::XenithBootInfo`. These C-layout records retain
//! the older aggregate handoff used by this kernel without pulling a bootloader runtime crate.

#![no_std]

use core::ffi::c_char;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct MemmapEntry {
    pub base: u64,
    pub length: u64,
    pub kind: u32,
    pub reserved: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Framebuffer {
    pub address: *mut u8,
    pub width: u16,
    pub height: u16,
    pub pitch: u16,
    pub bpp: u16,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Module {
    pub base: *const u8,
    pub length: u64,
    pub path: *const c_char,
    pub cmdline: *const c_char,
}

/// Aggregate compatibility handoff used by Xenith's legacy entry point.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BootInfo {
    pub hhdm_offset: u64,
    pub framebuffer: *const *const Framebuffer,
    pub framebuffer_count: u64,
    pub memmap: *const MemmapEntry,
    pub memmap_count: u64,
    pub modules: *const Module,
    pub modules_count: u64,
    pub rsdp: u64,
    pub kernel_cmdline: *const c_char,
}

impl BootInfo {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            hhdm_offset: 0,
            framebuffer: core::ptr::null(),
            framebuffer_count: 0,
            memmap: core::ptr::null(),
            memmap_count: 0,
            modules: core::ptr::null(),
            modules_count: 0,
            rsdp: 0,
            kernel_cmdline: core::ptr::null(),
        }
    }
}

// Loader memory becomes immutable before the handoff and remains mapped for kernel lifetime.
unsafe impl Send for BootInfo {}
unsafe impl Sync for BootInfo {}
