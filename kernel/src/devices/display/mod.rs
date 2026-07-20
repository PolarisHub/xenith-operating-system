//! VMware-oriented accelerated display foundation.
//!
//! [`svga2`] binds the VMware SVGA II PCI function (`15ad:0405`) without
//! replacing Xenith's boot framebuffer. It validates and attaches the current
//! frontbuffer, initializes the real legacy FIFO, publishes damaged regions,
//! and exposes capability-gated 2D copies and fences. 3D, screen objects,
//! guest-memory regions, interrupts, cursor planes, and hotplug are deliberately
//! not claimed by this module.

pub mod protocol;
mod svga2;

pub use protocol::{CopyRect, Mode, ModeLimits, ModeRequest, Rect};
pub use svga2::{
    device_info, insert_fence, is_attached, present, present_and_wait, rectangle_copy,
    rectangle_copy_and_wait, register_pci_driver, synchronize, wait_fence, DeviceInfo, SvgaError,
};
