//! Intel High Definition Audio controller register definitions and MMIO views.

use core::ptr;

/// Minimum architected HDA MMIO window used by the global register block.
pub const GLOBAL_REGISTER_BYTES: usize = 0x80;
/// First stream-descriptor register block.
pub const STREAM_BASE: usize = 0x80;
/// Bytes occupied by one stream descriptor.
pub const STREAM_STRIDE: usize = 0x20;
/// INTCTL reserves bits 0..=29 for stream interrupt enables.
pub const MAX_STREAMS: usize = 30;

pub const GCAP: usize = 0x00;
pub const VMIN: usize = 0x02;
pub const VMAJ: usize = 0x03;
pub const GCTL: usize = 0x08;
pub const WAKEEN: usize = 0x0c;
pub const STATESTS: usize = 0x0e;
pub const INTCTL: usize = 0x20;
pub const INTSTS: usize = 0x24;
pub const WALCLK: usize = 0x30;
pub const SSYNC: usize = 0x38;
pub const CORBLBASE: usize = 0x40;
pub const CORBUBASE: usize = 0x44;
pub const CORBWP: usize = 0x48;
pub const CORBRP: usize = 0x4a;
pub const CORBCTL: usize = 0x4c;
pub const CORBSTS: usize = 0x4d;
pub const CORBSIZE: usize = 0x4e;
pub const RIRBLBASE: usize = 0x50;
pub const RIRBUBASE: usize = 0x54;
pub const RIRBWP: usize = 0x58;
pub const RINTCNT: usize = 0x5a;
pub const RIRBCTL: usize = 0x5c;
pub const RIRBSTS: usize = 0x5d;
pub const RIRBSIZE: usize = 0x5e;
pub const DPLBASE: usize = 0x70;
pub const DPUBASE: usize = 0x74;

pub const GCTL_CRST: u32 = 1 << 0;
pub const GCTL_UNSOL: u32 = 1 << 8;
pub const INTCTL_GIE: u32 = 1 << 31;
pub const INTCTL_CIE: u32 = 1 << 30;

pub const CORBCTL_RUN: u8 = 1 << 1;
pub const CORBSTS_MEMORY_ERROR: u8 = 1 << 0;
pub const CORBRP_RESET: u16 = 1 << 15;
pub const RIRBCTL_DMA_ENABLE: u8 = 1 << 1;
pub const RIRBSTS_RESPONSE: u8 = 1 << 0;
pub const RIRBSTS_OVERRUN: u8 = 1 << 2;
pub const RIRBWP_RESET: u16 = 1 << 15;

/// Decoded Global Capabilities register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub output_streams: u8,
    pub input_streams: u8,
    pub bidirectional_streams: u8,
    /// Number of SDO signals. `None` preserves the architecturally reserved
    /// `11b` encoding instead of inventing a fourth output.
    pub serial_data_outputs: Option<u8>,
    pub supports_64bit_dma: bool,
}

impl Capabilities {
    #[must_use]
    pub const fn decode(raw: u16) -> Self {
        Self {
            output_streams: ((raw >> 12) & 0x0f) as u8,
            input_streams: ((raw >> 8) & 0x0f) as u8,
            bidirectional_streams: ((raw >> 3) & 0x1f) as u8,
            serial_data_outputs: match (raw >> 1) & 0x03 {
                0 => Some(1),
                1 => Some(2),
                2 => Some(4),
                _ => None,
            },
            supports_64bit_dma: raw & 1 != 0,
        }
    }

    #[must_use]
    pub const fn total_streams(self) -> usize {
        self.output_streams as usize
            + self.input_streams as usize
            + self.bidirectional_streams as usize
    }

    /// Absolute stream-descriptor index for an output-stream ordinal.
    #[must_use]
    pub const fn output_stream_index(self, ordinal: usize) -> Option<usize> {
        if ordinal < self.output_streams as usize {
            Some(self.input_streams as usize + ordinal)
        } else {
            None
        }
    }
}

/// HDA controller interface revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

/// Copyable volatile view over one controller's MMIO BAR.
#[derive(Clone, Copy)]
pub struct Mmio {
    base: u64,
}

impl Mmio {
    /// Construct an MMIO view from an HHDM virtual address.
    ///
    /// # Safety
    ///
    /// `base` must map a live HDA controller BAR for the lifetime of every
    /// copy of the returned handle.
    #[must_use]
    pub const unsafe fn new(base: u64) -> Self {
        Self { base }
    }

    #[inline]
    #[must_use]
    pub fn read8(self, offset: usize) -> u8 {
        // SAFETY: guaranteed by `new`; callers use architected byte registers.
        unsafe { ptr::read_volatile((self.base + offset as u64) as *const u8) }
    }

    #[inline]
    #[must_use]
    pub fn read16(self, offset: usize) -> u16 {
        // SAFETY: guaranteed by `new`; all 16-bit offsets used are aligned.
        unsafe { ptr::read_volatile((self.base + offset as u64) as *const u16) }
    }

    #[inline]
    #[must_use]
    pub fn read32(self, offset: usize) -> u32 {
        // SAFETY: guaranteed by `new`; all 32-bit offsets used are aligned.
        unsafe { ptr::read_volatile((self.base + offset as u64) as *const u32) }
    }

    #[inline]
    pub fn write8(self, offset: usize, value: u8) {
        // SAFETY: same MMIO/register-width invariant as `read8`.
        unsafe { ptr::write_volatile((self.base + offset as u64) as *mut u8, value) }
    }

    #[inline]
    pub fn write16(self, offset: usize, value: u16) {
        // SAFETY: same MMIO/register-width invariant as `read16`.
        unsafe { ptr::write_volatile((self.base + offset as u64) as *mut u16, value) }
    }

    #[inline]
    pub fn write32(self, offset: usize, value: u32) {
        // SAFETY: same MMIO/register-width invariant as `read32`.
        unsafe { ptr::write_volatile((self.base + offset as u64) as *mut u32, value) }
    }

    #[must_use]
    pub fn capabilities(self) -> Capabilities {
        Capabilities::decode(self.read16(GCAP))
    }

    #[must_use]
    pub fn version(self) -> Version {
        Version {
            major: self.read8(VMAJ),
            minor: self.read8(VMIN),
        }
    }

    #[must_use]
    pub const fn stream(self, index: usize) -> Option<StreamRegisters> {
        if index < MAX_STREAMS {
            Some(StreamRegisters {
                mmio: self,
                offset: STREAM_BASE + index * STREAM_STRIDE,
                index,
            })
        } else {
            None
        }
    }
}

// SAFETY: this is a plain address handle. Device ownership and higher-level
// serialization are enforced by the controller registry.
unsafe impl Send for Mmio {}
unsafe impl Sync for Mmio {}

/// Volatile view over one 32-byte stream-descriptor block.
#[derive(Clone, Copy)]
pub struct StreamRegisters {
    mmio: Mmio,
    offset: usize,
    index: usize,
}

impl StreamRegisters {
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }

    /// Read the 24-bit SDnCTL without touching the adjacent RW1C status byte.
    #[must_use]
    pub fn control(self) -> u32 {
        u32::from(self.mmio.read16(self.offset))
            | (u32::from(self.mmio.read8(self.offset + 2)) << 16)
    }

    /// Write the 24-bit SDnCTL without accidentally clearing SDnSTS.
    pub fn write_control(self, value: u32) {
        self.mmio.write16(self.offset, value as u16);
        self.mmio.write8(self.offset + 2, (value >> 16) as u8);
    }

    pub fn clear_status(self, mask: u8) {
        self.mmio.write8(self.offset + 3, mask);
    }

    #[must_use]
    pub fn position(self) -> u32 {
        self.mmio.read32(self.offset + 4)
    }

    pub fn write_cyclic_buffer_length(self, bytes: u32) {
        self.mmio.write32(self.offset + 8, bytes);
    }

    pub fn write_last_valid_index(self, index: u16) {
        self.mmio.write16(self.offset + 0x0c, index);
    }

    pub fn write_format(self, format: u16) {
        self.mmio.write16(self.offset + 0x12, format);
    }

    pub fn write_bdl_address(self, address: u64) {
        self.mmio.write32(self.offset + 0x18, address as u32);
        self.mmio
            .write32(self.offset + 0x1c, (address >> 32) as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_decode_all_fields_and_output_offset() {
        let caps = Capabilities::decode((4 << 12) | (3 << 8) | (5 << 3) | (2 << 1) | 1);
        assert_eq!(caps.output_streams, 4);
        assert_eq!(caps.input_streams, 3);
        assert_eq!(caps.bidirectional_streams, 5);
        assert_eq!(caps.serial_data_outputs, Some(4));
        assert!(caps.supports_64bit_dma);
        assert_eq!(caps.total_streams(), 12);
        assert_eq!(caps.output_stream_index(0), Some(3));
        assert_eq!(caps.output_stream_index(3), Some(6));
        assert_eq!(caps.output_stream_index(4), None);
    }

    #[test]
    fn serial_data_output_encoding_preserves_reserved_value() {
        assert_eq!(Capabilities::decode(0 << 1).serial_data_outputs, Some(1));
        assert_eq!(Capabilities::decode(1 << 1).serial_data_outputs, Some(2));
        assert_eq!(Capabilities::decode(2 << 1).serial_data_outputs, Some(4));
        assert_eq!(Capabilities::decode(3 << 1).serial_data_outputs, None);
    }

    #[test]
    fn stream_index_is_bounded_by_interrupt_bitmap() {
        // No MMIO access occurs in this test; the synthetic address is only
        // retained in the returned handles.
        let mmio = unsafe { Mmio::new(0x1000) };
        assert_eq!(mmio.stream(0).map(StreamRegisters::index), Some(0));
        assert_eq!(
            mmio.stream(MAX_STREAMS - 1).map(StreamRegisters::index),
            Some(29)
        );
        assert!(mmio.stream(MAX_STREAMS).is_none());
    }

    #[test]
    fn architected_global_offsets_do_not_alias_reserved_space() {
        assert_eq!(WALCLK, 0x30);
        assert_eq!(SSYNC, 0x38);
        assert_eq!(CORBLBASE, 0x40);
        assert_eq!(RIRBLBASE, 0x50);
    }
}
