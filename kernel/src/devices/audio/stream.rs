//! HDA PCM format, buffer descriptor, and stream-engine programming.
//!
//! This module deliberately stops at the controller DMA boundary. Starting
//! audible playback also requires codec-widget graph discovery and routing,
//! converter stream/channel assignment, pin power, gain, and EAPD handling;
//! none of those may be guessed safely from controller registers alone.

use super::registers::StreamRegisters;

const STREAM_CTL_RESET: u32 = 1 << 0;
const STREAM_CTL_RUN: u32 = 1 << 1;
const STREAM_CTL_IOCE: u32 = 1 << 2;
const STREAM_CTL_FEIE: u32 = 1 << 3;
const STREAM_CTL_DEIE: u32 = 1 << 4;
const STREAM_CTL_TAG_MASK: u32 = 0x0f << 20;
const STREAM_STATUS_CLEAR: u8 = (1 << 2) | (1 << 3) | (1 << 4);

/// PCM sample container width supported by the HDA stream format field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleBits {
    Bits8,
    Bits16,
    Bits20,
    Bits24,
    Bits32,
}

impl SampleBits {
    #[must_use]
    const fn encoding(self) -> u16 {
        match self {
            Self::Bits8 => 0,
            Self::Bits16 => 1,
            Self::Bits20 => 2,
            Self::Bits24 => 3,
            Self::Bits32 => 4,
        }
    }

    #[must_use]
    pub const fn bytes_per_sample(self) -> u8 {
        match self {
            Self::Bits8 => 1,
            Self::Bits16 => 2,
            Self::Bits20 | Self::Bits24 | Self::Bits32 => 4,
        }
    }
}

/// Validated HDA stream-format word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcmFormat {
    raw: u16,
    rate_hz: u32,
    bits: SampleBits,
    channels: u8,
}

impl PcmFormat {
    /// Encode an exact rate from the 48 kHz or 44.1 kHz base families.
    #[must_use]
    pub fn new(rate_hz: u32, bits: SampleBits, channels: u8) -> Option<Self> {
        if !(1..=16).contains(&channels) {
            return None;
        }
        let mut rate_fields = None;
        for (base_rate, base_bit) in [(48_000u32, 0u16), (44_100u32, 1u16)] {
            for multiplier in 1u32..=4 {
                for divisor in 1u32..=8 {
                    if base_rate.checked_mul(multiplier)? / divisor == rate_hz
                        && base_rate * multiplier % divisor == 0
                    {
                        rate_fields = Some(
                            (base_bit << 14)
                                | (((multiplier - 1) as u16) << 11)
                                | (((divisor - 1) as u16) << 8),
                        );
                        break;
                    }
                }
                if rate_fields.is_some() {
                    break;
                }
            }
            if rate_fields.is_some() {
                break;
            }
        }
        let raw = rate_fields? | (bits.encoding() << 4) | u16::from(channels - 1);
        Some(Self {
            raw,
            rate_hz,
            bits,
            channels,
        })
    }

    #[must_use]
    pub const fn raw(self) -> u16 {
        self.raw
    }

    #[must_use]
    pub const fn rate_hz(self) -> u32 {
        self.rate_hz
    }

    #[must_use]
    pub const fn bits(self) -> SampleBits {
        self.bits
    }

    #[must_use]
    pub const fn channels(self) -> u8 {
        self.channels
    }

    #[must_use]
    pub const fn frame_bytes(self) -> u32 {
        self.bits.bytes_per_sample() as u32 * self.channels as u32
    }
}

/// One 16-byte HDA Buffer Descriptor List Entry (BDLE).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferDescriptor {
    address: u64,
    length: u32,
    flags: u32,
}

impl BufferDescriptor {
    /// Validate the buffer alignment, whole-word/sample length, and the
    /// controller's advertised DMA address width before creating a
    /// device-visible descriptor.
    #[must_use]
    pub const fn new(
        address: u64,
        length: u32,
        interrupt_on_completion: bool,
        format: PcmFormat,
        supports_64bit_dma: bool,
    ) -> Option<Self> {
        let end = match address.checked_add(length.saturating_sub(1) as u64) {
            Some(end) => end,
            None => return None,
        };
        if address == 0
            || address & 0x7f != 0
            || length < 2
            || length & 1 != 0
            || !length.is_multiple_of(format.bits.bytes_per_sample() as u32)
            || end >= (1u64 << 52)
            || (!supports_64bit_dma && end > u32::MAX as u64)
        {
            return None;
        }
        Some(Self {
            address,
            length,
            flags: interrupt_on_completion as u32,
        })
    }

    #[must_use]
    pub const fn interrupt_on_completion(self) -> bool {
        self.flags & 1 != 0
    }

    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }

    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }
}

/// Validated register programming for a prepared cyclic BDL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamConfig {
    pub bdl_address: u64,
    pub cyclic_buffer_bytes: u32,
    pub descriptor_count: u16,
    pub stream_tag: u8,
    pub format: PcmFormat,
}

impl StreamConfig {
    #[must_use]
    pub const fn validate(self, supports_64bit_dma: bool) -> bool {
        let bdl_bytes = self.descriptor_count as u64 * 16;
        let bdl_end = match self.bdl_address.checked_add(bdl_bytes.saturating_sub(1)) {
            Some(end) => end,
            None => return false,
        };
        self.bdl_address != 0
            && self.bdl_address & 0x7f == 0
            && bdl_end < (1u64 << 52)
            && (supports_64bit_dma || bdl_end <= u32::MAX as u64)
            && self.cyclic_buffer_bytes != 0
            && self
                .cyclic_buffer_bytes
                .is_multiple_of(self.format.frame_bytes())
            && self.descriptor_count >= 2
            && self.descriptor_count <= 256
            && self.stream_tag >= 1
            && self.stream_tag <= 15
    }
}

/// Failure while stopping, resetting, or programming a stream descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamError {
    InvalidConfiguration,
    StopTimeout,
    ResetAssertTimeout,
    ResetClearTimeout,
}

/// Safe sequencing wrapper around one hardware stream descriptor.
pub struct StreamDescriptor {
    registers: StreamRegisters,
    supports_64bit_dma: bool,
}

impl StreamDescriptor {
    #[must_use]
    pub(crate) const fn new(registers: StreamRegisters, supports_64bit_dma: bool) -> Self {
        Self {
            registers,
            supports_64bit_dma,
        }
    }

    #[must_use]
    pub const fn index(&self) -> usize {
        self.registers.index()
    }

    #[must_use]
    pub fn running(&self) -> bool {
        self.registers.control() & STREAM_CTL_RUN != 0
    }

    #[must_use]
    pub fn position(&self) -> u32 {
        self.registers.position()
    }

    pub fn stop(&self) -> Result<(), StreamError> {
        self.registers
            .write_control(self.registers.control() & !STREAM_CTL_RUN);
        wait_control(
            self.registers,
            STREAM_CTL_RUN,
            false,
            StreamError::StopTimeout,
        )
    }

    pub fn reset(&self) -> Result<(), StreamError> {
        self.stop()?;
        self.registers
            .write_control(self.registers.control() | STREAM_CTL_RESET);
        wait_control(
            self.registers,
            STREAM_CTL_RESET,
            true,
            StreamError::ResetAssertTimeout,
        )?;
        self.registers
            .write_control(self.registers.control() & !STREAM_CTL_RESET);
        wait_control(
            self.registers,
            STREAM_CTL_RESET,
            false,
            StreamError::ResetClearTimeout,
        )
    }

    /// Program a stopped stream. This does not start DMA or configure a codec
    /// converter/pin path, so it cannot be mistaken for audible playback.
    pub fn program(&self, config: StreamConfig) -> Result<(), StreamError> {
        if !config.validate(self.supports_64bit_dma) {
            return Err(StreamError::InvalidConfiguration);
        }
        self.reset()?;
        self.registers.clear_status(STREAM_STATUS_CLEAR);
        self.registers
            .write_cyclic_buffer_length(config.cyclic_buffer_bytes);
        self.registers
            .write_last_valid_index(config.descriptor_count - 1);
        self.registers.write_format(config.format.raw());
        self.registers.write_bdl_address(config.bdl_address);
        let mut control = self.registers.control();
        control &= !(STREAM_CTL_TAG_MASK
            | STREAM_CTL_IOCE
            | STREAM_CTL_FEIE
            | STREAM_CTL_DEIE
            | STREAM_CTL_RUN);
        control |= u32::from(config.stream_tag) << 20;
        self.registers.write_control(control);
        Ok(())
    }

    /// Start a previously programmed stream in polling mode. Codec routing
    /// must already have been configured by a higher layer.
    pub fn start_polling(&self) {
        self.registers
            .write_control(self.registers.control() | STREAM_CTL_RUN);
    }
}

fn wait_control(
    registers: StreamRegisters,
    mask: u32,
    set: bool,
    timeout: StreamError,
) -> Result<(), StreamError> {
    if super::wait::until(super::wait::HARDWARE_TIMEOUT_MS, || {
        (registers.control() & mask != 0) == set
    }) {
        Ok(())
    } else {
        Err(timeout)
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn common_pcm_formats_encode_to_architected_words() {
        assert_eq!(
            PcmFormat::new(48_000, SampleBits::Bits16, 2).unwrap().raw(),
            0x0011
        );
        assert_eq!(
            PcmFormat::new(44_100, SampleBits::Bits16, 2).unwrap().raw(),
            0x4011
        );
        assert_eq!(
            PcmFormat::new(96_000, SampleBits::Bits24, 6).unwrap().raw(),
            0x0835
        );
        assert!(PcmFormat::new(47_999, SampleBits::Bits16, 2).is_none());
        assert!(PcmFormat::new(48_000, SampleBits::Bits16, 0).is_none());
        assert!(PcmFormat::new(48_000, SampleBits::Bits16, 17).is_none());
    }

    #[test]
    fn sample_container_width_drives_frame_size() {
        assert_eq!(SampleBits::Bits8.bytes_per_sample(), 1);
        assert_eq!(SampleBits::Bits16.bytes_per_sample(), 2);
        assert_eq!(SampleBits::Bits20.bytes_per_sample(), 4);
        assert_eq!(SampleBits::Bits24.bytes_per_sample(), 4);
        assert_eq!(SampleBits::Bits32.bytes_per_sample(), 4);
        assert_eq!(
            PcmFormat::new(48_000, SampleBits::Bits24, 6)
                .unwrap()
                .frame_bytes(),
            24
        );
    }

    #[test]
    fn descriptor_layout_and_constraints_match_hardware() {
        let pcm16 = PcmFormat::new(48_000, SampleBits::Bits16, 2).unwrap();
        let pcm24 = PcmFormat::new(48_000, SampleBits::Bits24, 2).unwrap();
        assert_eq!(size_of::<BufferDescriptor>(), 16);
        let descriptor = BufferDescriptor::new(0x20_000, 4096, true, pcm16, false).unwrap();
        assert_eq!(descriptor.address(), 0x20_000);
        assert_eq!(descriptor.length(), 4096);
        assert!(descriptor.interrupt_on_completion());
        assert!(BufferDescriptor::new(0x20_001, 4096, false, pcm16, true).is_none());
        assert!(BufferDescriptor::new(0x20_000, 1, false, pcm16, true).is_none());
        assert!(BufferDescriptor::new(0x20_000, 3, false, pcm16, true).is_none());
        assert!(BufferDescriptor::new(0x20_000, 6, false, pcm24, true).is_none());
        assert!(BufferDescriptor::new(1u64 << 52, 4096, false, pcm16, true).is_none());
        assert!(BufferDescriptor::new(0x1_0000_0000, 4096, false, pcm16, false).is_none());
    }

    #[test]
    fn stream_config_rejects_invalid_bdl_bounds_and_tags() {
        let format = PcmFormat::new(48_000, SampleBits::Bits16, 2).unwrap();
        let valid = StreamConfig {
            bdl_address: 0x10_000,
            cyclic_buffer_bytes: 8192,
            descriptor_count: 2,
            stream_tag: 1,
            format,
        };
        assert!(valid.validate(false));
        assert!(!StreamConfig {
            descriptor_count: 1,
            ..valid
        }
        .validate(true));
        assert!(!StreamConfig {
            stream_tag: 0,
            ..valid
        }
        .validate(true));
        assert!(!StreamConfig {
            bdl_address: u64::from(u32::MAX) + 1,
            ..valid
        }
        .validate(false));
        assert!(!StreamConfig {
            bdl_address: 0xffff_ff80,
            descriptor_count: 256,
            ..valid
        }
        .validate(false));
        assert!(!StreamConfig {
            cyclic_buffer_bytes: 8191,
            ..valid
        }
        .validate(true));
    }
}
