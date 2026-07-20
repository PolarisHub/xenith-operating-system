//! Command Output and Response Input Ring Buffer transport.

use core::hint::spin_loop;
use core::ptr;

use super::codec::Verb;
use super::dma::{DmaError, DmaRegion};
use super::registers::{
    Mmio, CORBCTL, CORBCTL_RUN, CORBLBASE, CORBRP, CORBRP_RESET, CORBSIZE, CORBSTS,
    CORBSTS_MEMORY_ERROR, CORBUBASE, CORBWP, RINTCNT, RIRBCTL, RIRBCTL_DMA_ENABLE, RIRBLBASE,
    RIRBSIZE, RIRBSTS, RIRBSTS_OVERRUN, RIRBSTS_RESPONSE, RIRBUBASE, RIRBWP, RIRBWP_RESET,
};

const CORB_OFFSET: usize = 0;
// A 2 KiB boundary works for every architected RIRB size and is stronger
// than the common 128-byte minimum alignment.
const RIRB_OFFSET: usize = 0x800;
const RING_ARENA_BYTES: usize = 0x1000;
const FAST_POLL_COUNT: usize = 1024;
const COMMAND_TIMEOUT_MS: u16 = 100;

/// Architected HDA ring sizes and their register encodings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingSize {
    Entries2,
    Entries16,
    Entries256,
}

impl RingSize {
    #[must_use]
    pub const fn entries(self) -> u16 {
        match self {
            Self::Entries2 => 2,
            Self::Entries16 => 16,
            Self::Entries256 => 256,
        }
    }

    #[must_use]
    pub const fn encoding(self) -> u8 {
        match self {
            Self::Entries2 => 0,
            Self::Entries16 => 1,
            Self::Entries256 => 2,
        }
    }

    /// Select the largest supported size from capability bits 7:4.
    #[must_use]
    pub const fn largest_supported(size_register: u8) -> Option<Self> {
        let capabilities = size_register >> 4;
        if capabilities & 0b0100 != 0 {
            Some(Self::Entries256)
        } else if capabilities & 0b0010 != 0 {
            Some(Self::Entries16)
        } else if capabilities & 0b0001 != 0 {
            Some(Self::Entries2)
        } else {
            None
        }
    }
}

/// One decoded 64-bit RIRB entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response {
    pub data: u32,
    pub codec: u8,
    pub unsolicited: bool,
}

impl Response {
    #[must_use]
    pub const fn decode(raw: u64) -> Self {
        let extension = (raw >> 32) as u32;
        Self {
            data: raw as u32,
            codec: (extension & 0x0f) as u8,
            unsolicited: extension & (1 << 4) != 0,
        }
    }
}

/// Errors produced by ring setup or a bounded command transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingError {
    Dma(DmaError),
    UnsupportedCorbSize,
    UnsupportedRirbSize,
    CorbStopTimeout,
    RirbStopTimeout,
    CorbResetClearTimeout,
    RirbResetTimeout,
    CorbStartTimeout,
    RirbStartTimeout,
    CorbSizeRejected,
    RirbSizeRejected,
    DmaAddressRejected,
    CorbFull,
    ResponseTimeout,
    CorbMemoryError,
    RirbOverrun,
    ResponseFromWrongCodec,
}

impl From<DmaError> for RingError {
    fn from(value: DmaError) -> Self {
        Self::Dma(value)
    }
}

/// Owned CORB/RIRB memory plus software-maintained pointers.
pub struct CommandRings {
    registers: Mmio,
    dma: Option<DmaRegion>,
    corb_size: RingSize,
    rirb_size: RingSize,
    corb_write_pointer: u16,
    rirb_read_pointer: u16,
    unsolicited_dropped: u64,
}

impl CommandRings {
    /// Allocate and program both DMA rings, leaving their engines running.
    pub fn initialize(registers: Mmio, supports_64bit: bool) -> Result<Self, RingError> {
        stop_engine(registers, CORBCTL, CORBCTL_RUN, RingError::CorbStopTimeout)?;
        stop_engine(
            registers,
            RIRBCTL,
            RIRBCTL_DMA_ENABLE,
            RingError::RirbStopTimeout,
        )?;

        let corb_size = RingSize::largest_supported(registers.read8(CORBSIZE))
            .ok_or(RingError::UnsupportedCorbSize)?;
        let rirb_size = RingSize::largest_supported(registers.read8(RIRBSIZE))
            .ok_or(RingError::UnsupportedRirbSize)?;
        let max_address = (!supports_64bit).then_some(u64::from(u32::MAX));
        let dma = DmaRegion::allocate(RING_ARENA_BYTES, max_address)?;
        let corb_address = dma
            .physical_at(CORB_OFFSET)
            .ok_or(RingError::Dma(DmaError::SizeOverflow))?;
        let rirb_address = dma
            .physical_at(RIRB_OFFSET)
            .ok_or(RingError::Dma(DmaError::SizeOverflow))?;
        debug_assert_eq!(corb_address & 0x7f, 0);
        debug_assert_eq!(rirb_address & 0x7f, 0);

        registers.write8(CORBSIZE, corb_size.encoding());
        if registers.read8(CORBSIZE) & 0x03 != corb_size.encoding() {
            return Err(RingError::CorbSizeRejected);
        }
        registers.write32(CORBLBASE, corb_address as u32);
        registers.write32(CORBUBASE, (corb_address >> 32) as u32);
        if registers.read32(CORBLBASE) != corb_address as u32
            || registers.read32(CORBUBASE) != (corb_address >> 32) as u32
        {
            return Err(RingError::DmaAddressRejected);
        }
        if !reset_corb_read_pointer(registers)? {
            // Some controllers self-clear CORBRP.RST before software can
            // observe it asserted. The final full-register zero check below
            // is still mandatory, so a stale hardware read pointer cannot be
            // mistaken for a successful reset.
            ::log::debug!("hda: CORBRP reset bit self-cleared before observation");
        }
        registers.write16(CORBWP, 0);
        registers.write8(CORBSTS, CORBSTS_MEMORY_ERROR);

        registers.write8(RIRBSIZE, rirb_size.encoding());
        if registers.read8(RIRBSIZE) & 0x03 != rirb_size.encoding() {
            return Err(RingError::RirbSizeRejected);
        }
        registers.write32(RIRBLBASE, rirb_address as u32);
        registers.write32(RIRBUBASE, (rirb_address >> 32) as u32);
        if registers.read32(RIRBLBASE) != rirb_address as u32
            || registers.read32(RIRBUBASE) != (rirb_address >> 32) as u32
        {
            return Err(RingError::DmaAddressRejected);
        }
        registers.write16(RIRBWP, RIRBWP_RESET);
        if !super::wait::until(super::wait::HARDWARE_TIMEOUT_MS, || {
            // RIRBWP.RST is write-only and always reads zero. The low byte
            // is the hardware pointer whose reset must be observed.
            registers.read16(RIRBWP) & 0xff == 0
        }) {
            return Err(RingError::RirbResetTimeout);
        }
        // One response is a useful polling cadence if interrupt delivery is
        // enabled later; RIRB DMA itself does not depend on interrupts.
        registers.write16(RINTCNT, 1);
        registers.write8(RIRBSTS, RIRBSTS_RESPONSE | RIRBSTS_OVERRUN);

        dma.sync_for_device();
        registers.write8(RIRBCTL, RIRBCTL_DMA_ENABLE);
        if let Err(error) = wait8(
            registers,
            RIRBCTL,
            RIRBCTL_DMA_ENABLE,
            true,
            RingError::RirbStartTimeout,
        ) {
            if !stop_command_engines(registers) {
                // Hardware may still own this address. Leaking one page is
                // safer than returning it to the frame allocator for reuse.
                core::mem::forget(dma);
            }
            return Err(error);
        }
        registers.write8(CORBCTL, CORBCTL_RUN);
        if let Err(error) = wait8(
            registers,
            CORBCTL,
            CORBCTL_RUN,
            true,
            RingError::CorbStartTimeout,
        ) {
            if !stop_command_engines(registers) {
                core::mem::forget(dma);
            }
            return Err(error);
        }

        Ok(Self {
            registers,
            dma: Some(dma),
            corb_size,
            rirb_size,
            corb_write_pointer: 0,
            rirb_read_pointer: 0,
            unsolicited_dropped: 0,
        })
    }

    #[must_use]
    pub const fn corb_size(&self) -> RingSize {
        self.corb_size
    }

    #[must_use]
    pub const fn rirb_size(&self) -> RingSize {
        self.rirb_size
    }

    #[must_use]
    pub const fn unsolicited_dropped(&self) -> u64 {
        self.unsolicited_dropped
    }

    /// Submit one verb and wait for its solicited response. Unsolicited
    /// responses are consumed and counted so they cannot block the ring.
    pub fn command(&mut self, registers: Mmio, verb: Verb) -> Result<Response, RingError> {
        self.check_status(registers)?;
        let corb_mask = self.corb_size.entries() - 1;
        let next = self.corb_write_pointer.wrapping_add(1) & corb_mask;
        let mut has_space = self.corb_has_space(registers, next, corb_mask)?;
        for _ in 0..FAST_POLL_COUNT {
            if has_space {
                break;
            }
            spin_loop();
            has_space = self.corb_has_space(registers, next, corb_mask)?;
        }
        for _ in 0..COMMAND_TIMEOUT_MS {
            if has_space {
                break;
            }
            super::wait::one_millisecond();
            has_space = self.corb_has_space(registers, next, corb_mask)?;
        }
        if !has_space {
            return Err(RingError::CorbFull);
        }

        // SAFETY: `next` is masked to the selected ring length, and the CORB
        // occupies the first 1024 bytes of the owned page.
        let dma = self.dma.as_mut().expect("live HDA rings retain DMA");
        unsafe {
            ptr::write_volatile(
                (dma.as_mut_ptr().add(CORB_OFFSET) as *mut u32).add(next as usize),
                verb.raw(),
            );
        }
        dma.sync_for_device();
        self.corb_write_pointer = next;
        registers.write16(CORBWP, next);

        for _ in 0..FAST_POLL_COUNT {
            if let Some(response) = self.poll_response(registers, verb)? {
                return Ok(response);
            }
            spin_loop();
        }
        for _ in 0..COMMAND_TIMEOUT_MS {
            super::wait::one_millisecond();
            if let Some(response) = self.poll_response(registers, verb)? {
                return Ok(response);
            }
        }
        Err(RingError::ResponseTimeout)
    }

    fn corb_has_space(
        &self,
        registers: Mmio,
        next: u16,
        corb_mask: u16,
    ) -> Result<bool, RingError> {
        self.check_status(registers)?;
        Ok(next != registers.read16(CORBRP) & corb_mask)
    }

    fn poll_response(
        &mut self,
        registers: Mmio,
        verb: Verb,
    ) -> Result<Option<Response>, RingError> {
        self.check_status(registers)?;
        let rirb_mask = self.rirb_size.entries() - 1;
        let hardware_write = registers.read16(RIRBWP) & rirb_mask;
        if hardware_write == self.rirb_read_pointer {
            return Ok(None);
        }

        self.rirb_read_pointer = self.rirb_read_pointer.wrapping_add(1) & rirb_mask;
        let dma = self.dma.as_ref().expect("live HDA rings retain DMA");
        dma.sync_for_cpu();
        // SAFETY: the software pointer is masked to the selected RIRB
        // length, whose maximum 2 KiB span begins at RIRB_OFFSET.
        let raw = unsafe {
            ptr::read_volatile(
                (dma.as_ptr().add(RIRB_OFFSET) as *const u64).add(self.rirb_read_pointer as usize),
            )
        };
        let response = Response::decode(raw);
        if response.unsolicited {
            self.unsolicited_dropped = self.unsolicited_dropped.saturating_add(1);
            return Ok(None);
        }
        if response.codec != verb.codec() {
            return Err(RingError::ResponseFromWrongCodec);
        }
        if registers.read8(RIRBSTS) & RIRBSTS_RESPONSE != 0 {
            registers.write8(RIRBSTS, RIRBSTS_RESPONSE);
        }
        Ok(Some(response))
    }

    fn check_status(&self, registers: Mmio) -> Result<(), RingError> {
        if registers.read8(CORBSTS) & CORBSTS_MEMORY_ERROR != 0 {
            return Err(RingError::CorbMemoryError);
        }
        if registers.read8(RIRBSTS) & RIRBSTS_OVERRUN != 0 {
            return Err(RingError::RirbOverrun);
        }
        Ok(())
    }
}

impl Drop for CommandRings {
    fn drop(&mut self) {
        // The owning controller is normally retained for kernel lifetime. If
        // later bring-up fails, stop both engines before `dma` releases the
        // backing page so hardware can never DMA into reallocated memory.
        let stopped = stop_command_engines(self.registers);
        if let Some(dma) = self.dma.take() {
            if stopped {
                drop(dma);
            } else {
                ::log::error!("hda: leaking command-ring DMA because an engine did not stop");
                core::mem::forget(dma);
            }
        }
    }
}

fn stop_command_engines(registers: Mmio) -> bool {
    registers.write8(CORBCTL, registers.read8(CORBCTL) & !CORBCTL_RUN);
    registers.write8(RIRBCTL, registers.read8(RIRBCTL) & !RIRBCTL_DMA_ENABLE);
    super::wait::until(super::wait::HARDWARE_TIMEOUT_MS, || {
        registers.read8(CORBCTL) & CORBCTL_RUN == 0
            && registers.read8(RIRBCTL) & RIRBCTL_DMA_ENABLE == 0
    })
}

fn stop_engine(
    registers: Mmio,
    register: usize,
    run_bit: u8,
    timeout: RingError,
) -> Result<(), RingError> {
    registers.write8(register, registers.read8(register) & !run_bit);
    wait8(registers, register, run_bit, false, timeout)
}

fn wait8(
    registers: Mmio,
    offset: usize,
    mask: u8,
    set: bool,
    timeout: RingError,
) -> Result<(), RingError> {
    if super::wait::until(super::wait::HARDWARE_TIMEOUT_MS, || {
        (registers.read8(offset) & mask != 0) == set
    }) {
        Ok(())
    } else {
        Err(timeout)
    }
}

/// Reset CORBRP using the architected assert/deassert sequence.
///
/// A few real and virtual controllers self-clear bit 15 immediately. Linux's
/// HDA core likewise treats failure to observe the asserted state as
/// diagnostic rather than fatal, then writes zero and requires the complete
/// register to read back as zero. Returning `false` records that behavior
/// without weakening the final pointer validation.
fn reset_corb_read_pointer(registers: Mmio) -> Result<bool, RingError> {
    registers.write16(CORBRP, CORBRP_RESET);
    let assertion_observed = super::wait::until(super::wait::HARDWARE_TIMEOUT_MS, || {
        registers.read16(CORBRP) & CORBRP_RESET != 0
    });

    registers.write16(CORBRP, 0);
    if super::wait::until(super::wait::HARDWARE_TIMEOUT_MS, || {
        // Check the pointer bits as well as RST. Merely seeing bit 15 clear
        // is insufficient if the controller retained a non-zero read index.
        registers.read16(CORBRP) == 0
    }) {
        Ok(assertion_observed)
    } else {
        Err(RingError::CorbResetClearTimeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_size_chooses_largest_advertised_value() {
        assert_eq!(
            RingSize::largest_supported(0x70),
            Some(RingSize::Entries256)
        );
        assert_eq!(RingSize::largest_supported(0x30), Some(RingSize::Entries16));
        assert_eq!(RingSize::largest_supported(0x10), Some(RingSize::Entries2));
        assert_eq!(RingSize::largest_supported(0x00), None);
        assert_eq!(RingSize::Entries256.entries(), 256);
        assert_eq!(RingSize::Entries256.encoding(), 2);
    }

    #[test]
    fn pointer_arithmetic_wraps_at_each_power_of_two_size() {
        for size in [
            RingSize::Entries2,
            RingSize::Entries16,
            RingSize::Entries256,
        ] {
            let mask = size.entries() - 1;
            assert_eq!((mask.wrapping_add(1)) & mask, 0);
        }
    }

    #[test]
    fn response_extension_decodes_codec_and_unsolicited_bit() {
        let solicited = Response::decode((5u64 << 32) | 0x1234_5678);
        assert_eq!(solicited.data, 0x1234_5678);
        assert_eq!(solicited.codec, 5);
        assert!(!solicited.unsolicited);
        let unsolicited = Response::decode((0x1eu64 << 32) | 0xaabb_ccdd);
        assert_eq!(unsolicited.codec, 14);
        assert!(unsolicited.unsolicited);
    }
}
