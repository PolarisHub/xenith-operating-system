//! Pure VMware SVGA II protocol primitives.
//!
//! Register numbers, capability bits, FIFO indices, and command identifiers
//! follow VMware's X11/MIT-licensed `svga_reg.h`, carried upstream in Linux at
//! `drivers/gpu/drm/vmwgfx/device_include/svga_reg.h`.  This file deliberately
//! contains no port I/O or raw pointers so its validation and ring arithmetic
//! can be exercised by ordinary host tests.

/// VMware's PCI vendor identifier.
pub const PCI_VENDOR_VMWARE: u16 = 0x15ad;
/// PCI device identifier for the port-I/O based VMware SVGA II adapter.
pub const PCI_DEVICE_SVGA2: u16 = 0x0405;

const SVGA_MAGIC: u32 = 0x0090_0000;
const fn make_id(version: u32) -> u32 {
    (SVGA_MAGIC << 8) | version
}

/// Highest protocol version supported by the SVGA II PCI function.
pub const SVGA_ID_2: u32 = make_id(2);
/// Value returned when protocol negotiation fails.
pub const SVGA_ID_INVALID: u32 = u32::MAX;

/// Byte offset of the register-index port within BAR0.
pub const INDEX_PORT_OFFSET: u16 = 0;
/// Byte offset of the register-value port within BAR0.
pub const VALUE_PORT_OFFSET: u16 = 1;

/// SVGA device register indices.
pub mod register {
    pub const ID: u32 = 0;
    pub const ENABLE: u32 = 1;
    pub const WIDTH: u32 = 2;
    pub const HEIGHT: u32 = 3;
    pub const MAX_WIDTH: u32 = 4;
    pub const MAX_HEIGHT: u32 = 5;
    pub const DEPTH: u32 = 6;
    pub const BITS_PER_PIXEL: u32 = 7;
    pub const RED_MASK: u32 = 9;
    pub const GREEN_MASK: u32 = 10;
    pub const BLUE_MASK: u32 = 11;
    pub const BYTES_PER_LINE: u32 = 12;
    pub const FB_START: u32 = 13;
    pub const FB_OFFSET: u32 = 14;
    pub const VRAM_SIZE: u32 = 15;
    pub const FB_SIZE: u32 = 16;
    pub const CAPABILITIES: u32 = 17;
    pub const MEM_START: u32 = 18;
    pub const MEM_SIZE: u32 = 19;
    pub const CONFIG_DONE: u32 = 20;
    pub const SYNC: u32 = 21;
    pub const BUSY: u32 = 22;
    pub const MEM_REGS: u32 = 30;
}

/// Values used with [`register::ENABLE`].
pub const ENABLE_DISABLE: u32 = 0;
pub const ENABLE_ENABLE: u32 = 1 << 0;

/// Generic FIFO work notification used with [`register::SYNC`].
pub const SYNC_GENERIC: u32 = 1;

/// Byte-indexed FIFO header cells. Each index names one little-endian `u32`.
pub mod fifo {
    pub const MIN: u32 = 0;
    pub const MAX: u32 = 1;
    pub const NEXT_CMD: u32 = 2;
    pub const STOP: u32 = 3;
    pub const CAPABILITIES: u32 = 4;
    pub const FENCE: u32 = 6;
    pub const RESERVED: u32 = 14;
    // Indices 32..=287 are the 256 legacy 3D capability cells. These final
    // extended header indices therefore follow them rather than the small
    // cursor/register block above.
    pub const BUSY: u32 = 290;
    pub const NUM_REGS: u32 = 291;
}

/// Device capability bitmap from [`register::CAPABILITIES`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceCapabilities(u32);

impl DeviceCapabilities {
    pub const RECT_COPY: u32 = 0x0000_0002;
    pub const EXTENDED_FIFO: u32 = 0x0000_8000;

    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, capability: u32) -> bool {
        self.0 & capability == capability
    }

    #[must_use]
    pub const fn rect_copy(self) -> bool {
        self.contains(Self::RECT_COPY)
    }

    #[must_use]
    pub const fn extended_fifo(self) -> bool {
        self.contains(Self::EXTENDED_FIFO)
    }
}

/// FIFO capability bitmap stored at [`fifo::CAPABILITIES`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FifoCapabilities(u32);

impl FifoCapabilities {
    pub const FENCE: u32 = 1 << 0;
    pub const RESERVE: u32 = 1 << 6;

    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, capability: u32) -> bool {
        self.0 & capability == capability
    }

    #[must_use]
    pub const fn fence(self) -> bool {
        self.contains(Self::FENCE)
    }

    #[must_use]
    pub const fn reserve(self) -> bool {
        self.contains(Self::RESERVE)
    }
}

/// Checked software bound for the complete legacy VRAM aperture. VMware's
/// modern virtual-hardware configurations can expose 256 MiB even though the
/// oldest SVGA II header used 128 MiB; one GiB matches VMware's published
/// overall SVGA memory ceiling while keeping every size representable in the
/// device's 32-bit registers. Per-mode span and physical-end checks still
/// constrain every actual access.
pub const MAX_VRAM_BYTES: u32 = 1024 * 1024 * 1024;
pub const MAX_FIFO_BYTES: u32 = 2 * 1024 * 1024;
pub const MIN_FIFO_BYTES: u32 = 4096 + 8;
pub const FIFO_PAGE_BYTES: u32 = 4096;
pub const FIFO_GUARD_BYTES: u32 = 4;
pub const MAX_PRESENT_RECTS: usize = 64;

/// Pure protocol validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidMode,
    UnsupportedPixelFormat,
    FramebufferTooSmall,
    InvalidRectangle,
    InvalidFifoLayout,
    InvalidFifoCursor,
    InvalidCommand,
    FifoFull,
}

/// Mode limits reported by the SVGA registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModeLimits {
    pub max_width: u32,
    pub max_height: u32,
    pub vram_bytes: u32,
    pub framebuffer_bytes: u32,
}

impl ModeLimits {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.max_width == 0
            || self.max_height == 0
            || self.vram_bytes == 0
            || self.vram_bytes > MAX_VRAM_BYTES
            || self.framebuffer_bytes == 0
            || self.framebuffer_bytes > self.vram_bytes
        {
            return Err(ProtocolError::InvalidMode);
        }
        Ok(self)
    }
}

/// Requested legacy scanout mode. Xenith intentionally supports only the
/// native 32-bpp direct-colour path used by its framebuffer renderer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModeRequest {
    pub width: u32,
    pub height: u32,
    pub bits_per_pixel: u32,
}

impl ModeRequest {
    #[must_use]
    pub const fn xrgb8888(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            bits_per_pixel: 32,
        }
    }

    pub fn validate(self, limits: ModeLimits) -> Result<Self, ProtocolError> {
        let limits = limits.validate()?;
        if self.bits_per_pixel != 32 {
            return Err(ProtocolError::UnsupportedPixelFormat);
        }
        if self.width == 0
            || self.height == 0
            || self.width > limits.max_width
            || self.height > limits.max_height
        {
            return Err(ProtocolError::InvalidMode);
        }
        let minimum_pitch = self
            .width
            .checked_mul(4)
            .ok_or(ProtocolError::FramebufferTooSmall)?;
        let minimum_span = u64::from(minimum_pitch)
            .checked_mul(u64::from(self.height))
            .ok_or(ProtocolError::FramebufferTooSmall)?;
        if minimum_span > u64::from(limits.framebuffer_bytes) {
            return Err(ProtocolError::FramebufferTooSmall);
        }
        Ok(self)
    }
}

/// Current mode and frontbuffer layout read back from the device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    pub bits_per_pixel: u32,
    pub depth: u32,
    pub pitch: u32,
    pub framebuffer_offset: u32,
    pub framebuffer_bytes: u32,
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
}

impl Mode {
    pub fn validate(self, limits: ModeLimits) -> Result<Self, ProtocolError> {
        ModeRequest {
            width: self.width,
            height: self.height,
            bits_per_pixel: self.bits_per_pixel,
        }
        .validate(limits)?;
        if self.depth == 0 || self.depth > self.bits_per_pixel || !self.pitch.is_multiple_of(4) {
            return Err(ProtocolError::InvalidMode);
        }
        let minimum_pitch = self
            .width
            .checked_mul(4)
            .ok_or(ProtocolError::FramebufferTooSmall)?;
        if self.pitch < minimum_pitch
            || self.framebuffer_bytes == 0
            || self.framebuffer_bytes > limits.framebuffer_bytes
        {
            return Err(ProtocolError::FramebufferTooSmall);
        }
        let span = u64::from(self.pitch)
            .checked_mul(u64::from(self.height))
            .ok_or(ProtocolError::FramebufferTooSmall)?;
        let end = u64::from(self.framebuffer_offset)
            .checked_add(span)
            .ok_or(ProtocolError::FramebufferTooSmall)?;
        if span > u64::from(self.framebuffer_bytes) || end > u64::from(limits.vram_bytes) {
            return Err(ProtocolError::FramebufferTooSmall);
        }
        let masks = [self.red_mask, self.green_mask, self.blue_mask];
        if masks.contains(&0)
            || self.red_mask & self.green_mask != 0
            || self.red_mask & self.blue_mask != 0
            || self.green_mask & self.blue_mask != 0
        {
            return Err(ProtocolError::UnsupportedPixelFormat);
        }
        Ok(self)
    }

    #[must_use]
    pub const fn request(self) -> ModeRequest {
        ModeRequest {
            width: self.width,
            height: self.height,
            bits_per_pixel: self.bits_per_pixel,
        }
    }
}

/// Visible frontbuffer rectangle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    #[must_use]
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    #[must_use]
    pub const fn full(mode: Mode) -> Self {
        Self::new(0, 0, mode.width, mode.height)
    }

    pub fn validate(self, mode: Mode) -> Result<Self, ProtocolError> {
        let right = self
            .x
            .checked_add(self.width)
            .ok_or(ProtocolError::InvalidRectangle)?;
        let bottom = self
            .y
            .checked_add(self.height)
            .ok_or(ProtocolError::InvalidRectangle)?;
        if self.width == 0 || self.height == 0 || right > mode.width || bottom > mode.height {
            return Err(ProtocolError::InvalidRectangle);
        }
        Ok(self)
    }
}

/// Same-surface rectangle-copy parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyRect {
    pub source_x: u32,
    pub source_y: u32,
    pub destination_x: u32,
    pub destination_y: u32,
    pub width: u32,
    pub height: u32,
}

impl CopyRect {
    pub fn validate(self, mode: Mode) -> Result<Self, ProtocolError> {
        Rect::new(self.source_x, self.source_y, self.width, self.height).validate(mode)?;
        Rect::new(
            self.destination_x,
            self.destination_y,
            self.width,
            self.height,
        )
        .validate(mode)?;
        Ok(self)
    }
}

/// Validated byte layout of the shared FIFO ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FifoLayout {
    min: u32,
    max: u32,
}

impl FifoLayout {
    pub fn new(min: u32, max: u32, mapped_bytes: u32) -> Result<Self, ProtocolError> {
        if min < 4 * (fifo::STOP + 1)
            || !min.is_multiple_of(4)
            || !max.is_multiple_of(4)
            || max > mapped_bytes
            || max
                .checked_sub(min)
                .is_none_or(|bytes| bytes < 2 * FIFO_GUARD_BYTES)
        {
            return Err(ProtocolError::InvalidFifoLayout);
        }
        Ok(Self { min, max })
    }

    #[must_use]
    pub const fn min(self) -> u32 {
        self.min
    }

    #[must_use]
    pub const fn max(self) -> u32 {
        self.max
    }

    #[must_use]
    pub const fn capacity(self) -> u32 {
        self.max - self.min
    }

    pub fn validate_cursor(self, cursor: u32) -> Result<u32, ProtocolError> {
        if cursor < self.min || cursor >= self.max || !cursor.is_multiple_of(4) {
            return Err(ProtocolError::InvalidFifoCursor);
        }
        Ok(cursor)
    }

    /// Space available from `next` up to (but not including) `stop`, keeping
    /// one dword empty so an empty FIFO is distinguishable from a full FIFO.
    pub fn free_bytes(self, next: u32, stop: u32) -> Result<u32, ProtocolError> {
        let next = self.validate_cursor(next)?;
        let stop = self.validate_cursor(stop)?;
        let distance = if next >= stop {
            (self.max - next) + (stop - self.min)
        } else {
            stop - next
        };
        distance
            .checked_sub(FIFO_GUARD_BYTES)
            .ok_or(ProtocolError::InvalidFifoLayout)
    }

    pub fn reserve(self, next: u32, stop: u32, bytes: u32) -> Result<u32, ProtocolError> {
        if bytes == 0 || !bytes.is_multiple_of(4) || bytes >= self.capacity() {
            return Err(ProtocolError::InvalidCommand);
        }
        if bytes > self.free_bytes(next, stop)? {
            return Err(ProtocolError::FifoFull);
        }
        self.advance(next, bytes)
    }

    pub fn advance(self, cursor: u32, bytes: u32) -> Result<u32, ProtocolError> {
        let cursor = self.validate_cursor(cursor)?;
        if !bytes.is_multiple_of(4) || bytes >= self.capacity() {
            return Err(ProtocolError::InvalidCommand);
        }
        let relative = cursor - self.min;
        Ok(self.min + (relative + bytes) % self.capacity())
    }
}

pub const CMD_UPDATE: u32 = 1;
pub const CMD_RECT_COPY: u32 = 3;
pub const CMD_FENCE: u32 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateCommand([u32; 5]);

impl UpdateCommand {
    pub fn new(rect: Rect, mode: Mode) -> Result<Self, ProtocolError> {
        let rect = rect.validate(mode)?;
        Ok(Self([CMD_UPDATE, rect.x, rect.y, rect.width, rect.height]))
    }

    #[must_use]
    pub const fn words(&self) -> &[u32; 5] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RectCopyCommand([u32; 7]);

impl RectCopyCommand {
    pub fn new(copy: CopyRect, mode: Mode) -> Result<Self, ProtocolError> {
        let copy = copy.validate(mode)?;
        Ok(Self([
            CMD_RECT_COPY,
            copy.source_x,
            copy.source_y,
            copy.destination_x,
            copy.destination_y,
            copy.width,
            copy.height,
        ]))
    }

    #[must_use]
    pub const fn words(&self) -> &[u32; 7] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FenceCommand([u32; 2]);

impl FenceCommand {
    pub fn new(sequence: u32) -> Result<Self, ProtocolError> {
        if sequence == 0 {
            return Err(ProtocolError::InvalidCommand);
        }
        Ok(Self([CMD_FENCE, sequence]))
    }

    #[must_use]
    pub const fn words(&self) -> &[u32; 2] {
        &self.0
    }
}

/// Non-zero serial allocator for FIFO fence commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FenceSequence {
    next: u32,
}

impl FenceSequence {
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 1 }
    }

    pub fn allocate(&mut self) -> u32 {
        let current = self.next;
        self.next = self.next.wrapping_add(1);
        if self.next == 0 {
            self.next = 1;
        }
        current
    }

    /// Serial comparison valid while fewer than 2^31 fences are outstanding.
    #[must_use]
    pub const fn passed(completed: u32, target: u32) -> bool {
        completed.wrapping_sub(target) < (1 << 31)
    }
}

impl Default for FenceSequence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ModeLimits {
        ModeLimits {
            max_width: 2560,
            max_height: 1600,
            vram_bytes: 16 * 1024 * 1024,
            framebuffer_bytes: 16 * 1024 * 1024,
        }
    }

    fn mode() -> Mode {
        Mode {
            width: 800,
            height: 600,
            bits_per_pixel: 32,
            depth: 24,
            pitch: 3200,
            framebuffer_offset: 0,
            framebuffer_bytes: 16 * 1024 * 1024,
            red_mask: 0x00ff_0000,
            green_mask: 0x0000_ff00,
            blue_mask: 0x0000_00ff,
        }
    }

    #[test]
    fn official_identity_values_are_exact() {
        assert_eq!(PCI_VENDOR_VMWARE, 0x15ad);
        assert_eq!(PCI_DEVICE_SVGA2, 0x0405);
        assert_eq!(SVGA_ID_2, 0x9000_0002);
        assert_eq!(fifo::BUSY, 290);
        assert_eq!(fifo::NUM_REGS, 291);
    }

    #[test]
    fn mode_validation_accepts_xrgb8888_and_rejects_short_pitch() {
        assert_eq!(mode().validate(limits()), Ok(mode()));
        let mut short = mode();
        short.pitch = 3196;
        assert_eq!(
            short.validate(limits()),
            Err(ProtocolError::FramebufferTooSmall)
        );
    }

    #[test]
    fn mode_validation_rejects_overlapping_masks_and_span_overflow() {
        let mut overlapping = mode();
        overlapping.green_mask = overlapping.red_mask;
        assert_eq!(
            overlapping.validate(limits()),
            Err(ProtocolError::UnsupportedPixelFormat)
        );
        let mut outside_vram = mode();
        outside_vram.framebuffer_offset = 15 * 1024 * 1024;
        assert_eq!(
            outside_vram.validate(limits()),
            Err(ProtocolError::FramebufferTooSmall)
        );
    }

    #[test]
    fn requests_are_bounded_by_register_limits_and_storage() {
        assert!(ModeRequest::xrgb8888(2560, 1600).validate(limits()).is_ok());
        assert_eq!(
            ModeRequest::xrgb8888(2561, 1600).validate(limits()),
            Err(ProtocolError::InvalidMode)
        );
        assert_eq!(
            ModeRequest {
                width: 800,
                height: 600,
                bits_per_pixel: 16,
            }
            .validate(limits()),
            Err(ProtocolError::UnsupportedPixelFormat)
        );
    }

    #[test]
    fn rectangle_validation_checks_both_edges_and_overflow() {
        assert!(Rect::new(799, 599, 1, 1).validate(mode()).is_ok());
        for invalid in [
            Rect::new(0, 0, 0, 1),
            Rect::new(799, 0, 2, 1),
            Rect::new(0, 599, 1, 2),
            Rect::new(u32::MAX, 0, 2, 1),
        ] {
            assert_eq!(
                invalid.validate(mode()),
                Err(ProtocolError::InvalidRectangle)
            );
        }
    }

    #[test]
    fn fifo_empty_capacity_keeps_one_dword_guard() {
        let layout = FifoLayout::new(4096, 8192, 8192).unwrap();
        assert_eq!(layout.free_bytes(4096, 4096), Ok(4092));
        assert_eq!(layout.reserve(4096, 4096, 4092), Ok(8188));
        assert_eq!(
            layout.reserve(4096, 4096, 4096),
            Err(ProtocolError::InvalidCommand)
        );
    }

    #[test]
    fn fifo_free_space_is_correct_on_each_side_of_stop() {
        let layout = FifoLayout::new(4096, 8192, 8192).unwrap();
        assert_eq!(layout.free_bytes(6144, 7168), Ok(1020));
        assert_eq!(layout.free_bytes(7168, 6144), Ok(3068));
        assert_eq!(layout.reserve(8188, 5000, 20), Ok(4112));
    }

    #[test]
    fn fifo_rejects_misaligned_headers_cursors_and_commands() {
        assert_eq!(
            FifoLayout::new(4098, 8192, 8192),
            Err(ProtocolError::InvalidFifoLayout)
        );
        let layout = FifoLayout::new(4096, 8192, 8192).unwrap();
        assert_eq!(
            layout.free_bytes(4098, 4096),
            Err(ProtocolError::InvalidFifoCursor)
        );
        assert_eq!(
            layout.reserve(4096, 4096, 6),
            Err(ProtocolError::InvalidCommand)
        );
    }

    #[test]
    fn fifo_full_is_distinct_from_malformed_input() {
        let layout = FifoLayout::new(4096, 8192, 8192).unwrap();
        assert_eq!(layout.free_bytes(5000, 5004), Ok(0));
        assert_eq!(layout.reserve(5000, 5004, 4), Err(ProtocolError::FifoFull));
    }

    #[test]
    fn update_and_copy_commands_match_wire_word_order() {
        let update = UpdateCommand::new(Rect::new(1, 2, 3, 4), mode()).unwrap();
        assert_eq!(update.words(), &[CMD_UPDATE, 1, 2, 3, 4]);
        let copy = RectCopyCommand::new(
            CopyRect {
                source_x: 1,
                source_y: 2,
                destination_x: 11,
                destination_y: 12,
                width: 30,
                height: 40,
            },
            mode(),
        )
        .unwrap();
        assert_eq!(copy.words(), &[CMD_RECT_COPY, 1, 2, 11, 12, 30, 40]);
    }

    #[test]
    fn fence_sequences_skip_zero_and_compare_across_wrap() {
        let mut sequence = FenceSequence { next: u32::MAX };
        assert_eq!(sequence.allocate(), u32::MAX);
        assert_eq!(sequence.allocate(), 1);
        assert!(FenceSequence::passed(1, u32::MAX));
        assert!(!FenceSequence::passed(u32::MAX - 10, 20));
        assert_eq!(FenceCommand::new(0), Err(ProtocolError::InvalidCommand));
    }
}
