//! Allocation-free Xenith boot splash over a 32-bpp UEFI GOP framebuffer.
//!
//! The image is stored as little-endian RGB565 so the loader does not need a
//! compressed-image decoder. Every source pixel is expanded to RGB888 and
//! packed according to the channel geometry reported by GOP. Splash handoff
//! is deliberately limited to byte-oriented RGBX/BGRX modes because the
//! kernel continues updating the same pixels after firmware exit.

use core::ptr;

use xenith_boot_common::XenithFramebuffer;

const IMAGE_WIDTH: u32 = 640;
const IMAGE_HEIGHT: u32 = 480;
const IMAGE_BYTES: usize = IMAGE_WIDTH as usize * IMAGE_HEIGHT as usize * 2;
static IMAGE_RGB565: &[u8; IMAGE_BYTES] = include_bytes!("../assets/xenith-splash.rgb565");

const WORDMARK_X: u32 = 58;
const WORDMARK_Y: u32 = 330;
const GLYPH_WIDTH: u32 = 5;
const GLYPH_HEIGHT: u32 = 7;
const GLYPH_SCALE: u32 = 4;
const GLYPH_GAP: u32 = 1;

const PROGRESS_X: u32 = 58;
const PROGRESS_Y: u32 = 378;
const PROGRESS_WIDTH: u32 = 220;
const PROGRESS_HEIGHT: u32 = 10;

const WORDMARK: [[u8; GLYPH_HEIGHT as usize]; 6] = [
    // X
    [
        0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001,
    ],
    // E
    [
        0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111,
    ],
    // N
    [
        0b10001, 0b11001, 0b11001, 0b10101, 0b10011, 0b10011, 0b10001,
    ],
    // I
    [
        0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b11111,
    ],
    // T
    [
        0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100,
    ],
    // H
    [
        0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
    ],
];

/// Live loader-side splash state. The framebuffer remains firmware-owned, but
/// its linear pixel storage is writable until and after `ExitBootServices`.
#[derive(Clone, Copy)]
pub struct Splash {
    surface: Surface,
    image_x: u32,
    image_y: u32,
}

impl Splash {
    /// Paint the centered splash, deterministic wordmark, and initial progress
    /// indicator. Returns `None` when GOP did not expose a compatible direct
    /// framebuffer or the mode is smaller than the native 640x480 artwork.
    ///
    /// # Safety
    ///
    /// `framebuffer.address` must name the live writable GOP framebuffer
    /// described by the remaining fields for the duration of loader execution.
    pub unsafe fn begin(framebuffer: XenithFramebuffer) -> Option<Self> {
        let surface = Surface::new(framebuffer)?;
        if surface.width < IMAGE_WIDTH || surface.height < IMAGE_HEIGHT {
            return None;
        }
        let splash = Self {
            surface,
            image_x: (surface.width - IMAGE_WIDTH) / 2,
            image_y: (surface.height - IMAGE_HEIGHT) / 2,
        };
        // SAFETY: `surface` was validated above and every draw is clipped to
        // the native image rectangle within that surface.
        unsafe {
            splash.draw_image();
            splash.draw_wordmark();
            splash.progress(4);
        }
        Some(splash)
    }

    /// Redraw the bounded progress track with `percent` clamped to 0..=100.
    ///
    /// # Safety
    ///
    /// The GOP framebuffer supplied to [`Self::begin`] must still be live and
    /// writable. The loader calls this only before changing page tables.
    pub unsafe fn progress(&self, percent: u8) {
        let x = self.image_x + PROGRESS_X;
        let y = self.image_y + PROGRESS_Y;
        let border = self.surface.packer.pack(0x9a, 0x9a, 0x9a);
        let track = self.surface.packer.pack(0x1a, 0x1a, 0x1a);
        let fill = self.surface.packer.pack(0xee, 0xee, 0xee);
        // SAFETY: all rectangles lie within the 640x480 image, which `begin`
        // proved lies inside the framebuffer.
        unsafe {
            self.surface
                .fill_rect(x, y, PROGRESS_WIDTH, PROGRESS_HEIGHT, border);
            self.surface
                .fill_rect(x + 1, y + 1, PROGRESS_WIDTH - 2, PROGRESS_HEIGHT - 2, track);
            let inner = PROGRESS_WIDTH - 2;
            let filled = inner * u32::from(percent.min(100)) / 100;
            if filled != 0 {
                self.surface
                    .fill_rect(x + 1, y + 1, filled, PROGRESS_HEIGHT - 2, fill);
            }
        }
    }

    unsafe fn draw_image(&self) {
        if let Some(order) = self.surface.packer.byte_order() {
            // The two standard GOP layouts cover VMware, the Xenith firmware
            // model, and virtually all PC firmware. Keeping their RGB565
            // expansion free of general bit-mask scaling is important for the
            // instruction-interpreted UEFI acceptance gate.
            unsafe { self.draw_image_standard(order) };
            return;
        }
        for source_y in 0..IMAGE_HEIGHT {
            let row = source_y as usize * IMAGE_WIDTH as usize * 2;
            for source_x in 0..IMAGE_WIDTH {
                let offset = row + source_x as usize * 2;
                let encoded = u16::from_le_bytes([IMAGE_RGB565[offset], IMAGE_RGB565[offset + 1]]);
                let (red, green, blue) = unpack_rgb565(encoded);
                let pixel = self.surface.packer.pack(red, green, blue);
                // SAFETY: the destination is the native image rectangle that
                // `begin` proved fits wholly within the framebuffer.
                unsafe {
                    self.surface.write_pixel_unchecked(
                        self.image_x + source_x,
                        self.image_y + source_y,
                        pixel,
                    );
                }
            }
        }
    }

    unsafe fn draw_image_standard(&self, order: ByteOrder) {
        for source_y in 0..IMAGE_HEIGHT {
            let row = source_y as usize * IMAGE_WIDTH as usize * 2;
            for source_x in 0..IMAGE_WIDTH {
                let offset = row + source_x as usize * 2;
                let encoded = u16::from_le_bytes([IMAGE_RGB565[offset], IMAGE_RGB565[offset + 1]]);
                let (red, green, blue) = unpack_rgb565(encoded);
                let pixel = match order {
                    ByteOrder::Rgb => {
                        u32::from(blue) << 16 | u32::from(green) << 8 | u32::from(red)
                    },
                    ByteOrder::Bgr => {
                        u32::from(red) << 16 | u32::from(green) << 8 | u32::from(blue)
                    },
                };
                // SAFETY: the destination is the native image rectangle that
                // `begin` proved fits wholly within the framebuffer.
                unsafe {
                    self.surface.write_pixel_unchecked(
                        self.image_x + source_x,
                        self.image_y + source_y,
                        pixel,
                    );
                }
            }
        }
    }

    unsafe fn draw_wordmark(&self) {
        let shadow = self.surface.packer.pack(0x08, 0x20, 0x35);
        let foreground = self.surface.packer.pack(0xd9, 0xf3, 0xff);
        let advance = (GLYPH_WIDTH + GLYPH_GAP) * GLYPH_SCALE;
        for (index, glyph) in WORDMARK.iter().enumerate() {
            let glyph_x = self.image_x + WORDMARK_X + index as u32 * advance;
            let glyph_y = self.image_y + WORDMARK_Y;
            // SAFETY: fixed wordmark geometry lies inside the native image.
            unsafe {
                self.draw_glyph(glyph_x + 2, glyph_y + 2, glyph, shadow);
                self.draw_glyph(glyph_x, glyph_y, glyph, foreground);
            }
        }
    }

    unsafe fn draw_glyph(&self, x: u32, y: u32, glyph: &[u8; 7], pixel: u32) {
        for (row, bits) in glyph.iter().copied().enumerate() {
            for column in 0..GLYPH_WIDTH {
                if bits & (1 << (GLYPH_WIDTH - 1 - column)) != 0 {
                    // SAFETY: callers place every scaled cell within the
                    // fixed wordmark area of the validated native image.
                    unsafe {
                        self.surface.fill_rect(
                            x + column * GLYPH_SCALE,
                            y + row as u32 * GLYPH_SCALE,
                            GLYPH_SCALE,
                            GLYPH_SCALE,
                            pixel,
                        );
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Surface {
    address: u64,
    pitch: u32,
    width: u32,
    height: u32,
    packer: PixelPacker,
}

impl Surface {
    fn new(framebuffer: XenithFramebuffer) -> Option<Self> {
        if framebuffer.address == 0
            || framebuffer.bpp != 32
            || framebuffer.width == 0
            || framebuffer.height == 0
            || framebuffer.pitch < framebuffer.width.checked_mul(4)?
        {
            return None;
        }
        let byte_length =
            u64::from(framebuffer.pitch).checked_mul(u64::from(framebuffer.height))?;
        framebuffer.address.checked_add(byte_length)?;
        let packer = PixelPacker::new(framebuffer)?;
        // The kernel-side progress renderer preserves the loader image only
        // for byte-addressable RGBX/BGRX channels. Reject otherwise valid
        // wide or shifted GOP bitmask modes here so `Splash::begin == Some`
        // remains a sufficient condition for advertising xenith.splash=1.
        packer.byte_order()?;
        Some(Self {
            address: framebuffer.address,
            pitch: framebuffer.pitch,
            width: framebuffer.width,
            height: framebuffer.height,
            packer,
        })
    }

    unsafe fn fill_rect(&self, x: u32, y: u32, width: u32, height: u32, pixel: u32) {
        let end_x = x.saturating_add(width).min(self.width);
        let end_y = y.saturating_add(height).min(self.height);
        for py in y.min(self.height)..end_y {
            for px in x.min(self.width)..end_x {
                // SAFETY: both loop coordinates are clipped to the validated
                // visible framebuffer geometry.
                unsafe { self.write_pixel_unchecked(px, py, pixel) };
            }
        }
    }

    unsafe fn write_pixel_unchecked(&self, x: u32, y: u32, pixel: u32) {
        let offset = u64::from(y) * u64::from(self.pitch) + u64::from(x) * 4;
        let destination = (self.address + offset) as *mut u32;
        // SAFETY: callers keep x/y inside the geometry validated by `new`.
        unsafe { ptr::write_volatile(destination, pixel) };
    }
}

#[derive(Clone, Copy)]
struct PixelPacker {
    red_shift: u8,
    red_size: u8,
    green_shift: u8,
    green_size: u8,
    blue_shift: u8,
    blue_size: u8,
}

#[derive(Clone, Copy)]
enum ByteOrder {
    /// Red, green, blue bytes at increasing framebuffer addresses.
    Rgb,
    /// Blue, green, red bytes at increasing framebuffer addresses.
    Bgr,
}

impl PixelPacker {
    fn new(framebuffer: XenithFramebuffer) -> Option<Self> {
        for (shift, size) in [
            (framebuffer.red_shift, framebuffer.red_size),
            (framebuffer.green_shift, framebuffer.green_size),
            (framebuffer.blue_shift, framebuffer.blue_size),
        ] {
            if size == 0 || size > 16 || u16::from(shift) + u16::from(size) > 32 {
                return None;
            }
        }
        let red = channel_mask(framebuffer.red_shift, framebuffer.red_size);
        let green = channel_mask(framebuffer.green_shift, framebuffer.green_size);
        let blue = channel_mask(framebuffer.blue_shift, framebuffer.blue_size);
        if red & green != 0 || red & blue != 0 || green & blue != 0 {
            return None;
        }
        Some(Self {
            red_shift: framebuffer.red_shift,
            red_size: framebuffer.red_size,
            green_shift: framebuffer.green_shift,
            green_size: framebuffer.green_size,
            blue_shift: framebuffer.blue_shift,
            blue_size: framebuffer.blue_size,
        })
    }

    fn pack(self, red: u8, green: u8, blue: u8) -> u32 {
        scale_channel(red, self.red_size) << self.red_shift
            | scale_channel(green, self.green_size) << self.green_shift
            | scale_channel(blue, self.blue_size) << self.blue_shift
    }

    fn byte_order(self) -> Option<ByteOrder> {
        if self.red_size != 8 || self.green_size != 8 || self.blue_size != 8 {
            return None;
        }
        match (self.red_shift, self.green_shift, self.blue_shift) {
            (0, 8, 16) => Some(ByteOrder::Rgb),
            (16, 8, 0) => Some(ByteOrder::Bgr),
            _ => None,
        }
    }
}

fn channel_mask(shift: u8, size: u8) -> u32 {
    (((1_u64 << size) - 1) << shift) as u32
}

fn scale_channel(value: u8, size: u8) -> u32 {
    let maximum = (1_u32 << size) - 1;
    (u32::from(value) * maximum + 127) / 255
}

fn unpack_rgb565(pixel: u16) -> (u8, u8, u8) {
    let red = ((pixel >> 11) & 0x1f) as u8;
    let green = ((pixel >> 5) & 0x3f) as u8;
    let blue = (pixel & 0x1f) as u8;
    (
        (red << 3) | (red >> 2),
        (green << 2) | (green >> 4),
        (blue << 3) | (blue >> 2),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framebuffer(red_shift: u8, green_shift: u8, blue_shift: u8) -> XenithFramebuffer {
        XenithFramebuffer {
            address: 0x1000,
            pitch: 800 * 4,
            width: 800,
            height: 600,
            bpp: 32,
            red_shift,
            red_size: 8,
            green_shift,
            green_size: 8,
            blue_shift,
            blue_size: 8,
        }
    }

    #[test]
    fn asset_has_exact_native_geometry() {
        assert_eq!(IMAGE_RGB565.len(), 640 * 480 * 2);
    }

    #[test]
    fn rgb565_primary_colors_expand_to_rgb888() {
        assert_eq!(unpack_rgb565(0xf800), (255, 0, 0));
        assert_eq!(unpack_rgb565(0x07e0), (0, 255, 0));
        assert_eq!(unpack_rgb565(0x001f), (0, 0, 255));
        assert_eq!(unpack_rgb565(0xffff), (255, 255, 255));
    }

    #[test]
    fn packer_honors_rgb_and_bgr_channel_layouts() {
        let rgb = PixelPacker::new(framebuffer(0, 8, 16)).unwrap();
        let bgr = PixelPacker::new(framebuffer(16, 8, 0)).unwrap();
        assert_eq!(rgb.pack(0x12, 0x34, 0x56), 0x0056_3412);
        assert_eq!(bgr.pack(0x12, 0x34, 0x56), 0x0012_3456);
    }

    #[test]
    fn rejects_overlapping_or_out_of_word_pixel_masks() {
        assert!(PixelPacker::new(framebuffer(0, 0, 16)).is_none());
        let mut invalid = framebuffer(0, 8, 16);
        invalid.red_shift = 28;
        invalid.red_size = 8;
        assert!(PixelPacker::new(invalid).is_none());
    }

    #[test]
    fn native_image_is_centered_in_emulator_gop_mode() {
        let surface = Surface::new(framebuffer(16, 8, 0)).unwrap();
        assert_eq!((surface.width - IMAGE_WIDTH) / 2, 80);
        assert_eq!((surface.height - IMAGE_HEIGHT) / 2, 60);
    }

    #[test]
    fn splash_handoff_rejects_wide_and_non_byte_bitmask_modes() {
        let mut wide = framebuffer(0, 10, 20);
        wide.red_size = 10;
        wide.green_size = 10;
        wide.blue_size = 10;
        assert!(PixelPacker::new(wide).is_some());
        assert!(Surface::new(wide).is_none());

        let shifted = framebuffer(1, 9, 17);
        assert!(PixelPacker::new(shifted).is_some());
        assert!(Surface::new(shifted).is_none());

        assert!(Surface::new(framebuffer(0, 8, 16)).is_some());
        assert!(Surface::new(framebuffer(16, 8, 0)).is_some());
    }
}
