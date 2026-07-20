//! Embedded, allocation-free desktop wallpaper sampling.
//!
//! The source photo is kept as a compact RGB8 asset. Rendering uses a
//! focal-point cover crop and bilinear filtering so every framebuffer shape
//! is filled without stretching the portrait or introducing nearest-neighbor
//! shimmer around cursor damage.

use crate::Size;

const SOURCE_WIDTH: u32 = 192;
const SOURCE_HEIGHT: u32 = 225;
const CHANNELS: usize = 3;
const SOURCE: &[u8; SOURCE_WIDTH as usize * SOURCE_HEIGHT as usize * CHANNELS] =
    include_bytes!("../assets/sedat-wallpaper.rgb");

// Keep the face above the visual center when a wide screen crops the portrait.
const FOCAL_X_Q16: i64 = (SOURCE_WIDTH as i64 * 48 / 100) << 16;
const FOCAL_Y_Q16: i64 = (SOURCE_HEIGHT as i64 * 40 / 100) << 16;

#[derive(Clone, Copy)]
struct Crop {
    left_q16: i64,
    top_q16: i64,
    width_q16: i64,
    height_q16: i64,
}

impl Crop {
    fn cover(size: Size) -> Self {
        let destination_width = i64::from(size.width.max(1));
        let destination_height = i64::from(size.height.max(1));
        let source_width_q16 = i64::from(SOURCE_WIDTH) << 16;
        let source_height_q16 = i64::from(SOURCE_HEIGHT) << 16;

        let (width_q16, height_q16) = if i64::from(SOURCE_WIDTH) * destination_height
            < i64::from(SOURCE_HEIGHT) * destination_width
        {
            (
                source_width_q16,
                (source_width_q16 * destination_height / destination_width).max(1 << 16),
            )
        } else {
            (
                (source_height_q16 * destination_width / destination_height).max(1 << 16),
                source_height_q16,
            )
        };

        let left_q16 = (FOCAL_X_Q16 - width_q16 / 2).clamp(0, source_width_q16 - width_q16);
        let top_q16 = (FOCAL_Y_Q16 - height_q16 / 2).clamp(0, source_height_q16 - height_q16);
        Self {
            left_q16,
            top_q16,
            width_q16,
            height_q16,
        }
    }
}

/// Precomputed embedded-photo transform for one destination size.
///
/// Constructing this performs the cover-crop divisions once per damaged
/// region. Sampling then uses only fixed-point multiply/add operations plus
/// bilinear interpolation, avoiding division in the framebuffer's hot loop.
pub(crate) struct Sampler {
    width: u32,
    height: u32,
    left_q32: i64,
    top_q32: i64,
    step_x_q32: i64,
    step_y_q32: i64,
}

impl Sampler {
    #[must_use]
    pub(crate) fn new(size: Size) -> Self {
        let width = size.width.max(1);
        let height = size.height.max(1);
        let crop = Crop::cover(size);
        Self {
            width,
            height,
            left_q32: crop.left_q16 << 16,
            top_q32: crop.top_q16 << 16,
            step_x_q32: (crop.width_q16 << 16) / i64::from(width),
            step_y_q32: (crop.height_q16 << 16) / i64::from(height),
        }
    }

    /// Sample the embedded photo at one destination pixel.
    #[must_use]
    pub(crate) fn sample(&self, x: u32, y: u32) -> [u8; 3] {
        // Pixel-center mapping avoids pinning the first and final destination
        // pixels to source texel corners. Q32 steps retain enough precision
        // that even very wide framebuffers do not accumulate visible error.
        let x = i64::from(x.min(self.width - 1));
        let y = i64::from(y.min(self.height - 1));
        let source_x_q16 =
            (self.left_q32 + self.step_x_q32 / 2 + x.saturating_mul(self.step_x_q32)) >> 16;
        let source_y_q16 =
            (self.top_q32 + self.step_y_q32 / 2 + y.saturating_mul(self.step_y_q32)) >> 16;
        bilinear(source_x_q16, source_y_q16)
    }
}

fn bilinear(x_q16: i64, y_q16: i64) -> [u8; 3] {
    let max_x = SOURCE_WIDTH - 1;
    let max_y = SOURCE_HEIGHT - 1;
    let x_q16 = x_q16.clamp(0, i64::from(max_x) << 16) as u64;
    let y_q16 = y_q16.clamp(0, i64::from(max_y) << 16) as u64;
    let x0 = (x_q16 >> 16) as u32;
    let y0 = (y_q16 >> 16) as u32;
    let x1 = x0.saturating_add(1).min(max_x);
    let y1 = y0.saturating_add(1).min(max_y);
    let fx = (x_q16 & 0xffff) as u32;
    let fy = (y_q16 & 0xffff) as u32;
    let inverse_x = 65_536 - fx;
    let inverse_y = 65_536 - fy;

    let top_left = texel(x0, y0);
    let top_right = texel(x1, y0);
    let bottom_left = texel(x0, y1);
    let bottom_right = texel(x1, y1);
    let mut output = [0u8; 3];
    for channel in 0..CHANNELS {
        let top = u32::from(top_left[channel]) * inverse_x + u32::from(top_right[channel]) * fx;
        let bottom =
            u32::from(bottom_left[channel]) * inverse_x + u32::from(bottom_right[channel]) * fx;
        let value = (u64::from(top) * u64::from(inverse_y)
            + u64::from(bottom) * u64::from(fy)
            + (1u64 << 31))
            >> 32;
        output[channel] = value.min(255) as u8;
    }
    output
}

fn texel(x: u32, y: u32) -> [u8; 3] {
    let offset = (y as usize * SOURCE_WIDTH as usize + x as usize) * CHANNELS;
    [SOURCE[offset], SOURCE[offset + 1], SOURCE[offset + 2]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_common_shape_samples_deterministically_inside_the_photo() {
        for size in [
            Size::new(1, 1),
            Size::new(320, 200),
            Size::new(800, 600),
            Size::new(1920, 1080),
            Size::new(400, 800),
        ] {
            for (x, y) in [
                (0, 0),
                (size.width.saturating_sub(1), 0),
                (0, size.height.saturating_sub(1)),
                (size.width.saturating_sub(1), size.height.saturating_sub(1)),
                (size.width / 2, size.height / 2),
            ] {
                let sampler = Sampler::new(size);
                assert_eq!(sampler.sample(x, y), sampler.sample(x, y));
            }
        }
    }

    #[test]
    fn cover_crop_fills_the_destination_without_stretching() {
        let landscape = Crop::cover(Size::new(800, 600));
        assert_eq!(landscape.width_q16, i64::from(SOURCE_WIDTH) << 16);
        assert!(landscape.height_q16 < i64::from(SOURCE_HEIGHT) << 16);

        let portrait = Crop::cover(Size::new(400, 800));
        assert_eq!(portrait.height_q16, i64::from(SOURCE_HEIGHT) << 16);
        assert!(portrait.width_q16 < i64::from(SOURCE_WIDTH) << 16);
    }

    #[test]
    fn source_asset_layout_is_exact() {
        assert_eq!(SOURCE.len(), 129_600);
        assert_ne!(texel(0, 0), texel(SOURCE_WIDTH / 2, SOURCE_HEIGHT / 2));
    }
}
