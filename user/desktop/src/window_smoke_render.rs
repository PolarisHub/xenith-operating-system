//! Deterministic, allocation-free pixels for the opt-in compositor smoke client.

#[derive(Clone, Copy)]
struct Color {
    red: u8,
    green: u8,
    blue: u8,
}

impl Color {
    const fn new(red: u8, green: u8, blue: u8) -> Self {
        Self { red, green, blue }
    }

    fn blend(self, other: Self, alpha: u8) -> Self {
        let alpha = u32::from(alpha);
        let inverse = 255 - alpha;
        Self::new(
            ((u32::from(self.red) * inverse + u32::from(other.red) * alpha + 127) / 255) as u8,
            ((u32::from(self.green) * inverse + u32::from(other.green) * alpha + 127) / 255) as u8,
            ((u32::from(self.blue) * inverse + u32::from(other.blue) * alpha + 127) / 255) as u8,
        )
    }
}

/// Paint a complete opaque BGRX8888 client surface.
#[must_use]
pub fn draw_window(buffer: &mut [u8], width: u32, height: u32, stride: usize) -> bool {
    let Some(visible) = (width as usize).checked_mul(4) else {
        return false;
    };
    let Some(required) = (height as usize).checked_mul(stride) else {
        return false;
    };
    if width == 0 || height == 0 || stride < visible || buffer.len() < required {
        return false;
    }

    for y in 0..height {
        for x in 0..width {
            let vertical = y.saturating_mul(255) / height.max(1);
            let horizontal = x.saturating_mul(255) / width.max(1);
            let mut color = Color::new(
                (11 + horizontal / 28) as u8,
                (19 + horizontal / 17) as u8,
                (38 + vertical / 9) as u8,
            );

            let glow_x = width.saturating_mul(4) / 5;
            let glow_y = height / 4;
            let distance = x.abs_diff(glow_x).max(y.abs_diff(glow_y));
            let radius = width.max(height).max(1) / 2;
            if distance < radius {
                let alpha = ((radius - distance) * 112 / radius) as u8;
                color = color.blend(Color::new(20, 193, 232), alpha);
            }

            let title_height = height.min(56);
            if y < title_height {
                color = color.blend(Color::new(30, 45, 72), 188);
            }
            if y == title_height.saturating_sub(1) {
                color = Color::new(70, 105, 143);
            }

            let margin = width.min(height).clamp(8, 24);
            let card_top = title_height.saturating_add(margin);
            let card_bottom = height.saturating_sub(margin);
            if x >= margin && x < width.saturating_sub(margin) && y >= card_top && y < card_bottom {
                color = color.blend(Color::new(26, 39, 63), 184);
                if x == margin
                    || x + 1 == width.saturating_sub(margin)
                    || y == card_top
                    || y + 1 == card_bottom
                {
                    color = Color::new(83, 122, 159);
                }
            }

            if y >= card_top.saturating_add(margin)
                && y < card_top.saturating_add(margin).saturating_add(6)
                && x >= margin.saturating_mul(2)
                && x < width.saturating_sub(margin.saturating_mul(2))
            {
                color = Color::new(96, 226, 255);
            }
            if y >= card_top.saturating_add(margin).saturating_add(20)
                && y < card_top.saturating_add(margin).saturating_add(24)
                && x >= margin.saturating_mul(2)
                && x < width.saturating_sub(margin.saturating_mul(3))
            {
                color = Color::new(131, 150, 185);
            }

            let button_y = title_height / 2;
            for (center_x, button) in [
                (margin, Color::new(255, 105, 125)),
                (margin.saturating_add(18), Color::new(255, 202, 92)),
                (margin.saturating_add(36), Color::new(91, 232, 171)),
            ] {
                let dx = i64::from(x) - i64::from(center_x);
                let dy = i64::from(y) - i64::from(button_y);
                if dx * dx + dy * dy <= 25 {
                    color = button;
                }
            }

            put_bgrx(buffer, stride, x, y, color);
        }
    }
    true
}

fn put_bgrx(buffer: &mut [u8], stride: usize, x: u32, y: u32, color: Color) {
    let offset = y as usize * stride + x as usize * 4;
    buffer[offset] = color.blue;
    buffer[offset + 1] = color.green;
    buffer[offset + 2] = color.red;
    buffer[offset + 3] = 0xff;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn render_is_deterministic_opaque_and_non_flat() {
        let (width, height, stride) = (320, 200, 320 * 4);
        let mut first = std::vec![0u8; stride * height];
        let mut second = first.clone();
        assert!(draw_window(&mut first, width, height as u32, stride));
        assert!(draw_window(&mut second, width, height as u32, stride));
        assert_eq!(first, second);
        let (pixels, tail) = first.as_chunks::<4>();
        assert!(tail.is_empty());
        assert!(pixels.iter().all(|pixel| pixel[3] == 0xff));
        assert!(pixels.iter().any(|pixel| pixel != &first[..4]));
    }

    #[test]
    fn render_rejects_truncated_or_invalid_surfaces() {
        assert!(!draw_window(&mut [], 0, 10, 40));
        assert!(!draw_window(&mut [0; 64], 8, 8, 31));
        assert!(!draw_window(&mut [0; 64], 8, 8, 32));
    }
}
