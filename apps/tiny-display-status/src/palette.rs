use embedded_graphics::pixelcolor::Rgb565;

/// Converts an 8-bit-per-channel color into embedded-graphics' native
/// Rgb565 component ranges (5/6/5 bits), so palette values can be written
/// as ordinary 0-255 triples instead of pre-shifted magic numbers.
const fn rgb565(r: u8, g: u8, b: u8) -> Rgb565 {
    Rgb565::new(r >> 3, g >> 2, b >> 3)
}

// Dark-surface categorical palette (validated for CVD-safe adjacent
// contrast and >=3:1 contrast on a dark surface), assigned in fixed
// order - one hue per page, never cycled per-line.
pub const CATEGORY_BLUE: Rgb565 = rgb565(0x39, 0x87, 0xe5);
pub const CATEGORY_AQUA: Rgb565 = rgb565(0x19, 0x9e, 0x70);
pub const CATEGORY_YELLOW: Rgb565 = rgb565(0xc9, 0x85, 0x00);

// Fixed status colors - reserved for actual state, never reused as a
// generic accent.
pub const STATUS_GOOD: Rgb565 = rgb565(0x0c, 0xa3, 0x0c);
pub const STATUS_CRITICAL: Rgb565 = rgb565(0xd0, 0x3b, 0x3b);

// Secondary ink for labels.
pub const INK_SECONDARY: Rgb565 = rgb565(0xc3, 0xc2, 0xb7);

pub const DOT_INACTIVE: Rgb565 = rgb565(0x38, 0x38, 0x35);
