use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use embedded_graphics::Pixel;
use embedded_graphics::pixelcolor::{IntoStorage, Rgb565};
use embedded_graphics::prelude::*;

pub const WIDTH: usize = 240;
pub const HEIGHT: usize = 240;

/// In-memory RGB565 pixel buffer implementing `DrawTarget`, flushed to a
/// Linux framebuffer device (e.g. `/dev/fb0`) with plain file writes.
///
/// This device's panel (ST7789V via fbtft) is 240x240 at 16 bits/pixel;
/// those dimensions are hardcoded rather than read from sysfs since this
/// binary targets that one panel.
pub struct FrameBuffer {
    pixels: Vec<Rgb565>,
    device_path: std::path::PathBuf,
}

impl FrameBuffer {
    pub fn new(device_path: impl AsRef<Path>) -> Self {
        Self {
            pixels: vec![Rgb565::BLACK; WIDTH * HEIGHT],
            device_path: device_path.as_ref().to_path_buf(),
        }
    }

    pub fn clear_black(&mut self) {
        self.pixels.fill(Rgb565::BLACK);
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        // This panel is mounted rotated 180 degrees relative to the "up"
        // orientation kvm_app renders in (its own display_rotation: 180
        // config compensates for the same thing). Reversing the whole
        // raster is exactly a 180 degree rotation, since it flips both X
        // and Y simultaneously.
        let mut bytes = Vec::with_capacity(WIDTH * HEIGHT * 2);
        for pixel in self.pixels.iter().rev() {
            let raw: u16 = pixel.into_storage();
            bytes.extend_from_slice(&raw.to_ne_bytes());
        }

        let mut file = OpenOptions::new().write(true).open(&self.device_path)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        Ok(())
    }
}

impl OriginDimensions for FrameBuffer {
    fn size(&self) -> Size {
        Size::new(WIDTH as u32, HEIGHT as u32)
    }
}

impl DrawTarget for FrameBuffer {
    type Color = Rgb565;
    type Error = std::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(point, color) in pixels {
            if point.x < 0 || point.y < 0 {
                continue;
            }
            let (x, y) = (point.x as usize, point.y as usize);
            if x < WIDTH && y < HEIGHT {
                self.pixels[y * WIDTH + x] = color;
            }
        }
        Ok(())
    }
}
