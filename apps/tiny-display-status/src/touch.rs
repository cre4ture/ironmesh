use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use evdev::{Device, EventType};

// Raw evdev codes, used directly rather than named constants to stay
// independent of exactly which enum variants a given evdev crate version
// exposes for this touch controller's single-touch protocol.
const ABS_X: u16 = 0x00;
const BTN_TOUCH: u16 = 0x14a;

const SWIPE_THRESHOLD_PX: i32 = 30;

/// Reads swipe gestures from the touchscreen and updates `page_index` by
/// +1/-1 (mod `num_pages`) on a left/right swipe. Runs until the device is
/// unplugged or read errors persist; logs and returns on unrecoverable
/// failure so the caller can decide whether to keep the display running
/// without touch support.
pub fn run_swipe_listener(
    device_path: impl AsRef<Path>,
    page_index: Arc<AtomicUsize>,
    num_pages: usize,
) -> anyhow::Result<()> {
    let mut device = Device::open(device_path.as_ref())?;

    let mut touch_start_x: Option<i32> = None;
    let mut touch_last_x: Option<i32> = None;

    loop {
        for event in device.fetch_events()? {
            match event.event_type() {
                EventType::ABSOLUTE if event.code() == ABS_X => {
                    let x = event.value();
                    touch_last_x = Some(x);
                    if touch_start_x.is_none() {
                        touch_start_x = Some(x);
                    }
                }
                EventType::KEY if event.code() == BTN_TOUCH => {
                    if event.value() == 1 {
                        // Fresh touch starting; drop any stale state.
                        touch_start_x = None;
                        touch_last_x = None;
                    } else if event.value() == 0 {
                        if let (Some(start), Some(last)) = (touch_start_x, touch_last_x) {
                            let delta = last - start;
                            if delta.abs() >= SWIPE_THRESHOLD_PX {
                                let direction: i64 = if delta > 0 { 1 } else { -1 };
                                advance_page(&page_index, num_pages, direction);
                            }
                        }
                        touch_start_x = None;
                        touch_last_x = None;
                    }
                }
                _ => {}
            }
        }
    }
}

fn advance_page(page_index: &AtomicUsize, num_pages: usize, direction: i64) {
    let current = page_index.load(Ordering::Relaxed) as i64;
    let next = (current + direction).rem_euclid(num_pages as i64) as usize;
    page_index.store(next, Ordering::Relaxed);
}
