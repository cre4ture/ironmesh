mod framebuffer;
mod palette;
mod stats;
#[cfg(target_os = "linux")]
mod touch;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::{FONT_8X13, FONT_10X20};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Circle, PrimitiveStyle};
use embedded_graphics::text::Text;

use framebuffer::FrameBuffer;

const FB_DEVICE: &str = "/dev/fb0";
#[cfg(target_os = "linux")]
const TOUCH_DEVICE: &str = "/dev/input/event0";
// Matches the server-node's optional unauthenticated local status listener,
// see IRONMESH_LOCAL_STATUS_BIND (crates/server-node-sdk).
const IRONMESH_BASE_URL: &str = "http://127.0.0.1:18090";
const NUM_PAGES: usize = 3;
const REFRESH_INTERVAL: Duration = Duration::from_millis(1000);

const BODY_CHAR_WIDTH: i32 = 8; // FONT_8X13 advance width

/// One status line, rendered as a dim label followed by a colored value.
/// `value_color` defaults to the page's accent but can be overridden per
/// line for actual status meaning (e.g. unreachable -> critical red).
struct Line {
    label: &'static str,
    value: String,
    value_color: Option<Rgb565>,
}

fn line(label: &'static str, value: String) -> Line {
    Line {
        label,
        value,
        value_color: None,
    }
}

fn line_colored(label: &'static str, value: String, color: Rgb565) -> Line {
    Line {
        label,
        value,
        value_color: Some(color),
    }
}

fn main() -> anyhow::Result<()> {
    let page_index = Arc::new(AtomicUsize::new(0));

    #[cfg(target_os = "linux")]
    {
        let page_index = Arc::clone(&page_index);
        thread::spawn(move || {
            if let Err(err) = touch::run_swipe_listener(TOUCH_DEVICE, page_index, NUM_PAGES) {
                eprintln!("touch listener stopped: {err:#}");
            }
        });
    }

    let mut fb = FrameBuffer::new(FB_DEVICE);

    loop {
        let page = page_index.load(Ordering::Relaxed);
        render_page(&mut fb, page);
        if let Err(err) = fb.flush() {
            eprintln!("framebuffer flush failed: {err:#}");
        }
        thread::sleep(REFRESH_INTERVAL);
    }
}

fn render_page(fb: &mut FrameBuffer, page: usize) {
    fb.clear_black();

    let (title, accent, lines) = match page {
        0 => {
            let info = stats::collect_system_info();
            (
                "SYSTEM",
                palette::CATEGORY_BLUE,
                vec![
                    line("host: ", info.hostname),
                    line("ip:   ", info.local_ip),
                    line("up:   ", format_duration(info.uptime_secs)),
                    line("load: ", format!("{:.2}", info.load_avg_1m)),
                    line(
                        "cpu:  ",
                        info.cpu_percent
                            .map(|p| format!("{p:.0}%"))
                            .unwrap_or_else(|| "...".to_string()),
                    ),
                    line(
                        "ram:  ",
                        info.mem_used_percent
                            .map(|p| format!("{p:.0}%"))
                            .unwrap_or_else(|| "n/a".to_string()),
                    ),
                    line(
                        "temp: ",
                        info.temperature_celsius
                            .map(|t| format!("{t:.0} C"))
                            .unwrap_or_else(|| "n/a".to_string()),
                    ),
                ],
            )
        }
        1 => {
            let info = stats::collect_storage_info();
            (
                "STORAGE",
                palette::CATEGORY_AQUA,
                vec![
                    line(
                        "root: ",
                        info.root_used_percent
                            .map(|p| format!("{p}% used"))
                            .unwrap_or_else(|| "n/a".to_string()),
                    ),
                    line(
                        "ssd1: ",
                        info.ssd1_free_gb
                            .map(|gb| format!("{gb:.1} GB free"))
                            .unwrap_or_else(|| "not mounted".to_string()),
                    ),
                    line(
                        "ssd2: ",
                        info.ssd2_free_gb
                            .map(|gb| format!("{gb:.1} GB free"))
                            .unwrap_or_else(|| "not mounted".to_string()),
                    ),
                    line(
                        "sd:   ",
                        info.sdcard_free_gb
                            .map(|gb| format!("{gb:.1} GB free"))
                            .unwrap_or_else(|| "not mounted".to_string()),
                    ),
                ],
            )
        }
        _ => {
            let info = stats::collect_ironmesh_info(IRONMESH_BASE_URL);
            if info.reachable {
                (
                    "IRONMESH",
                    palette::CATEGORY_YELLOW,
                    vec![
                        line_colored("node: ", "online".to_string(), palette::STATUS_GOOD),
                        line(
                            "id:   ",
                            info.node_id
                                .map(|id| short_id(&id))
                                .unwrap_or_else(|| "?".to_string()),
                        ),
                        line("ver:  ", info.version.unwrap_or_else(|| "?".to_string())),
                        line(
                            "peers:",
                            format!(
                                "{} up / {} down",
                                info.online_nodes.unwrap_or(0),
                                info.offline_nodes.unwrap_or(0)
                            ),
                        ),
                    ],
                )
            } else {
                (
                    "IRONMESH",
                    palette::CATEGORY_YELLOW,
                    vec![line_colored(
                        "node: ",
                        "unreachable".to_string(),
                        palette::STATUS_CRITICAL,
                    )],
                )
            }
        }
    };

    let header_style = MonoTextStyle::new(&FONT_10X20, accent);
    let label_style = MonoTextStyle::new(&FONT_8X13, palette::INK_SECONDARY);

    Text::new(title, Point::new(8, 26), header_style)
        .draw(fb)
        .ok();

    for (i, entry) in lines.iter().enumerate() {
        let y = 56 + (i as i32) * 20;
        Text::new(entry.label, Point::new(8, y), label_style)
            .draw(fb)
            .ok();

        let value_style = MonoTextStyle::new(&FONT_8X13, entry.value_color.unwrap_or(accent));
        let value_x = 8 + (entry.label.chars().count() as i32) * BODY_CHAR_WIDTH;
        Text::new(&entry.value, Point::new(value_x, y), value_style)
            .draw(fb)
            .ok();
    }

    draw_page_dots(fb, page, accent);
}

fn draw_page_dots(fb: &mut FrameBuffer, active_page: usize, accent: Rgb565) {
    let spacing = 18;
    let start_x = (framebuffer::WIDTH as i32 / 2) - (spacing * (NUM_PAGES as i32 - 1)) / 2;
    let y = framebuffer::HEIGHT as i32 - 18;

    for i in 0..NUM_PAGES {
        let x = start_x + spacing * (i as i32);
        let color = if i == active_page {
            accent
        } else {
            palette::DOT_INACTIVE
        };
        Circle::new(Point::new(x - 4, y - 4), 8)
            .into_styled(PrimitiveStyle::with_fill(color))
            .draw(fb)
            .ok();
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

fn format_duration(total_secs: u64) -> String {
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}
