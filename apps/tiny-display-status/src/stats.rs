use std::fs;
use std::net::UdpSocket;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

pub struct SystemInfo {
    pub hostname: String,
    pub local_ip: String,
    pub uptime_secs: u64,
    pub load_avg_1m: f32,
    pub cpu_percent: Option<f32>,
    pub mem_used_percent: Option<f32>,
    pub temperature_celsius: Option<f32>,
}

pub fn collect_system_info() -> SystemInfo {
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let local_ip = local_ip_via_udp_connect().unwrap_or_else(|| "unknown".to_string());

    let uptime_secs = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|s| s.to_string()))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|v| v as u64)
        .unwrap_or(0);

    let load_avg_1m = fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|s| s.to_string()))
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);

    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_total_kb = parse_meminfo_field(&meminfo, "MemTotal:");
    let mem_available_kb = parse_meminfo_field(&meminfo, "MemAvailable:");
    let mem_used_percent = if mem_total_kb > 0 {
        Some((mem_total_kb.saturating_sub(mem_available_kb) as f32 / mem_total_kb as f32) * 100.0)
    } else {
        None
    };

    SystemInfo {
        hostname,
        local_ip,
        uptime_secs,
        load_avg_1m,
        cpu_percent: sample_cpu_percent(),
        mem_used_percent,
        temperature_celsius: read_temperature_celsius(),
    }
}

fn local_ip_via_udp_connect() -> Option<String> {
    // Doesn't actually send any traffic; connect() on a UDP socket just
    // picks the local address the kernel would route this destination
    // through, which is a standard trick for discovering the outbound
    // interface's address without parsing `ip addr` output.
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.168.178.1:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

static PREV_CPU_SAMPLE: Mutex<Option<(u64, u64)>> = Mutex::new(None);

/// Percentage of CPU busy since the previous call, computed from the
/// `/proc/stat` aggregate `cpu` line. Returns None on the first call,
/// since there's no prior sample yet to diff against.
fn sample_cpu_percent() -> Option<f32> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    let cpu_line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let fields: Vec<u64> = cpu_line
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse::<u64>().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }

    let idle = fields[3] + fields.get(4).copied().unwrap_or(0); // idle + iowait
    let total: u64 = fields.iter().sum();

    let mut prev = PREV_CPU_SAMPLE.lock().ok()?;
    let percent = match *prev {
        Some((prev_idle, prev_total)) => {
            let delta_total = total.saturating_sub(prev_total);
            let delta_idle = idle.saturating_sub(prev_idle);
            if delta_total == 0 {
                None
            } else {
                Some((delta_total.saturating_sub(delta_idle) as f32 / delta_total as f32) * 100.0)
            }
        }
        None => None,
    };
    *prev = Some((idle, total));
    percent
}

fn read_temperature_celsius() -> Option<f32> {
    fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .map(|millidegrees| millidegrees / 1000.0)
}

pub struct StorageInfo {
    pub root_used_percent: Option<u32>,
    pub ssd1_free_gb: Option<f32>,
    pub ssd2_free_gb: Option<f32>,
    pub sdcard_free_gb: Option<f32>,
}

pub fn collect_storage_info() -> StorageInfo {
    StorageInfo {
        root_used_percent: df_used_percent("/"),
        ssd1_free_gb: df_free_gb("/mnt/ssd1"),
        ssd2_free_gb: df_free_gb("/mnt/ssd2"),
        sdcard_free_gb: df_free_gb("/mnt/sdcard"),
    }
}

fn parse_meminfo_field(meminfo: &str, field: &str) -> u64 {
    meminfo
        .lines()
        .find(|line| line.starts_with(field))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

fn df_used_percent(path: &str) -> Option<u32> {
    let output = Command::new("df").arg(path).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().nth(1)?;
    let percent_field = line.split_whitespace().nth(4)?;
    percent_field.trim_end_matches('%').parse::<u32>().ok()
}

fn df_free_gb(path: &str) -> Option<f32> {
    let output = Command::new("df").args(["-k", path]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().nth(1)?;
    let available_kb = line.split_whitespace().nth(3)?.parse::<f32>().ok()?;
    Some(available_kb / (1024.0 * 1024.0))
}

pub struct IronmeshInfo {
    pub reachable: bool,
    pub node_id: Option<String>,
    pub version: Option<String>,
    pub online_nodes: Option<u32>,
    pub offline_nodes: Option<u32>,
}

pub fn collect_ironmesh_info(base_url: &str) -> IronmeshInfo {
    let client = match reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return IronmeshInfo {
                reachable: false,
                node_id: None,
                version: None,
                online_nodes: None,
                offline_nodes: None,
            }
        }
    };

    let health: Option<serde_json::Value> = client
        .get(format!("{base_url}/health"))
        .send()
        .ok()
        .and_then(|resp| resp.json().ok());

    let cluster_status: Option<serde_json::Value> = client
        .get(format!("{base_url}/api/v1/cluster/status"))
        .send()
        .ok()
        .and_then(|resp| resp.json().ok());

    let reachable = health.is_some();
    let node_id = health
        .as_ref()
        .and_then(|v| v.get("node_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let version = health
        .as_ref()
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let online_nodes = cluster_status
        .as_ref()
        .and_then(|v| v.get("online_nodes"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let offline_nodes = cluster_status
        .as_ref()
        .and_then(|v| v.get("offline_nodes"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    IronmeshInfo {
        reachable,
        node_id,
        version,
        online_nodes,
        offline_nodes,
    }
}
