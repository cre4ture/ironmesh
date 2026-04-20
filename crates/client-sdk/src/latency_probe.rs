use anyhow::{Result, bail};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{IronMeshClient, TransportSessionPoolSnapshot};

const LATENCY_PROBE_ROUTE: &str = "/api/v1/diagnostics/latency";
const LATENCY_PROBE_HEADER_NODE_ID: &str = "x-ironmesh-latency-node-id";
const LATENCY_PROBE_HEADER_RESPONSE_BYTES: &str = "x-ironmesh-latency-response-bytes";
const LATENCY_PROBE_HEADER_SERVER_DURATION_MS: &str = "x-ironmesh-latency-server-duration-ms";
const MAX_LATENCY_PROBE_SAMPLES: usize = 64;
const MAX_LATENCY_PROBE_WARMUP_SAMPLES: usize = 16;
const MAX_LATENCY_PROBE_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_LATENCY_PROBE_SERVER_DELAY_MS: u64 = 5_000;
const MAX_LATENCY_PROBE_PAUSE_MS: u64 = 5_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProbeConfig {
    pub sample_count: usize,
    #[serde(default)]
    pub warmup_count: usize,
    #[serde(default = "default_latency_probe_response_bytes")]
    pub response_bytes: usize,
    #[serde(default)]
    pub server_delay_ms: u64,
    #[serde(default = "default_latency_probe_pause_ms")]
    pub pause_between_samples_ms: u64,
}

impl Default for LatencyProbeConfig {
    fn default() -> Self {
        Self {
            sample_count: default_latency_probe_sample_count(),
            warmup_count: 1,
            response_bytes: default_latency_probe_response_bytes(),
            server_delay_ms: 0,
            pause_between_samples_ms: default_latency_probe_pause_ms(),
        }
    }
}

impl LatencyProbeConfig {
    pub fn validate(&self) -> Result<()> {
        if self.sample_count == 0 {
            bail!("sample_count must be at least 1");
        }
        if self.sample_count > MAX_LATENCY_PROBE_SAMPLES {
            bail!("sample_count must be <= {MAX_LATENCY_PROBE_SAMPLES}");
        }
        if self.warmup_count > MAX_LATENCY_PROBE_WARMUP_SAMPLES {
            bail!("warmup_count must be <= {MAX_LATENCY_PROBE_WARMUP_SAMPLES}");
        }
        if self.response_bytes > MAX_LATENCY_PROBE_RESPONSE_BYTES {
            bail!("response_bytes must be <= {MAX_LATENCY_PROBE_RESPONSE_BYTES}");
        }
        if self.server_delay_ms > MAX_LATENCY_PROBE_SERVER_DELAY_MS {
            bail!("server_delay_ms must be <= {MAX_LATENCY_PROBE_SERVER_DELAY_MS}");
        }
        if self.pause_between_samples_ms > MAX_LATENCY_PROBE_PAUSE_MS {
            bail!("pause_between_samples_ms must be <= {MAX_LATENCY_PROBE_PAUSE_MS}");
        }
        Ok(())
    }
}

fn default_latency_probe_sample_count() -> usize {
    6
}

fn default_latency_probe_response_bytes() -> usize {
    1024
}

fn default_latency_probe_pause_ms() -> u64 {
    125
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LatencyProbeAssessment {
    Healthy,
    Warn,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProbeSample {
    pub index: usize,
    pub started_unix_ms: u64,
    pub successful: bool,
    #[serde(default)]
    pub status_code: Option<u16>,
    pub total_duration_ms: f64,
    #[serde(default)]
    pub server_duration_ms: Option<f64>,
    #[serde(default)]
    pub transport_overhead_ms: Option<f64>,
    #[serde(default)]
    pub response_bytes: usize,
    #[serde(default)]
    pub throughput_bytes_per_sec: Option<f64>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProbeSummary {
    pub requested_samples: usize,
    pub success_count: usize,
    pub failure_count: usize,
    #[serde(default)]
    pub min_total_duration_ms: Option<f64>,
    #[serde(default)]
    pub avg_total_duration_ms: Option<f64>,
    #[serde(default)]
    pub p50_total_duration_ms: Option<f64>,
    #[serde(default)]
    pub p95_total_duration_ms: Option<f64>,
    #[serde(default)]
    pub max_total_duration_ms: Option<f64>,
    #[serde(default)]
    pub avg_server_duration_ms: Option<f64>,
    #[serde(default)]
    pub avg_transport_overhead_ms: Option<f64>,
    #[serde(default)]
    pub p95_transport_overhead_ms: Option<f64>,
    #[serde(default)]
    pub avg_throughput_bytes_per_sec: Option<f64>,
    pub assessment: LatencyProbeAssessment,
    #[serde(default)]
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProbeResult {
    pub config: LatencyProbeConfig,
    pub route: String,
    pub generated_at_unix_ms: u64,
    #[serde(default)]
    pub cold_connect_duration_ms: Option<f64>,
    #[serde(default)]
    pub transport_session_pool: TransportSessionPoolSnapshot,
    pub samples: Vec<LatencyProbeSample>,
    pub summary: LatencyProbeSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProbeComparison {
    pub assessment: LatencyProbeAssessment,
    #[serde(default)]
    pub relay_avg_total_delta_ms: Option<f64>,
    #[serde(default)]
    pub relay_avg_total_ratio: Option<f64>,
    #[serde(default)]
    pub relay_avg_transport_overhead_delta_ms: Option<f64>,
    #[serde(default)]
    pub observations: Vec<String>,
}

impl IronMeshClient {
    pub async fn run_latency_probe(
        &self,
        config: LatencyProbeConfig,
    ) -> Result<LatencyProbeResult> {
        config.validate()?;

        let request_path = format!(
            "{LATENCY_PROBE_ROUTE}?response_bytes={}&server_delay_ms={}",
            config.response_bytes, config.server_delay_ms
        );

        let session_pool_before = self.transport_session_pool_snapshot();
        let mut cold_connect_duration_ms = None;
        let mut samples = Vec::with_capacity(config.sample_count);
        let total_requests = config.warmup_count + config.sample_count;
        for request_index in 0..total_requests {
            if request_index > 0 && config.pause_between_samples_ms > 0 {
                tokio::time::sleep(Duration::from_millis(config.pause_between_samples_ms)).await;
            }

            let started_unix_ms = unix_ts_ms();
            let started_at = Instant::now();
            let sample = match self.get_relative_path(&request_path).await {
                Ok(response) => {
                    let total_duration_ms = started_at.elapsed().as_secs_f64() * 1000.0;
                    let server_duration_ms = parse_header_f64(
                        &response.headers,
                        LATENCY_PROBE_HEADER_SERVER_DURATION_MS,
                    );
                    let transport_overhead_ms =
                        server_duration_ms.map(|duration| (total_duration_ms - duration).max(0.0));
                    let response_bytes =
                        parse_header_usize(&response.headers, LATENCY_PROBE_HEADER_RESPONSE_BYTES)
                            .unwrap_or(response.body.len());
                    let throughput_bytes_per_sec = if total_duration_ms > 0.0 {
                        Some(response.body.len() as f64 / (total_duration_ms / 1000.0))
                    } else {
                        None
                    };
                    let successful = response.status.is_success();

                    LatencyProbeSample {
                        index: request_index.saturating_sub(config.warmup_count),
                        started_unix_ms,
                        successful,
                        status_code: Some(response.status.as_u16()),
                        total_duration_ms,
                        server_duration_ms,
                        transport_overhead_ms,
                        response_bytes,
                        throughput_bytes_per_sec,
                        node_id: parse_header_string(
                            &response.headers,
                            LATENCY_PROBE_HEADER_NODE_ID,
                        ),
                        error: (!successful).then(|| {
                            let body = String::from_utf8_lossy(response.body.as_ref());
                            if body.trim().is_empty() {
                                format!("probe returned HTTP {}", response.status)
                            } else {
                                format!("probe returned HTTP {}: {}", response.status, body.trim())
                            }
                        }),
                    }
                }
                Err(error) => LatencyProbeSample {
                    index: request_index.saturating_sub(config.warmup_count),
                    started_unix_ms,
                    successful: false,
                    status_code: None,
                    total_duration_ms: started_at.elapsed().as_secs_f64() * 1000.0,
                    server_duration_ms: None,
                    transport_overhead_ms: None,
                    response_bytes: 0,
                    throughput_bytes_per_sec: None,
                    node_id: None,
                    error: Some(error.to_string()),
                },
            };

            if request_index == 0 {
                let session_pool_after_first = self.transport_session_pool_snapshot();
                if session_pool_after_first.connect_count > session_pool_before.connect_count {
                    cold_connect_duration_ms = Some(sample.total_duration_ms);
                }
            }

            if request_index >= config.warmup_count {
                samples.push(sample);
            }
        }

        let session_pool_after = self.transport_session_pool_snapshot();
        let session_pool_delta = TransportSessionPoolSnapshot {
            connect_count: session_pool_after
                .connect_count
                .saturating_sub(session_pool_before.connect_count),
            reuse_count: session_pool_after
                .reuse_count
                .saturating_sub(session_pool_before.reuse_count),
            reset_count: session_pool_after
                .reset_count
                .saturating_sub(session_pool_before.reset_count),
        };
        let summary = summarize_latency_probe(
            &samples,
            config.sample_count,
            cold_connect_duration_ms,
            session_pool_delta,
        );
        Ok(LatencyProbeResult {
            config,
            route: LATENCY_PROBE_ROUTE.to_string(),
            generated_at_unix_ms: unix_ts_ms(),
            cold_connect_duration_ms,
            transport_session_pool: session_pool_delta,
            samples,
            summary,
        })
    }
}

pub fn compare_direct_and_relay_latency(
    direct: Option<&LatencyProbeResult>,
    relay: Option<&LatencyProbeResult>,
) -> Option<LatencyProbeComparison> {
    let direct = direct?;
    let relay = relay?;
    let direct_avg_total = direct.summary.avg_total_duration_ms?;
    let relay_avg_total = relay.summary.avg_total_duration_ms?;

    let relay_avg_total_delta_ms = Some((relay_avg_total - direct_avg_total).max(0.0));
    let relay_avg_total_ratio = if direct_avg_total > 0.0 {
        Some(relay_avg_total / direct_avg_total)
    } else {
        None
    };
    let relay_avg_transport_overhead_delta_ms = match (
        direct.summary.avg_transport_overhead_ms,
        relay.summary.avg_transport_overhead_ms,
    ) {
        (Some(direct_overhead), Some(relay_overhead)) => {
            Some((relay_overhead - direct_overhead).max(0.0))
        }
        _ => None,
    };

    let mut assessment = LatencyProbeAssessment::Healthy;
    let mut observations = Vec::new();

    if let Some(delta_ms) = relay_avg_total_delta_ms {
        if delta_ms >= 200.0 {
            assessment = LatencyProbeAssessment::Degraded;
        } else if delta_ms >= 75.0 {
            assessment = LatencyProbeAssessment::Warn;
        }
    }
    if let Some(ratio) = relay_avg_total_ratio {
        if ratio >= 4.0 {
            assessment = LatencyProbeAssessment::Degraded;
        } else if ratio >= 2.0 && assessment == LatencyProbeAssessment::Healthy {
            assessment = LatencyProbeAssessment::Warn;
        }
    }

    if let (Some(delta_ms), Some(ratio)) = (relay_avg_total_delta_ms, relay_avg_total_ratio)
        && (delta_ms >= 75.0 || ratio >= 2.0)
    {
        observations.push(format!(
            "Relay average latency is {:.1} ms higher than direct ({:.2}x slower).",
            delta_ms, ratio
        ));
    }

    if let Some(delta_ms) = relay_avg_transport_overhead_delta_ms
        && delta_ms >= 75.0
    {
        observations.push(format!(
            "Most of the relay slowdown appears outside server processing (+{delta_ms:.1} ms average transport overhead)."
        ));
    }

    Some(LatencyProbeComparison {
        assessment,
        relay_avg_total_delta_ms,
        relay_avg_total_ratio,
        relay_avg_transport_overhead_delta_ms,
        observations,
    })
}

fn summarize_latency_probe(
    samples: &[LatencyProbeSample],
    requested_samples: usize,
    cold_connect_duration_ms: Option<f64>,
    session_pool: TransportSessionPoolSnapshot,
) -> LatencyProbeSummary {
    let successful_samples = samples
        .iter()
        .filter(|sample| sample.successful)
        .collect::<Vec<_>>();
    let failure_count = samples.len().saturating_sub(successful_samples.len());

    let total_durations = successful_samples
        .iter()
        .map(|sample| sample.total_duration_ms)
        .collect::<Vec<_>>();
    let server_durations = successful_samples
        .iter()
        .filter_map(|sample| sample.server_duration_ms)
        .collect::<Vec<_>>();
    let transport_overheads = successful_samples
        .iter()
        .filter_map(|sample| sample.transport_overhead_ms)
        .collect::<Vec<_>>();
    let throughput_values = successful_samples
        .iter()
        .filter_map(|sample| sample.throughput_bytes_per_sec)
        .collect::<Vec<_>>();

    let mut assessment = LatencyProbeAssessment::Healthy;
    let mut observations = Vec::new();

    if successful_samples.is_empty() {
        return LatencyProbeSummary {
            requested_samples,
            success_count: 0,
            failure_count,
            min_total_duration_ms: None,
            avg_total_duration_ms: None,
            p50_total_duration_ms: None,
            p95_total_duration_ms: None,
            max_total_duration_ms: None,
            avg_server_duration_ms: None,
            avg_transport_overhead_ms: None,
            p95_transport_overhead_ms: None,
            avg_throughput_bytes_per_sec: None,
            assessment: LatencyProbeAssessment::Degraded,
            observations: vec!["All latency probe samples failed.".to_string()],
        };
    }

    let avg_total_duration_ms = average(&total_durations);
    let p95_total_duration_ms = percentile_nearest_rank(&total_durations, 0.95);
    let avg_server_duration_ms = average(&server_durations);
    let avg_transport_overhead_ms = average(&transport_overheads);
    let p95_transport_overhead_ms = percentile_nearest_rank(&transport_overheads, 0.95);
    let min_total_duration_ms = total_durations.iter().copied().reduce(f64::min);
    let max_total_duration_ms = total_durations.iter().copied().reduce(f64::max);

    if failure_count > 0 {
        assessment = LatencyProbeAssessment::Warn;
        observations.push(format!(
            "{failure_count} of {requested_samples} latency probe samples failed."
        ));
    }

    if let Some(overhead_ms) = avg_transport_overhead_ms {
        if overhead_ms >= 250.0 {
            assessment = LatencyProbeAssessment::Degraded;
        } else if overhead_ms >= 100.0 && assessment == LatencyProbeAssessment::Healthy {
            assessment = LatencyProbeAssessment::Warn;
        }
    }
    if let Some(overhead_ms) = p95_transport_overhead_ms {
        if overhead_ms >= 400.0 {
            assessment = LatencyProbeAssessment::Degraded;
        } else if overhead_ms >= 175.0 && assessment == LatencyProbeAssessment::Healthy {
            assessment = LatencyProbeAssessment::Warn;
        }
    }

    if let (Some(server_ms), Some(overhead_ms)) =
        (avg_server_duration_ms, avg_transport_overhead_ms)
        && server_ms <= 25.0
        && overhead_ms >= server_ms + 75.0
    {
        observations.push(
            "Most of the elapsed time is outside server processing, which usually points to transport or relay overhead."
                .to_string(),
        );
    }

    if let (Some(min_ms), Some(max_ms)) = (min_total_duration_ms, max_total_duration_ms)
        && max_ms - min_ms >= 150.0
    {
        if assessment == LatencyProbeAssessment::Healthy {
            assessment = LatencyProbeAssessment::Warn;
        }
        observations.push(format!(
            "Latency jitter is high across samples ({:.1} ms spread between min and max).",
            max_ms - min_ms
        ));
    }

    if session_pool.connect_count > 0 {
        observations.push(format!(
            "Probe opened {} transport session(s) and reused warm sessions {} time(s).",
            session_pool.connect_count, session_pool.reuse_count
        ));
    }
    if session_pool.reset_count > 0 {
        if assessment == LatencyProbeAssessment::Healthy {
            assessment = LatencyProbeAssessment::Warn;
        }
        observations.push(format!(
            "Transport sessions reset {} time(s) during the probe.",
            session_pool.reset_count
        ));
    }
    if let (Some(cold_ms), Some(avg_ms)) = (cold_connect_duration_ms, avg_total_duration_ms)
        && cold_ms >= avg_ms + 25.0
    {
        observations.push(format!(
            "Cold session setup took {:.1} ms versus {:.1} ms average for measured warm requests.",
            cold_ms, avg_ms
        ));
    }

    LatencyProbeSummary {
        requested_samples,
        success_count: successful_samples.len(),
        failure_count,
        min_total_duration_ms,
        avg_total_duration_ms,
        p50_total_duration_ms: percentile_nearest_rank(&total_durations, 0.50),
        p95_total_duration_ms,
        max_total_duration_ms,
        avg_server_duration_ms,
        avg_transport_overhead_ms,
        p95_transport_overhead_ms,
        avg_throughput_bytes_per_sec: average(&throughput_values),
        assessment,
        observations,
    }
}

fn parse_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn parse_header_usize(headers: &HeaderMap, name: &str) -> Option<usize> {
    parse_header_string(headers, name).and_then(|value| value.parse::<usize>().ok())
}

fn parse_header_f64(headers: &HeaderMap, name: &str) -> Option<f64> {
    parse_header_string(headers, name).and_then(|value| value.parse::<f64>().ok())
}

fn percentile_nearest_rank(values: &[f64], percentile: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let clamped = percentile.clamp(0.0, 1.0);
    let rank = ((sorted.len() as f64 - 1.0) * clamped).round() as usize;
    sorted.get(rank).copied()
}

fn average(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    Some(values.iter().sum::<f64>() / values.len() as f64)
}

fn unix_ts_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Router, body::Body};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct ProbeQuery {
        response_bytes: Option<usize>,
        server_delay_ms: Option<u64>,
    }

    async fn diagnostics_route(Query(query): Query<ProbeQuery>) -> impl IntoResponse {
        let response_bytes = query.response_bytes.unwrap_or(0);
        let server_delay_ms = query.server_delay_ms.unwrap_or(0);
        if server_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(server_delay_ms)).await;
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            LATENCY_PROBE_HEADER_NODE_ID,
            HeaderValue::from_static("node-123"),
        );
        headers.insert(
            LATENCY_PROBE_HEADER_RESPONSE_BYTES,
            HeaderValue::from_str(&response_bytes.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0")),
        );
        headers.insert(
            LATENCY_PROBE_HEADER_SERVER_DURATION_MS,
            HeaderValue::from_static("5"),
        );
        (
            StatusCode::OK,
            headers,
            Body::from(vec![0_u8; response_bytes]),
        )
    }

    async fn spawn_probe_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(LATENCY_PROBE_ROUTE, get(diagnostics_route)),
            )
            .await
            .expect("probe server should run");
        });
        (format!("http://{addr}"), server)
    }

    #[test]
    fn latency_probe_config_rejects_invalid_values() {
        let error = LatencyProbeConfig {
            sample_count: 0,
            ..LatencyProbeConfig::default()
        }
        .validate()
        .expect_err("zero sample_count should fail");
        assert!(error.to_string().contains("sample_count"));
    }

    #[tokio::test]
    async fn latency_probe_collects_samples_and_summary() {
        let (base_url, server) = spawn_probe_server().await;
        let client = IronMeshClient::from_direct_base_url(base_url);

        let result = client
            .run_latency_probe(LatencyProbeConfig {
                sample_count: 3,
                warmup_count: 0,
                response_bytes: 32,
                server_delay_ms: 0,
                pause_between_samples_ms: 0,
            })
            .await
            .expect("latency probe should succeed");

        assert_eq!(result.samples.len(), 3);
        assert_eq!(result.summary.success_count, 3);
        assert_eq!(result.summary.failure_count, 0);
        assert!(result.summary.avg_total_duration_ms.is_some());
        assert_eq!(result.transport_session_pool.connect_count, 0);
        assert_eq!(result.transport_session_pool.reuse_count, 0);
        assert_eq!(result.transport_session_pool.reset_count, 0);
        assert!(result.cold_connect_duration_ms.is_none());
        assert!(
            result
                .samples
                .iter()
                .all(|sample| sample.response_bytes == 32 && sample.successful)
        );

        server.abort();
        let _ = server.await;
    }

    #[test]
    fn compare_direct_and_relay_flags_large_gap() {
        let direct = LatencyProbeResult {
            config: LatencyProbeConfig::default(),
            route: LATENCY_PROBE_ROUTE.to_string(),
            generated_at_unix_ms: 1,
            cold_connect_duration_ms: Some(35.0),
            transport_session_pool: TransportSessionPoolSnapshot {
                connect_count: 1,
                reuse_count: 3,
                reset_count: 0,
            },
            samples: Vec::new(),
            summary: LatencyProbeSummary {
                requested_samples: 3,
                success_count: 3,
                failure_count: 0,
                min_total_duration_ms: Some(20.0),
                avg_total_duration_ms: Some(25.0),
                p50_total_duration_ms: Some(25.0),
                p95_total_duration_ms: Some(30.0),
                max_total_duration_ms: Some(30.0),
                avg_server_duration_ms: Some(5.0),
                avg_transport_overhead_ms: Some(20.0),
                p95_transport_overhead_ms: Some(25.0),
                avg_throughput_bytes_per_sec: None,
                assessment: LatencyProbeAssessment::Healthy,
                observations: Vec::new(),
            },
        };
        let relay = LatencyProbeResult {
            config: LatencyProbeConfig::default(),
            route: LATENCY_PROBE_ROUTE.to_string(),
            generated_at_unix_ms: 1,
            cold_connect_duration_ms: Some(210.0),
            transport_session_pool: TransportSessionPoolSnapshot {
                connect_count: 1,
                reuse_count: 3,
                reset_count: 0,
            },
            samples: Vec::new(),
            summary: LatencyProbeSummary {
                requested_samples: 3,
                success_count: 3,
                failure_count: 0,
                min_total_duration_ms: Some(140.0),
                avg_total_duration_ms: Some(180.0),
                p50_total_duration_ms: Some(180.0),
                p95_total_duration_ms: Some(220.0),
                max_total_duration_ms: Some(220.0),
                avg_server_duration_ms: Some(8.0),
                avg_transport_overhead_ms: Some(172.0),
                p95_transport_overhead_ms: Some(212.0),
                avg_throughput_bytes_per_sec: None,
                assessment: LatencyProbeAssessment::Warn,
                observations: Vec::new(),
            },
        };

        let comparison = compare_direct_and_relay_latency(Some(&direct), Some(&relay))
            .expect("comparison should be available");
        assert_eq!(comparison.assessment, LatencyProbeAssessment::Degraded);
        assert!(comparison.relay_avg_total_delta_ms.unwrap_or_default() >= 150.0);
        assert!(!comparison.observations.is_empty());
    }

    #[test]
    fn latency_probe_summary_reports_session_reuse_and_cold_connect() {
        let summary = summarize_latency_probe(
            &[LatencyProbeSample {
                index: 0,
                started_unix_ms: 1,
                successful: true,
                status_code: Some(200),
                total_duration_ms: 18.0,
                server_duration_ms: Some(2.0),
                transport_overhead_ms: Some(16.0),
                response_bytes: 32,
                throughput_bytes_per_sec: Some(1000.0),
                node_id: Some("node-123".to_string()),
                error: None,
            }],
            1,
            Some(64.0),
            TransportSessionPoolSnapshot {
                connect_count: 1,
                reuse_count: 4,
                reset_count: 1,
            },
        );

        assert!(
            summary
                .observations
                .iter()
                .any(|entry| entry.contains("reused warm sessions 4 time(s)"))
        );
        assert!(
            summary
                .observations
                .iter()
                .any(|entry| entry.contains("Cold session setup took 64.0 ms"))
        );
        assert_eq!(summary.assessment, LatencyProbeAssessment::Warn);
    }
}
