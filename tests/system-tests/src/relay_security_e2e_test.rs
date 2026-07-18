#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::{Context, Result};
    use bytes::Bytes;
    use client_sdk::BootstrapEndpointUse;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use transport_sdk::{RelayMode, TransportPathKind};

    use crate::framework::{
        TEST_ADMIN_TOKEN, fresh_data_dir, issue_bootstrap_bundle_and_enroll_client,
        start_open_server_with_env, start_rendezvous_service_with_env, stop_server,
        wait_for_rendezvous_registered_endpoints,
    };

    const KNOWN_RELAY_PAYLOAD: &[u8] = b"phase1-relay-e2e-known-payload-do-not-leak";
    const UNREACHABLE_DIRECT_ENDPOINT: &str = "http://127.0.0.1:9";

    #[derive(Debug, Default, Clone)]
    struct ObservedRelayTraffic {
        binary_frames: Vec<Vec<u8>>,
        control_messages: Vec<String>,
    }

    struct RelayFrameObserver {
        traffic: Arc<Mutex<ObservedRelayTraffic>>,
        tamper_next_tls_application_data_record: Arc<AtomicBool>,
        tls_application_data_tamper_count: Arc<AtomicUsize>,
        shutdown: watch::Sender<bool>,
        task: JoinHandle<()>,
        public_url: String,
    }

    impl RelayFrameObserver {
        async fn start(upstream_addr: &str) -> Result<Self> {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .context("failed binding relay frame observer")?;
            let local_addr = listener
                .local_addr()
                .context("failed reading relay frame observer address")?;
            let upstream_addr = upstream_addr.to_string();
            let traffic = Arc::new(Mutex::new(ObservedRelayTraffic::default()));
            let tamper_next_tls_application_data_record = Arc::new(AtomicBool::new(false));
            let tls_application_data_tamper_count = Arc::new(AtomicUsize::new(0));
            let (shutdown, mut shutdown_rx) = watch::channel(false);

            let task = tokio::spawn({
                let traffic = Arc::clone(&traffic);
                let tamper_next_tls_application_data_record =
                    Arc::clone(&tamper_next_tls_application_data_record);
                let tls_application_data_tamper_count =
                    Arc::clone(&tls_application_data_tamper_count);
                async move {
                    loop {
                        tokio::select! {
                            changed = shutdown_rx.changed() => {
                                if changed.is_err() || *shutdown_rx.borrow() {
                                    break;
                                }
                            }
                            accepted = listener.accept() => {
                                let Ok((client, _)) = accepted else {
                                    break;
                                };
                                let connection_shutdown = shutdown_rx.clone();
                                let traffic = Arc::clone(&traffic);
                                let tamper_next_tls_application_data_record =
                                    Arc::clone(&tamper_next_tls_application_data_record);
                                let tls_application_data_tamper_count =
                                    Arc::clone(&tls_application_data_tamper_count);
                                let upstream_addr = upstream_addr.clone();
                                tokio::spawn(async move {
                                    relay_connection(
                                        client,
                                        &upstream_addr,
                                        traffic,
                                        tamper_next_tls_application_data_record,
                                        tls_application_data_tamper_count,
                                        connection_shutdown,
                                    )
                                    .await;
                                });
                            }
                        }
                    }
                }
            });

            Ok(Self {
                traffic,
                tamper_next_tls_application_data_record,
                tls_application_data_tamper_count,
                shutdown,
                task,
                public_url: format!("http://{local_addr}"),
            })
        }

        fn public_url(&self) -> &str {
            &self.public_url
        }

        fn snapshot(&self) -> ObservedRelayTraffic {
            self.traffic
                .lock()
                .expect("relay traffic observer lock poisoned")
                .clone()
        }

        fn clear(&self) {
            *self
                .traffic
                .lock()
                .expect("relay traffic observer lock poisoned") = ObservedRelayTraffic::default();
            self.tamper_next_tls_application_data_record
                .store(false, Ordering::SeqCst);
            self.tls_application_data_tamper_count
                .store(0, Ordering::SeqCst);
        }

        fn arm_next_tls_application_data_record_tampering(&self) {
            self.tamper_next_tls_application_data_record
                .store(true, Ordering::SeqCst);
        }

        fn tls_application_data_tamper_count(&self) -> usize {
            self.tls_application_data_tamper_count
                .load(Ordering::SeqCst)
        }

        async fn stop(self) {
            let _ = self.shutdown.send(true);
            let _ = self.task.await;
        }
    }

    async fn relay_connection(
        client: TcpStream,
        upstream_addr: &str,
        traffic: Arc<Mutex<ObservedRelayTraffic>>,
        tamper_next_tls_application_data_record: Arc<AtomicBool>,
        tls_application_data_tamper_count: Arc<AtomicUsize>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let Ok(upstream) = TcpStream::connect(upstream_addr).await else {
            return;
        };
        let (client_read, client_write) = client.into_split();
        let (upstream_read, upstream_write) = upstream.into_split();

        tokio::select! {
            _ = shutdown.changed() => {}
            _ = async {
                let _ = tokio::join!(
                    forward_websocket_frames(
                        client_read,
                        upstream_write,
                        Arc::clone(&traffic),
                        Arc::clone(&tamper_next_tls_application_data_record),
                        Arc::clone(&tls_application_data_tamper_count),
                        true,
                    ),
                    forward_websocket_frames(
                        upstream_read,
                        client_write,
                        traffic,
                        tamper_next_tls_application_data_record,
                        tls_application_data_tamper_count,
                        false,
                    ),
                );
            } => {}
        }
    }

    async fn forward_websocket_frames(
        mut reader: OwnedReadHalf,
        mut writer: OwnedWriteHalf,
        traffic: Arc<Mutex<ObservedRelayTraffic>>,
        tamper_next_tls_application_data_record: Arc<AtomicBool>,
        tls_application_data_tamper_count: Arc<AtomicUsize>,
        source_to_target: bool,
    ) {
        let mut observer = WebSocketFrameForwarder::default();
        let mut read_buffer = [0_u8; 16 * 1024];

        loop {
            let read = match reader.read(&mut read_buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            observer.pending.extend_from_slice(&read_buffer[..read]);

            for mut frame in observer.drain_complete_messages() {
                observe_websocket_frame(
                    &mut frame,
                    &traffic,
                    &tamper_next_tls_application_data_record,
                    &tls_application_data_tamper_count,
                    source_to_target,
                    &mut observer.tampered_tls_application_data_record,
                );
                if writer.write_all(&frame).await.is_err() {
                    return;
                }
            }
        }
    }

    #[derive(Default)]
    struct WebSocketFrameForwarder {
        upgraded: bool,
        pending: Vec<u8>,
        tampered_tls_application_data_record: bool,
    }

    impl WebSocketFrameForwarder {
        fn drain_complete_messages(&mut self) -> Vec<Vec<u8>> {
            let mut ready = Vec::new();
            if !self.upgraded {
                let Some(end) = self
                    .pending
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|offset| offset + 4)
                else {
                    return ready;
                };
                ready.push(self.pending.drain(..end).collect());
                self.upgraded = true;
            }

            while let Some(frame_len) = websocket_frame_len(&self.pending) {
                ready.push(self.pending.drain(..frame_len).collect());
            }
            ready
        }
    }

    fn observe_websocket_frame(
        frame: &mut [u8],
        traffic: &Arc<Mutex<ObservedRelayTraffic>>,
        tamper_next_tls_application_data_record: &Arc<AtomicBool>,
        tls_application_data_tamper_count: &Arc<AtomicUsize>,
        source_to_target: bool,
        tampered_tls_application_data_record: &mut bool,
    ) {
        let Some(metadata) = websocket_frame_metadata(frame) else {
            return;
        };
        let payload = decode_websocket_payload(frame, &metadata);

        match metadata.opcode {
            0x1 => {
                if let Ok(message) = String::from_utf8(payload) {
                    traffic
                        .lock()
                        .expect("relay traffic observer lock poisoned")
                        .control_messages
                        .push(message);
                }
            }
            0x0 | 0x2 => {
                traffic
                    .lock()
                    .expect("relay traffic observer lock poisoned")
                    .binary_frames
                    .push(payload.clone());

                if source_to_target
                    && !*tampered_tls_application_data_record
                    && tamper_next_tls_application_data_record.load(Ordering::SeqCst)
                    && let Some(payload_offset) = tls_application_data_payload_offset(&payload)
                    && tamper_next_tls_application_data_record
                        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                {
                    frame[metadata.payload_start + payload_offset] ^= 0x01;
                    *tampered_tls_application_data_record = true;
                    tls_application_data_tamper_count.fetch_add(1, Ordering::SeqCst);
                }
            }
            _ => {}
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct WebSocketFrameMetadata {
        opcode: u8,
        payload_start: usize,
        payload_end: usize,
        mask_key: Option<[u8; 4]>,
    }

    fn websocket_frame_len(buffer: &[u8]) -> Option<usize> {
        if buffer.len() < 2 {
            return None;
        }
        let masked = buffer[1] & 0x80 != 0;
        let mut cursor = 2;
        let payload_len = match buffer[1] & 0x7f {
            len @ 0..=125 => usize::from(len),
            126 => {
                if buffer.len() < cursor + 2 {
                    return None;
                }
                let len = u16::from_be_bytes([buffer[cursor], buffer[cursor + 1]]);
                cursor += 2;
                usize::from(len)
            }
            127 => {
                if buffer.len() < cursor + 8 {
                    return None;
                }
                let len = u64::from_be_bytes(buffer[cursor..cursor + 8].try_into().ok()?);
                cursor += 8;
                usize::try_from(len).ok()?
            }
            _ => return None,
        };
        if masked {
            cursor = cursor.checked_add(4)?;
        }
        cursor
            .checked_add(payload_len)
            .filter(|len| *len <= buffer.len())
    }

    fn websocket_frame_metadata(frame: &[u8]) -> Option<WebSocketFrameMetadata> {
        let frame_len = websocket_frame_len(frame)?;
        if frame_len != frame.len() {
            return None;
        }
        let masked = frame[1] & 0x80 != 0;
        let mut cursor = 2;
        match frame[1] & 0x7f {
            0..=125 => {}
            126 => cursor += 2,
            127 => cursor += 8,
            _ => return None,
        }
        let mask_key = if masked {
            let key = frame.get(cursor..cursor + 4)?.try_into().ok()?;
            cursor += 4;
            Some(key)
        } else {
            None
        };

        Some(WebSocketFrameMetadata {
            opcode: frame[0] & 0x0f,
            payload_start: cursor,
            payload_end: frame_len,
            mask_key,
        })
    }

    fn decode_websocket_payload(frame: &[u8], metadata: &WebSocketFrameMetadata) -> Vec<u8> {
        let mut payload = frame[metadata.payload_start..metadata.payload_end].to_vec();
        if let Some(mask_key) = metadata.mask_key {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask_key[index % mask_key.len()];
            }
        }
        payload
    }

    fn tls_application_data_payload_offset(payload: &[u8]) -> Option<usize> {
        let mut offset = 0;
        while offset + 5 <= payload.len() {
            let record_len = usize::from(u16::from_be_bytes([
                payload[offset + 3],
                payload[offset + 4],
            ]));
            let record_end = offset + 5 + record_len;
            if record_end > payload.len() {
                return None;
            }
            if payload[offset] == 0x17
                && payload[offset + 1..offset + 3] == [0x03, 0x03]
                && record_len > 0
            {
                return Some(offset + 5);
            }
            offset = record_end;
        }
        None
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[tokio::test]
    async fn relay_only_enrolled_client_keeps_frames_opaque_and_rejects_post_handshake_tampering_without_committing_write()
    -> Result<()> {
        let rendezvous_bind = "127.0.0.1:19266";
        let server_bind = "127.0.0.1:19267";
        let cluster_id = "11111111-1111-7111-8111-111111111166";
        let node_id = "00000000-0000-0000-0000-000000000966";
        let rendezvous_url = format!("http://{rendezvous_bind}");
        let server_url = format!("http://{server_bind}");
        let client_dir = fresh_data_dir("relay-security-e2e-client");
        let server_dir = fresh_data_dir("relay-security-e2e-server");

        std::fs::create_dir_all(&client_dir)?;
        let observer = RelayFrameObserver::start(rendezvous_bind).await?;
        let rendezvous_env = [("IRONMESH_RELAY_PUBLIC_URLS", observer.public_url())];
        let node_env = [
            ("IRONMESH_CLUSTER_ID", cluster_id),
            ("IRONMESH_RENDEZVOUS_URLS", rendezvous_url.as_str()),
            ("IRONMESH_RELAY_MODE", "required"),
            ("IRONMESH_PUBLIC_PEER_API_ENABLED", "true"),
            ("IRONMESH_REQUIRE_CLIENT_AUTH", "true"),
            ("IRONMESH_ADMIN_TOKEN", TEST_ADMIN_TOKEN),
        ];

        let mut rendezvous =
            start_rendezvous_service_with_env(rendezvous_bind, &rendezvous_env).await?;
        let mut server =
            start_open_server_with_env(server_bind, &server_dir, node_id, 1, &node_env).await?;
        let http = reqwest::Client::new();

        let result = async {
            wait_for_rendezvous_registered_endpoints(&rendezvous_url, 1, 120).await?;

            let enrolled = issue_bootstrap_bundle_and_enroll_client(
                &http,
                &server_url,
                TEST_ADMIN_TOKEN,
                &client_dir,
                "relay-security-e2e.bootstrap.json",
                Some("relay-security-e2e"),
                Some(3600),
            )
            .await?;
            assert!(
                enrolled.identity.rendezvous_client_identity_pem.is_some(),
                "relay enrollment must issue the device identity used by inner mTLS"
            );

            let mut relay_only_bootstrap = enrolled.bootstrap.clone();
            relay_only_bootstrap.relay_mode = RelayMode::Required;
            for endpoint in &mut relay_only_bootstrap.direct_endpoints {
                endpoint.url = UNREACHABLE_DIRECT_ENDPOINT.to_string();
            }
            assert!(
                relay_only_bootstrap
                    .direct_endpoints
                    .iter()
                    .filter(|endpoint| endpoint.usage == Some(BootstrapEndpointUse::PublicApi))
                    .all(|endpoint| endpoint.url == UNREACHABLE_DIRECT_ENDPOINT),
                "the enrolled client must not retain a reachable direct public endpoint"
            );
            assert!(
                relay_only_bootstrap
                    .planned_targets()?
                    .iter()
                    .all(|target| target.path_kind == TransportPathKind::RelayTunnel),
                "RelayMode::Required must exclude every direct transport target"
            );

            let client = {
                let bootstrap = relay_only_bootstrap.clone();
                let identity = enrolled.identity.clone();
                tokio::task::spawn_blocking(move || bootstrap.build_client_with_identity(&identity))
                    .await
                    .context("relay-only client construction task panicked")??
            };
            assert!(client.uses_relay_transport());

            client
                .put(
                    "relay-security-e2e.bin",
                    Bytes::from_static(KNOWN_RELAY_PAYLOAD),
                )
                .await?;
            assert_eq!(
                client.get("relay-security-e2e.bin").await?,
                Bytes::from_static(KNOWN_RELAY_PAYLOAD)
            );

            let observed = observer.snapshot();
            assert!(
                !observed.binary_frames.is_empty(),
                "the relay observer did not receive binary relay frames"
            );
            assert!(
                observed
                    .control_messages
                    .iter()
                    .any(|message| message.contains("\"security_mode\":\"inner_mtls\"")),
                "the relay ticket/control metadata must select inner_mtls"
            );
            assert!(
                observed
                    .control_messages
                    .iter()
                    .all(|message| !message.contains("legacy_plaintext")),
                "the relay session must not negotiate a legacy plaintext fallback"
            );

            let observed_ciphertext = observed.binary_frames.concat();
            for forbidden in [
                b"GET /".as_slice(),
                b"PUT /".as_slice(),
                b"POST /".as_slice(),
                b"DELETE /".as_slice(),
                b"Authorization:".as_slice(),
                b"Bearer ".as_slice(),
                b"x-ironmesh-auth-signature".as_slice(),
                b"x-ironmesh-credential-fingerprint".as_slice(),
                KNOWN_RELAY_PAYLOAD,
                enrolled
                    .identity
                    .credential_pem
                    .as_deref()
                    .unwrap_or_default()
                    .as_bytes(),
            ] {
                assert!(
                    !contains_bytes(&observed_ciphertext, forbidden),
                    "relay binary frames exposed known plaintext {:?}",
                    String::from_utf8_lossy(forbidden)
                );
            }

            let tampered_client = {
                let bootstrap = relay_only_bootstrap;
                let identity = enrolled.identity.clone();
                tokio::task::spawn_blocking(move || bootstrap.build_client_with_identity(&identity))
                    .await
                    .context("tampered relay-only client construction task panicked")??
            };
            assert_eq!(
                tampered_client.get("relay-security-e2e.bin").await?,
                Bytes::from_static(KNOWN_RELAY_PAYLOAD),
                "the second client must complete inner mTLS before tampering is armed"
            );

            observer.clear();
            observer.arm_next_tls_application_data_record_tampering();
            let tampered_result = timeout(
                Duration::from_secs(30),
                tampered_client.put(
                    "relay-security-e2e-tampered.bin",
                    Bytes::from_static(KNOWN_RELAY_PAYLOAD),
                ),
            )
            .await
            .context("tampered relay request timed out")?;
            assert!(
                tampered_result.is_err(),
                "a relay session with modified inner-TLS ciphertext must fail closed"
            );
            assert!(
                observer.tls_application_data_tamper_count() == 1,
                "the observer must modify exactly one post-handshake TLS application-data record"
            );
            assert!(
                client.get("relay-security-e2e-tampered.bin").await.is_err(),
                "the node must not commit an object write carried by modified inner-TLS ciphertext"
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        stop_server(&mut rendezvous).await;
        observer.stop().await;
        let _ = std::fs::remove_dir_all(&client_dir);
        let _ = std::fs::remove_dir_all(&server_dir);

        result
    }
}
