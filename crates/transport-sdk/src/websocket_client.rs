use anyhow::{Context, Result, anyhow, bail};
use reqwest::Url;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};

pub trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub async fn connect_websocket(
    url: &Url,
    server_ca_pem: Option<&str>,
    client_identity_pem: Option<&[u8]>,
    headers: &[(String, String)],
) -> Result<WebSocketStream<Box<dyn AsyncIo>>> {
    let stream = open_websocket_io(url, server_ca_pem, client_identity_pem).await?;
    let mut request = url
        .as_str()
        .into_client_request()
        .context("failed building websocket client request")?;
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid websocket request header name {name}"))?;
        let value = HeaderValue::from_str(value)
            .with_context(|| format!("invalid websocket request header value for {name}"))?;
        request.headers_mut().insert(name, value);
    }
    let (websocket, _response) = client_async(request, stream)
        .await
        .context("websocket handshake failed")?;
    Ok(websocket)
}

pub fn websocket_url(base_url: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(base_url.trim())
        .with_context(|| format!("invalid websocket base URL {base_url}"))?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        "ws" => "ws",
        "wss" => "wss",
        other => bail!("unsupported websocket base URL scheme {other}"),
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow!("failed setting websocket URL scheme"))?;
    url.join(path.trim_start_matches('/'))
        .with_context(|| format!("failed building websocket URL from {base_url} and {path}"))
}

async fn open_websocket_io(
    url: &Url,
    server_ca_pem: Option<&str>,
    client_identity_pem: Option<&[u8]>,
) -> Result<Box<dyn AsyncIo>> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("websocket URL is missing a host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("websocket URL is missing a port"))?;
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("failed connecting websocket TCP stream to {host}:{port}"))?;

    match url.scheme() {
        "ws" => Ok(Box::new(tcp)),
        "wss" => {
            let server_name = ServerName::try_from(host.to_string())
                .context("failed building TLS server name")?;
            let tls_stream = TlsConnector::from(std::sync::Arc::new(build_tls_client_config(
                server_ca_pem,
                client_identity_pem,
            )?))
            .connect(server_name, tcp)
            .await
            .with_context(|| {
                format!("failed establishing TLS websocket stream to {host}:{port}")
            })?;
            Ok(Box::new(tls_stream))
        }
        other => bail!("unsupported websocket URL scheme {other}"),
    }
}

fn build_tls_client_config(
    server_ca_pem: Option<&str>,
    client_identity_pem: Option<&[u8]>,
) -> Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    if let Some(server_ca_pem) = server_ca_pem {
        let mut reader = std::io::Cursor::new(server_ca_pem.as_bytes());
        for cert in CertificateDer::pem_reader_iter(&mut reader) {
            let cert = cert.context("failed parsing websocket server CA certificate")?;
            roots
                .add(cert)
                .context("failed adding websocket server CA certificate")?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            roots
                .add(cert)
                .context("failed adding native websocket root certificate")?;
        }
        if !native.errors.is_empty() && roots.is_empty() {
            bail!("failed loading native root certificates for websocket TLS");
        }
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    match client_identity_pem {
        Some(identity_pem) => {
            let (cert_chain, key) = parse_client_identity_pem(identity_pem)?;
            builder
                .with_client_auth_cert(cert_chain, key)
                .context("failed building websocket TLS client identity")
        }
        None => Ok(builder.with_no_client_auth()),
    }
}

fn parse_client_identity_pem(
    identity_pem: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_reader = std::io::Cursor::new(identity_pem);
    let cert_chain = CertificateDer::pem_reader_iter(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed parsing websocket client certificate chain")?;
    if cert_chain.is_empty() {
        bail!("websocket client identity PEM is missing a certificate chain");
    }

    let mut key_reader = std::io::Cursor::new(identity_pem);
    let key = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .context("failed parsing websocket client private key")?;
    Ok((cert_chain, key))
}
