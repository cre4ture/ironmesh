use anyhow::{Context, Result, anyhow, bail};
use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::mux::MultiplexedSession;
use crate::transport_protocol::{
    TRANSPORT_PROTOCOL_VERSION, TransportHeader, TransportSessionControlMessage,
    TransportStreamControlMessage, TransportStreamKind,
};

const MAX_CONTROL_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BufferedTransportRequest {
    pub request_id: String,
    pub kind: TransportStreamKind,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Vec<TransportHeader>,
    #[serde(default)]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BufferedTransportResponse {
    pub request_id: String,
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<TransportHeader>,
    #[serde(default)]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportRequestHead {
    pub request_id: String,
    pub kind: TransportStreamKind,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Vec<TransportHeader>,
    #[serde(default)]
    pub end_of_stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportResponseHead {
    pub request_id: String,
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<TransportHeader>,
}

impl BufferedTransportRequest {
    pub fn new(
        kind: TransportStreamKind,
        method: impl Into<String>,
        path: impl Into<String>,
        headers: Vec<TransportHeader>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            request_id: Uuid::now_v7().to_string(),
            kind,
            method: method.into(),
            path: path.into(),
            headers,
            body,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.request_head().validate()
    }

    fn request_head(&self) -> TransportRequestHead {
        TransportRequestHead {
            request_id: self.request_id.clone(),
            kind: self.kind,
            method: self.method.clone(),
            path: self.path.clone(),
            headers: self.headers.clone(),
            end_of_stream: self.body.is_empty(),
        }
    }
}

impl BufferedTransportResponse {
    pub fn validate(&self) -> Result<()> {
        self.response_head().validate()
    }

    fn response_head(&self) -> TransportResponseHead {
        TransportResponseHead {
            request_id: self.request_id.clone(),
            status: self.status,
            headers: self.headers.clone(),
        }
    }
}

impl TransportRequestHead {
    pub fn validate(&self) -> Result<()> {
        self.clone().into_control_message().validate()
    }

    fn into_control_message(self) -> TransportStreamControlMessage {
        TransportStreamControlMessage::RequestHead {
            request_id: self.request_id,
            kind: self.kind,
            method: self.method,
            path: self.path,
            headers: self.headers,
            end_of_stream: self.end_of_stream,
        }
    }

    fn from_control_message(message: TransportStreamControlMessage) -> Result<Self> {
        let TransportStreamControlMessage::RequestHead {
            request_id,
            kind,
            method,
            path,
            headers,
            end_of_stream,
        } = message
        else {
            bail!("transport stream did not begin with a request head");
        };
        let head = Self {
            request_id,
            kind,
            method,
            path,
            headers,
            end_of_stream,
        };
        head.validate()?;
        Ok(head)
    }
}

impl TransportResponseHead {
    pub fn validate(&self) -> Result<()> {
        self.clone().into_control_message().validate()
    }

    fn into_control_message(self) -> TransportStreamControlMessage {
        TransportStreamControlMessage::ResponseHead {
            request_id: self.request_id,
            status: self.status,
            headers: self.headers,
        }
    }

    fn from_control_message(message: TransportStreamControlMessage) -> Result<Self> {
        let TransportStreamControlMessage::ResponseHead {
            request_id,
            status,
            headers,
        } = message
        else {
            bail!("transport stream did not begin with a response head");
        };
        let head = Self {
            request_id,
            status,
            headers,
        };
        head.validate()?;
        Ok(head)
    }
}

pub async fn perform_transport_client_handshake(
    session: &MultiplexedSession,
    hello: TransportSessionControlMessage,
) -> Result<TransportSessionControlMessage> {
    match &hello {
        TransportSessionControlMessage::Hello {
            protocol_version, ..
        } if *protocol_version == TRANSPORT_PROTOCOL_VERSION => {}
        TransportSessionControlMessage::Hello { .. } => {
            bail!("transport client handshake must use the current protocol version");
        }
        _ => bail!("transport client handshake expects a hello message"),
    }
    hello.validate()?;

    let mut stream = session
        .open_stream()
        .await
        .context("failed opening transport control stream")?;
    write_json_frame(&mut stream, &hello)
        .await
        .context("failed writing transport hello")?;
    let ready = read_json_frame::<_, TransportSessionControlMessage>(&mut stream)
        .await
        .context("failed reading transport ready")?;
    match &ready {
        TransportSessionControlMessage::Ready {
            protocol_version, ..
        } if *protocol_version == TRANSPORT_PROTOCOL_VERSION => {}
        TransportSessionControlMessage::Ready { .. } => {
            bail!("transport ready used an unsupported protocol version");
        }
        TransportSessionControlMessage::Error { message } => {
            bail!("transport session rejected during handshake: {message}");
        }
        _ => bail!("transport control stream returned an unexpected handshake message"),
    }
    ready.validate()?;
    stream
        .close()
        .await
        .context("failed closing transport control stream after client handshake")?;
    Ok(ready)
}

pub async fn perform_transport_server_handshake(
    session: &mut MultiplexedSession,
    ready: TransportSessionControlMessage,
) -> Result<TransportSessionControlMessage> {
    match &ready {
        TransportSessionControlMessage::Ready {
            protocol_version, ..
        } if *protocol_version == TRANSPORT_PROTOCOL_VERSION => {}
        TransportSessionControlMessage::Ready { .. } => {
            bail!("transport server handshake must use the current protocol version");
        }
        _ => bail!("transport server handshake expects a ready message"),
    }
    ready.validate()?;

    let mut stream = session
        .accept_stream()
        .await
        .context("failed accepting transport control stream")?
        .ok_or_else(|| anyhow!("transport session closed before handshake"))?;
    let hello = read_json_frame::<_, TransportSessionControlMessage>(&mut stream)
        .await
        .context("failed reading transport hello")?;
    match &hello {
        TransportSessionControlMessage::Hello {
            protocol_version, ..
        } if *protocol_version == TRANSPORT_PROTOCOL_VERSION => {}
        TransportSessionControlMessage::Hello { .. } => {
            bail!("transport hello used an unsupported protocol version");
        }
        _ => bail!("transport control stream did not start with a hello message"),
    }
    hello.validate()?;
    write_json_frame(&mut stream, &ready)
        .await
        .context("failed writing transport ready")?;
    stream
        .close()
        .await
        .context("failed closing transport control stream after server handshake")?;
    Ok(hello)
}

pub async fn write_buffered_transport_request<W>(
    writer: &mut W,
    request: &BufferedTransportRequest,
) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    write_transport_request_head(writer, &request.request_head())
        .await
        .context("failed writing buffered transport request head")?;
    if !request.body.is_empty() {
        writer
            .write_all(&request.body)
            .await
            .context("failed writing buffered transport request body")?;
    }
    writer
        .close()
        .await
        .context("failed closing buffered transport request stream")
}

pub async fn read_buffered_transport_request<R>(reader: &mut R) -> Result<BufferedTransportRequest>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_transport_request_head(reader)
        .await
        .context("failed reading buffered transport request head")?;

    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .await
        .context("failed reading buffered transport request body")?;
    let request = BufferedTransportRequest {
        request_id: head.request_id,
        kind: head.kind,
        method: head.method,
        path: head.path,
        headers: head.headers,
        body,
    };
    request.validate()?;
    Ok(request)
}

pub async fn write_buffered_transport_response<W>(
    writer: &mut W,
    response: &BufferedTransportResponse,
) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    write_transport_response_head(writer, &response.response_head())
        .await
        .context("failed writing buffered transport response head")?;
    if !response.body.is_empty() {
        writer
            .write_all(&response.body)
            .await
            .context("failed writing buffered transport response body")?;
    }
    writer
        .close()
        .await
        .context("failed closing buffered transport response stream")
}

pub async fn read_buffered_transport_response<R>(
    reader: &mut R,
) -> Result<BufferedTransportResponse>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_transport_response_head(reader)
        .await
        .context("failed reading buffered transport response head")?;

    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .await
        .context("failed reading buffered transport response body")?;
    let response = BufferedTransportResponse {
        request_id: head.request_id,
        status: head.status,
        headers: head.headers,
        body,
    };
    response.validate()?;
    Ok(response)
}

pub async fn write_transport_request_head<W>(
    writer: &mut W,
    head: &TransportRequestHead,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    head.validate()?;
    write_json_frame(writer, &head.clone().into_control_message()).await
}

pub async fn read_transport_request_head<R>(reader: &mut R) -> Result<TransportRequestHead>
where
    R: AsyncRead + Unpin,
{
    let message = read_json_frame::<_, TransportStreamControlMessage>(reader)
        .await
        .context("failed reading transport request head")?;
    TransportRequestHead::from_control_message(message)
}

pub async fn write_transport_response_head<W>(
    writer: &mut W,
    head: &TransportResponseHead,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    head.validate()?;
    write_json_frame(writer, &head.clone().into_control_message()).await
}

pub async fn read_transport_response_head<R>(reader: &mut R) -> Result<TransportResponseHead>
where
    R: AsyncRead + Unpin,
{
    let message = read_json_frame::<_, TransportStreamControlMessage>(reader)
        .await
        .context("failed reading transport response head")?;
    TransportResponseHead::from_control_message(message)
}

async fn write_json_frame<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let payload =
        serde_json::to_vec(message).context("failed serializing framed transport JSON")?;
    if payload.len() > MAX_CONTROL_MESSAGE_BYTES {
        bail!(
            "framed transport JSON message exceeded {} bytes",
            MAX_CONTROL_MESSAGE_BYTES
        );
    }

    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .context("failed writing framed transport JSON length")?;
    writer
        .write_all(&payload)
        .await
        .context("failed writing framed transport JSON payload")?;
    writer
        .flush()
        .await
        .context("failed flushing framed transport JSON payload")
}

async fn read_json_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut length_bytes = [0u8; 4];
    reader
        .read_exact(&mut length_bytes)
        .await
        .context("failed reading framed transport JSON length")?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_CONTROL_MESSAGE_BYTES {
        bail!(
            "framed transport JSON message exceeded {} bytes",
            MAX_CONTROL_MESSAGE_BYTES
        );
    }

    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .context("failed reading framed transport JSON payload")?;
    serde_json::from_slice(&payload).context("failed decoding framed transport JSON payload")
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;
    use crate::mux::{MultiplexConfig, MultiplexMode};
    use crate::peer::PeerIdentity;
    use crate::transport_protocol::{TransportSessionRole, TransportStreamKind};

    #[tokio::test]
    async fn buffered_transport_request_and_response_round_trip() {
        let (left, right) = duplex(64 * 1024);
        let client =
            MultiplexedSession::spawn(left.compat(), MultiplexMode::Client, Default::default())
                .expect("client session should spawn");
        let mut server =
            MultiplexedSession::spawn(right.compat(), MultiplexMode::Server, Default::default())
                .expect("server session should spawn");

        let server_task = tokio::spawn(async move {
            let hello = perform_transport_server_handshake(
                &mut server,
                TransportSessionControlMessage::Ready {
                    protocol_version: TRANSPORT_PROTOCOL_VERSION,
                    session_id: "server-session".to_string(),
                    max_concurrent_streams: MultiplexConfig::default().max_num_streams,
                },
            )
            .await
            .expect("server handshake should succeed");
            assert!(matches!(
                hello,
                TransportSessionControlMessage::Hello { .. }
            ));

            let mut stream = server
                .accept_stream()
                .await
                .expect("stream accept should succeed")
                .expect("stream should be present");
            let request = read_buffered_transport_request(&mut stream)
                .await
                .expect("request should decode");
            assert_eq!(request.path, "/diagnostics/latency");
            write_buffered_transport_response(
                &mut stream,
                &BufferedTransportResponse {
                    request_id: request.request_id,
                    status: 200,
                    headers: vec![TransportHeader {
                        name: "content-type".to_string(),
                        value: "application/json".to_string(),
                    }],
                    body: br#"{"ok":true}"#.to_vec(),
                },
            )
            .await
            .expect("response should write");
        });

        perform_transport_client_handshake(
            &client,
            TransportSessionControlMessage::Hello {
                protocol_version: TRANSPORT_PROTOCOL_VERSION,
                cluster_id: Uuid::now_v7(),
                role: TransportSessionRole::Client,
                peer: PeerIdentity::Device(Uuid::now_v7()),
                target: Some(PeerIdentity::Node(Uuid::now_v7())),
            },
        )
        .await
        .expect("client handshake should succeed");

        let mut stream = client
            .open_stream()
            .await
            .expect("client stream should open");
        let request = BufferedTransportRequest::new(
            TransportStreamKind::Diagnostics,
            "GET",
            "/diagnostics/latency",
            Vec::new(),
            Vec::new(),
        );
        write_buffered_transport_request(&mut stream, &request)
            .await
            .expect("request should write");
        let response = read_buffered_transport_response(&mut stream)
            .await
            .expect("response should read");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"ok":true}"#);

        server_task.await.expect("server task should join");
        client.close().await.expect("client session should close");
    }

    #[tokio::test]
    async fn buffered_transport_request_body_survives_round_trip() {
        let (left, right) = duplex(16 * 1024);
        let mut left = left.compat();
        let mut right = right.compat();
        let body = b"payload-body".to_vec();
        let request = BufferedTransportRequest::new(
            TransportStreamKind::Rpc,
            "POST",
            "/store/delete",
            vec![TransportHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body.clone(),
        );

        let write_task = tokio::spawn(async move {
            write_buffered_transport_request(&mut left, &request)
                .await
                .expect("request should write");
        });

        let decoded = read_buffered_transport_request(&mut right)
            .await
            .expect("request should decode");
        assert_eq!(decoded.body, body);

        write_task.await.expect("write task should join");
    }
}
