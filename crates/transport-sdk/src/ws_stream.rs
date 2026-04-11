use std::collections::VecDeque;
use std::fmt::Display;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::ready;
use futures_util::sink::Sink;
use futures_util::stream::Stream;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedWebSocketMessage {
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close,
    Ignore,
}

pub trait WebSocketMessageCodec: Sized {
    fn decode(self) -> io::Result<DecodedWebSocketMessage>;
    fn binary(bytes: Vec<u8>) -> Self;
    fn pong(bytes: Vec<u8>) -> Self;
}

#[derive(Debug)]
pub struct WebSocketByteStream<S, M> {
    socket: S,
    read_buffer: Vec<u8>,
    read_offset: usize,
    pending_control: VecDeque<M>,
    pending_send: Option<M>,
    seen_eof: bool,
}

impl<S, M> WebSocketByteStream<S, M> {
    pub fn new(socket: S) -> Self {
        Self {
            socket,
            read_buffer: Vec::new(),
            read_offset: 0,
            pending_control: VecDeque::new(),
            pending_send: None,
            seen_eof: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.socket
    }

    fn enqueue_control(&mut self, message: M) {
        if self.pending_send.is_none() {
            self.pending_send = Some(message);
        } else {
            self.pending_control.push_back(message);
        }
    }

    fn drain_read_buffer(&mut self, out: &mut [u8]) -> usize {
        if out.is_empty() || self.read_offset >= self.read_buffer.len() {
            return 0;
        }

        let available = &self.read_buffer[self.read_offset..];
        let count = available.len().min(out.len());
        out[..count].copy_from_slice(&available[..count]);
        self.read_offset += count;

        if self.read_offset >= self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_offset = 0;
        }

        count
    }

    fn map_socket_error<E>(err: E) -> io::Error
    where
        E: Display,
    {
        io::Error::other(err.to_string())
    }
}

impl<S, M, E> WebSocketByteStream<S, M>
where
    S: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin,
    M: WebSocketMessageCodec,
    E: Display,
{
    fn poll_drain_control_queue(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.pending_send.is_none() {
                self.pending_send = self.pending_control.pop_front();
            }

            let Some(message) = self.pending_send.take() else {
                return Poll::Ready(Ok(()));
            };

            ready!(
                Pin::new(&mut self.socket)
                    .poll_ready(cx)
                    .map_err(Self::map_socket_error)
            )?;
            Pin::new(&mut self.socket)
                .start_send(message)
                .map_err(Self::map_socket_error)?;
        }
    }
}

impl<S, M, E> futures_util::io::AsyncRead for WebSocketByteStream<S, M>
where
    S: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin,
    M: WebSocketMessageCodec + Unpin,
    E: Display,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let buffered = this.drain_read_buffer(out);
        if buffered > 0 {
            return Poll::Ready(Ok(buffered));
        }
        if this.seen_eof {
            return Poll::Ready(Ok(0));
        }

        loop {
            ready!(this.poll_drain_control_queue(cx))?;

            let next = match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(next) => next.map_err(Self::map_socket_error)?,
                None => {
                    this.seen_eof = true;
                    return Poll::Ready(Ok(0));
                }
            };

            match next.decode()? {
                DecodedWebSocketMessage::Binary(bytes) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    this.read_buffer = bytes;
                    this.read_offset = 0;
                    let count = this.drain_read_buffer(out);
                    return Poll::Ready(Ok(count));
                }
                DecodedWebSocketMessage::Ping(payload) => {
                    this.enqueue_control(M::pong(payload));
                }
                DecodedWebSocketMessage::Pong | DecodedWebSocketMessage::Ignore => {}
                DecodedWebSocketMessage::Close => {
                    this.seen_eof = true;
                    return Poll::Ready(Ok(0));
                }
            }
        }
    }
}

impl<S, M, E> futures_util::io::AsyncWrite for WebSocketByteStream<S, M>
where
    S: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin,
    M: WebSocketMessageCodec + Unpin,
    E: Display,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        ready!(this.poll_drain_control_queue(cx))?;
        ready!(
            Pin::new(&mut this.socket)
                .poll_ready(cx)
                .map_err(Self::map_socket_error)
        )?;
        Pin::new(&mut this.socket)
            .start_send(M::binary(buf.to_vec()))
            .map_err(Self::map_socket_error)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_control_queue(cx))?;
        Pin::new(&mut this.socket)
            .poll_flush(cx)
            .map_err(Self::map_socket_error)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_control_queue(cx))?;
        Pin::new(&mut this.socket)
            .poll_close(cx)
            .map_err(Self::map_socket_error)
    }
}

impl WebSocketMessageCodec for Message {
    fn decode(self) -> io::Result<DecodedWebSocketMessage> {
        Ok(match self {
            Message::Binary(bytes) => DecodedWebSocketMessage::Binary(bytes.to_vec()),
            Message::Ping(payload) => DecodedWebSocketMessage::Ping(payload.to_vec()),
            Message::Pong(_) => DecodedWebSocketMessage::Pong,
            Message::Close(_) => DecodedWebSocketMessage::Close,
            Message::Text(_) | Message::Frame(_) => DecodedWebSocketMessage::Ignore,
        })
    }

    fn binary(bytes: Vec<u8>) -> Self {
        Message::Binary(bytes)
    }

    fn pong(bytes: Vec<u8>) -> Self {
        Message::Pong(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TestWsMessage {
        Binary(Vec<u8>),
        Ping(Vec<u8>),
        Pong(Vec<u8>),
        Close,
    }

    impl WebSocketMessageCodec for TestWsMessage {
        fn decode(self) -> io::Result<DecodedWebSocketMessage> {
            Ok(match self {
                Self::Binary(bytes) => DecodedWebSocketMessage::Binary(bytes),
                Self::Ping(payload) => DecodedWebSocketMessage::Ping(payload),
                Self::Pong(_) => DecodedWebSocketMessage::Pong,
                Self::Close => DecodedWebSocketMessage::Close,
            })
        }

        fn binary(bytes: Vec<u8>) -> Self {
            Self::Binary(bytes)
        }

        fn pong(bytes: Vec<u8>) -> Self {
            Self::Pong(bytes)
        }
    }

    #[derive(Debug, Clone)]
    struct TestSocketError;

    impl Display for TestSocketError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("test socket error")
        }
    }

    struct TestSocket {
        state: Arc<Mutex<TestSocketState>>,
    }

    #[derive(Default)]
    struct TestSocketState {
        inbound: VecDeque<Result<TestWsMessage, TestSocketError>>,
        sent: Vec<TestWsMessage>,
        closed: bool,
    }

    impl TestSocket {
        fn new(
            inbound: impl IntoIterator<Item = TestWsMessage>,
        ) -> (Self, Arc<Mutex<TestSocketState>>) {
            let state = Arc::new(Mutex::new(TestSocketState {
                inbound: inbound.into_iter().map(Ok).collect(),
                sent: Vec::new(),
                closed: false,
            }));
            (
                Self {
                    state: Arc::clone(&state),
                },
                state,
            )
        }
    }

    impl Stream for TestSocket {
        type Item = Result<TestWsMessage, TestSocketError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut state = self.state.lock().expect("state lock should succeed");
            Poll::Ready(state.inbound.pop_front())
        }
    }

    impl Sink<TestWsMessage> for TestSocket {
        type Error = TestSocketError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: TestWsMessage) -> Result<(), Self::Error> {
            let mut state = self.state.lock().expect("state lock should succeed");
            state.sent.push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let mut state = self.state.lock().expect("state lock should succeed");
            state.closed = true;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn websocket_byte_stream_reads_binary_messages_and_replies_to_ping() {
        let (socket, state) = TestSocket::new([
            TestWsMessage::Ping(b"pong-me".to_vec()),
            TestWsMessage::Binary(b"hello".to_vec()),
            TestWsMessage::Close,
        ]);
        let mut stream = WebSocketByteStream::new(socket);

        let mut buf = [0u8; 5];
        let read = stream
            .read(&mut buf)
            .await
            .expect("binary payload should be readable");
        assert_eq!(read, 5);
        assert_eq!(&buf, b"hello");

        stream.flush().await.expect("flush should succeed");

        let state = state.lock().expect("state lock should succeed");
        assert_eq!(state.sent, vec![TestWsMessage::Pong(b"pong-me".to_vec())]);
    }

    #[tokio::test]
    async fn websocket_byte_stream_writes_binary_frames_and_closes() {
        let (socket, state) = TestSocket::new([]);
        let mut stream = WebSocketByteStream::new(socket);

        stream
            .write_all(b"payload")
            .await
            .expect("write should succeed");
        stream.close().await.expect("close should succeed");

        let state = state.lock().expect("state lock should succeed");
        assert_eq!(state.sent, vec![TestWsMessage::Binary(b"payload".to_vec())]);
        assert!(state.closed);
    }
}
