use anyhow::{Context, Result, bail};
use futures_util::future::poll_fn;
use futures_util::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

const MIN_YAMUX_STREAM_WINDOW_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiplexMode {
    Client,
    Server,
}

#[derive(Debug, Clone)]
pub struct MultiplexConfig {
    pub max_connection_receive_window: Option<usize>,
    pub max_num_streams: usize,
    pub read_after_close: bool,
    pub split_send_size: usize,
    pub inbound_stream_buffer: usize,
}

pub struct MultiplexedSession {
    command_tx: mpsc::Sender<SessionCommand>,
    inbound: mpsc::Receiver<Result<yamux::Stream>>,
    driver: Option<tokio::task::JoinHandle<Result<()>>>,
}

enum SessionCommand {
    OpenStream {
        response_tx: oneshot::Sender<Result<yamux::Stream>>,
    },
    Close {
        response_tx: oneshot::Sender<Result<()>>,
    },
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            max_connection_receive_window: Some(16 * 1024 * 1024),
            max_num_streams: 64,
            read_after_close: true,
            split_send_size: 16 * 1024,
            inbound_stream_buffer: 32,
        }
    }
}

impl MultiplexConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_num_streams == 0 {
            bail!("multiplex config max_num_streams must be greater than zero");
        }
        if self.split_send_size == 0 {
            bail!("multiplex config split_send_size must be greater than zero");
        }
        if let Some(limit) = self.max_connection_receive_window {
            let minimum = self.max_num_streams * MIN_YAMUX_STREAM_WINDOW_BYTES;
            if limit < minimum {
                bail!(
                    "multiplex config max_connection_receive_window must be at least {} bytes",
                    minimum
                );
            }
        }
        Ok(())
    }

    fn to_yamux_config(&self) -> yamux::Config {
        let mut config = yamux::Config::default();
        config.set_max_num_streams(self.max_num_streams);
        config.set_max_connection_receive_window(self.max_connection_receive_window);
        config.set_read_after_close(self.read_after_close);
        config.set_split_send_size(self.split_send_size);
        config
    }
}

impl MultiplexMode {
    fn into_yamux(self) -> yamux::Mode {
        match self {
            Self::Client => yamux::Mode::Client,
            Self::Server => yamux::Mode::Server,
        }
    }
}

impl MultiplexedSession {
    pub fn spawn<T>(io: T, mode: MultiplexMode, config: MultiplexConfig) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        config.validate()?;

        let mut connection =
            yamux::Connection::new(io, config.to_yamux_config(), mode.into_yamux());
        let (command_tx, mut command_rx) = mpsc::channel(config.inbound_stream_buffer.max(1));
        let (inbound_tx, inbound_rx) = mpsc::channel(config.inbound_stream_buffer.max(1));

        let driver = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(command) = command_rx.recv() => {
                        match command {
                            SessionCommand::OpenStream { response_tx } => {
                                let result = poll_fn(|cx| connection.poll_new_outbound(cx))
                                    .await
                                    .map_err(|err| anyhow::anyhow!("failed opening yamux outbound stream: {err}"));
                                let _ = response_tx.send(result);
                            }
                            SessionCommand::Close { response_tx } => {
                                let result = poll_fn(|cx| connection.poll_close(cx))
                                    .await
                                    .map_err(|err| anyhow::anyhow!("failed closing yamux connection: {err}"));
                                let _ = response_tx.send(result);
                                return Ok(());
                            }
                        }
                    }
                    inbound = poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                        match inbound {
                            Some(Ok(stream)) => {
                                if inbound_tx.send(Ok(stream)).await.is_err() {
                                    return Ok(());
                                }
                            }
                            Some(Err(err)) => {
                                let error = anyhow::anyhow!("yamux connection failed: {err}");
                                let _ = inbound_tx
                                    .send(Err(anyhow::anyhow!(error.to_string())))
                                    .await;
                                return Err(error);
                            }
                            None => return Ok(()),
                        }
                    }
                }
            }
        });

        Ok(Self {
            command_tx,
            inbound: inbound_rx,
            driver: Some(driver),
        })
    }

    pub async fn open_stream(&self) -> Result<yamux::Stream> {
        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .send(SessionCommand::OpenStream { response_tx })
            .await
            .context("failed sending multiplexed outbound stream request to driver")?;
        response_rx
            .await
            .context("multiplexed outbound stream response channel closed")?
    }

    pub async fn accept_stream(&mut self) -> Result<Option<yamux::Stream>> {
        match self.inbound.recv().await {
            Some(Ok(stream)) => Ok(Some(stream)),
            Some(Err(err)) => Err(err.context("multiplexed inbound stream driver failed")),
            None => {
                self.await_driver().await?;
                Ok(None)
            }
        }
    }

    pub async fn close(mut self) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        if self
            .command_tx
            .send(SessionCommand::Close { response_tx })
            .await
            .is_ok()
        {
            response_rx
                .await
                .context("multiplexed close response channel closed")??;
        }
        self.await_driver().await
    }

    async fn await_driver(&mut self) -> Result<()> {
        let Some(driver) = self.driver.take() else {
            return Ok(());
        };

        match driver.await {
            Ok(result) => result,
            Err(err) => Err(anyhow::anyhow!(
                "multiplexed session driver join failed: {err}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::io::duplex;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[tokio::test]
    async fn multiplexed_session_supports_multiple_logical_streams() {
        let (left, right) = duplex(64 * 1024);
        let client =
            MultiplexedSession::spawn(left.compat(), MultiplexMode::Client, Default::default())
                .expect("client session should spawn");
        let mut server =
            MultiplexedSession::spawn(right.compat(), MultiplexMode::Server, Default::default())
                .expect("server session should spawn");

        let mut outbound_one = client
            .open_stream()
            .await
            .expect("first outbound stream should open");
        let mut outbound_two = client
            .open_stream()
            .await
            .expect("second outbound stream should open");

        outbound_one
            .write_all(b"hello")
            .await
            .expect("first stream write should succeed");
        outbound_two
            .write_all(b"world")
            .await
            .expect("second stream write should succeed");
        outbound_one
            .close()
            .await
            .expect("first stream should close");
        outbound_two
            .close()
            .await
            .expect("second stream should close");

        let mut inbound_one = server
            .accept_stream()
            .await
            .expect("accepting first stream should succeed")
            .expect("first stream should be present");
        let mut inbound_two = server
            .accept_stream()
            .await
            .expect("accepting second stream should succeed")
            .expect("second stream should be present");

        let mut first = Vec::new();
        inbound_one
            .read_to_end(&mut first)
            .await
            .expect("first inbound stream should read");
        let mut second = Vec::new();
        inbound_two
            .read_to_end(&mut second)
            .await
            .expect("second inbound stream should read");

        assert_eq!(first, b"hello");
        assert_eq!(second, b"world");

        client.close().await.expect("client session should close");
        server.close().await.expect("server session should close");
    }

    #[test]
    fn multiplex_config_rejects_too_small_receive_windows() {
        let error = MultiplexConfig {
            max_connection_receive_window: Some(1024),
            ..Default::default()
        }
        .validate()
        .expect_err("config should reject too-small receive windows");

        assert!(error.to_string().contains("max_connection_receive_window"));
    }
}
