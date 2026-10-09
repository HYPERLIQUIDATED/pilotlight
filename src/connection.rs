use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::client::conn::http2::{Builder, SendRequest};
use hyper::{Request, Uri, header};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{oneshot, watch},
    time::{Instant, sleep, timeout_at},
};
use tokio_rustls::TlsConnector;

use crate::FailureKind;

const RESPONSE_LIMIT: usize = 16 * 1024;

type HttpSender = SendRequest<Full<Bytes>>;
type Driver = Pin<Box<dyn Future<Output = Result<(), hyper::Error>> + Send>>;

#[derive(Clone, Copy)]
pub(crate) struct ConnectionSettings {
    pub connect_timeout: Duration,
    pub reconnect_min_delay: Duration,
    pub reconnect_max_delay: Duration,
    pub initial_deadline: Instant,
    pub reset_stream_capacity: usize,
}

#[derive(Clone)]
pub(crate) enum Transport {
    Http,
    Https(ServerName<'static>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Capacity {
    Unavailable,
    Busy,
    Available { in_flight: usize },
}

#[derive(Clone, Copy)]
pub(crate) struct ConnectionId {
    pub endpoint: usize,
    pub peer: SocketAddr,
    pub slot: usize,
}

pub(crate) struct Connection {
    session: watch::Receiver<Option<Arc<Session>>>,
}

pub(crate) struct Session {
    sender: HttpSender,
    stream_limit: Box<dyn Fn() -> usize + Send + Sync>,
    in_flight: AtomicUsize,
}

pub(crate) struct Reservation(Arc<Session>);

impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Connection {
    pub(crate) fn start(
        transport: Transport,
        id: ConnectionId,
        tls: Arc<ClientConfig>,
        settings: ConnectionSettings,
    ) -> (Self, oneshot::Receiver<Result<(), FailureKind>>) {
        let (sender, session) = watch::channel(None);
        let (initial, ready) = oneshot::channel();
        tokio::spawn(maintain(transport, id, tls, settings, sender, initial));
        (Self { session }, ready)
    }

    pub(crate) fn session(&self) -> Option<Arc<Session>> {
        self.session.borrow().clone()
    }
}

impl Session {
    pub(crate) fn capacity(&self) -> Capacity {
        if self.sender.is_closed() {
            return Capacity::Unavailable;
        }

        let in_flight = self.in_flight.load(Ordering::Relaxed);

        if in_flight < (self.stream_limit)() {
            Capacity::Available { in_flight }
        } else {
            Capacity::Busy
        }
    }

    pub(crate) fn try_reserve(self: Arc<Self>, in_flight: usize) -> Option<Reservation> {
        self.in_flight
            .compare_exchange_weak(
                in_flight,
                in_flight + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .ok()
            .map(|_| Reservation(self))
    }
}

impl Reservation {
    pub(crate) async fn send(
        &self,
        uri: Uri,
        body: Bytes,
        deadline: Instant,
    ) -> Result<Bytes, FailureKind> {
        timeout_at(deadline, send_http(self.0.sender.clone(), uri, body))
            .await
            .unwrap_or(Err(FailureKind::Timeout))
    }
}

pub(crate) fn tls_config() -> Arc<ClientConfig> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("Built-in TLS provider supports default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();

    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

async fn maintain(
    transport: Transport,
    id: ConnectionId,
    tls: Arc<ClientConfig>,
    settings: ConnectionSettings,
    sender: watch::Sender<Option<Arc<Session>>>,
    initial: oneshot::Sender<Result<(), FailureKind>>,
) {
    let reconnect = async {
        let mut initial = Some(initial);
        let mut retry_delay = settings.reconnect_min_delay;

        loop {
            let deadline = if initial.is_some() {
                settings.initial_deadline
            } else {
                Instant::now() + settings.connect_timeout
            };

            let result = timeout_at(
                deadline,
                connect_peer(
                    &transport,
                    id.peer,
                    tls.clone(),
                    settings.reset_stream_capacity,
                ),
            )
            .await
            .unwrap_or(Err(FailureKind::Timeout))
            .map(|(request_sender, driver)| {
                retry_delay = settings.reconnect_min_delay;
                sender.send_replace(Some(request_sender));
                tracing::info!(
                    event = "connection_established",
                    endpoint = id.endpoint,
                    peer = %id.peer,
                    connection = id.slot,
                    "Connection established"
                );
                driver
            });

            if let Some(initial) = initial.take() {
                let _ = initial.send(result.as_ref().map(|_| ()).map_err(|error| *error));
            }

            let phase = if result.is_ok() { "active" } else { "connect" };
            let failure = match result {
                Ok(driver) => {
                    let result = driver.await;
                    sender.send_replace(None);
                    result.err().map(|error| {
                        if error.is_timeout() {
                            FailureKind::Timeout
                        } else {
                            FailureKind::Transport
                        }
                    })
                }
                Err(kind) => Some(kind),
            };

            if let Some(error) = failure {
                tracing::warn!(
                    event = "connection_retry_scheduled",
                    endpoint = id.endpoint,
                    peer = %id.peer,
                    connection = id.slot,
                    phase,
                    ?error,
                    ?retry_delay,
                    "Connection retry scheduled"
                );
            } else {
                tracing::debug!(
                    event = "connection_retry_scheduled",
                    endpoint = id.endpoint,
                    peer = %id.peer,
                    connection = id.slot,
                    reason = "peer_closed",
                    ?retry_delay,
                    "Connection retry scheduled"
                );
            }

            sleep(retry_delay).await;
            retry_delay = retry_delay
                .saturating_mul(2)
                .min(settings.reconnect_max_delay);
        }
    };

    tokio::select! {
        biased;
        () = sender.closed() => {
            tracing::debug!(
                event = "connection_stopped",
                endpoint = id.endpoint,
                peer = %id.peer,
                connection = id.slot,
                "Connection maintenance stopped"
            );
        },
        () = reconnect => {},
    }
}

async fn connect_peer(
    transport: &Transport,
    peer: SocketAddr,
    tls: Arc<ClientConfig>,
    reset_stream_capacity: usize,
) -> Result<(Arc<Session>, Driver), FailureKind> {
    let tcp = TcpStream::connect(peer)
        .await
        .map_err(|_| FailureKind::Transport)?;
    tcp.set_nodelay(true).map_err(|_| FailureKind::Transport)?;

    if let Transport::Https(name) = transport {
        let stream = TlsConnector::from(tls)
            .connect(name.clone(), tcp)
            .await
            .map_err(|_| FailureKind::Tls)?;

        if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(FailureKind::Tls);
        }

        handshake_http2(stream, reset_stream_capacity).await
    } else {
        handshake_http2(tcp, reset_stream_capacity).await
    }
}

async fn handshake_http2<T>(
    stream: T,
    reset_stream_capacity: usize,
) -> Result<(Arc<Session>, Driver), FailureKind>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, mut driver) = Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .initial_max_send_streams(0)
        .max_concurrent_reset_streams(reset_stream_capacity)
        .reset_stream_duration(Duration::from_secs(1))
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| FailureKind::Transport)?;

    let mut settings = tokio::time::interval(Duration::from_millis(1));

    loop {
        tokio::select! {
            _ = &mut driver => return Err(FailureKind::Transport),
            _ = settings.tick() => {
                if driver.current_max_send_streams() > 0 {
                    break;
                }
            }
        }
    }

    // Hyper processes SETTINGS in a separate task; sample its live limit on admission.
    let driver = Arc::new(Mutex::new(driver));
    let capacity = driver.clone();
    let session = Arc::new(Session {
        sender,
        stream_limit: Box::new(move || capacity.lock().unwrap().current_max_send_streams()),
        in_flight: AtomicUsize::new(0),
    });
    let driver = poll_fn(move |cx| Pin::new(&mut *driver.lock().unwrap()).poll(cx));

    Ok((session, Box::pin(driver)))
}

async fn send_http(mut sender: HttpSender, uri: Uri, body: Bytes) -> Result<Bytes, FailureKind> {
    let mut request = Request::new(Full::new(body));
    *request.method_mut() = hyper::Method::POST;
    *request.uri_mut() = uri;
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );

    let response = sender
        .send_request(request)
        .await
        .map_err(|_| FailureKind::Transport)?;

    if !response.status().is_success() {
        return Err(FailureKind::Http(response.status().as_u16()));
    }

    let body = Limited::new(response.into_body(), RESPONSE_LIMIT)
        .collect()
        .await
        .map_err(|error| {
            if error.is::<LengthLimitError>() {
                FailureKind::ResponseTooLarge
            } else {
                FailureKind::Transport
            }
        })?
        .to_bytes();

    Ok(body)
}
