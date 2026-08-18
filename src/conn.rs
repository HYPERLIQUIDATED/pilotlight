//! A single pre-warmed TLS connection to one sequencer IP.
//!
//! Each connection is owned by a supervisor task that establishes it, waits on
//! the task driving the hyper connection, and re-establishes it with
//! exponential backoff when it goes away. The send path never blocks on a handshake: if a
//! connection is not live, the caller is told immediately and moves on to
//! another endpoint.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;

use crate::config::Config;
use crate::endpoint::EndpointState;
use crate::error::{Error, Result};

/// The multiplexing request handle for an established HTTP/2 connection.
type Sender = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

/// One warm connection.
pub(crate) struct WarmConn {
    /// Which sequencer IP this connection terminates at.
    pub(crate) ip: IpAddr,
    /// A plain mutex, not tokio's: the handle is cloned out and the guard
    /// dropped before anything is awaited, so this is never held across a
    /// suspension point.
    slot: Mutex<Option<Sender>>,
    /// Mirrors `slot.is_some()` so the send path can skip a dead connection
    /// without taking the lock.
    ready: AtomicBool,
    /// Fired whenever this connection becomes usable.
    became_ready: Arc<Notify>,
}

impl WarmConn {
    /// Create a connection in the down state; [`supervise`] brings it up.
    pub(crate) fn new(ip: IpAddr, became_ready: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            ip,
            slot: Mutex::new(None),
            ready: AtomicBool::new(false),
            became_ready,
        })
    }

    /// Whether a request can be issued right now without a handshake.
    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Issue a request on this connection.
    ///
    /// Returns [`Error::Transport`] rather than waiting if the connection is
    /// not currently live — the caller has other endpoints to fall back on and
    /// blocking here would defeat the point of pre-warming.
    pub(crate) async fn send(&self, req: Request<Full<Bytes>>) -> Result<Response<Incoming>> {
        // HTTP/2 handles are cheap to clone, so take one and drop the guard
        // immediately; concurrent submissions then multiplex over the same
        // connection instead of queueing behind each other.
        let mut sender = {
            let guard = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
            match guard.as_ref() {
                Some(sender) => sender.clone(),
                None => return Err(self.transport_err("connection is not established")),
            }
        };

        sender
            .ready()
            .await
            .map_err(|e| self.transport_err(format!("stream not ready: {e}")))?;
        sender
            .send_request(req)
            .await
            .map_err(|e| self.transport_err(format!("send failed: {e}")))
    }

    /// Tag a failure with the endpoint it happened on.
    fn transport_err(&self, message: impl Into<String>) -> Error {
        Error::Transport {
            ip: self.ip,
            message: message.into(),
        }
    }

    /// Stop the send path from choosing this connection.
    fn mark_down(&self) {
        self.ready.store(false, Ordering::Release);
    }
}

/// Keep `conn` established forever, reconnecting with exponential backoff.
///
/// Runs until the task is aborted, which happens when the endpoint is retired
/// or the client is dropped.
pub(crate) async fn supervise(
    conn: Arc<WarmConn>,
    state: Arc<EndpointState>,
    cfg: Arc<Config>,
    tls: Arc<ClientConfig>,
) {
    let mut backoff = cfg.reconnect_min_backoff;

    loop {
        match establish(conn.ip, &cfg, &tls).await {
            Ok((sender, driver)) => {
                backoff = cfg.reconnect_min_backoff;

                *conn.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(sender);
                conn.ready.store(true, Ordering::Release);
                conn.became_ready.notify_waiters();

                tracing::debug!(ip = %conn.ip, "connection established");

                // Resolves when the peer closes, sends GOAWAY, or the socket
                // breaks. Envoy recycles connections on its own schedule, so
                // this is a routine event rather than an error.
                let reason = driver.await;

                conn.mark_down();
                *conn.slot.lock().unwrap_or_else(PoisonError::into_inner) = None;

                // A graceful close is the peer recycling on its own schedule
                // and says nothing about the endpoint's health. The other two
                // are genuine failures of a connection that had been working,
                // and without recording them an endpoint whose connections
                // keep breaking and reconnecting reports no failures at all.
                match reason {
                    Ok(ClosedReason::Graceful) => tracing::debug!(
                        ip = %conn.ip,
                        "peer closed the connection (GOAWAY or idle reap), reconnecting"
                    ),
                    Ok(ClosedReason::Error(e)) => {
                        tracing::debug!(
                            ip = %conn.ip, error = %e, "connection failed, reconnecting"
                        );
                        state.record_failure(&Error::Transport {
                            ip: conn.ip,
                            message: format!("established connection failed: {e}"),
                        });
                    }
                    Err(e) => {
                        tracing::debug!(
                            ip = %conn.ip, error = %e, "connection driver task ended, reconnecting"
                        );
                        state.record_failure(&Error::Transport {
                            ip: conn.ip,
                            message: format!("connection ended unexpectedly: {e}"),
                        });
                    }
                }
            }
            Err(e) => {
                conn.mark_down();
                tracing::warn!(ip = %conn.ip, error = %e, "connection attempt failed");
                state.record_failure(&e);
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = next_backoff(backoff, cfg.reconnect_max_backoff);
    }
}

/// Double the reconnect delay, clamped to the configured ceiling.
///
/// Saturating rather than `*`, which panics on overflow: [`Config`] is public,
/// so the starting delay is whatever the caller set.
fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

/// Reason a connection ended, for logging.
#[derive(Debug)]
pub(crate) enum ClosedReason {
    /// Clean shutdown (typically a GOAWAY from the load balancer).
    Graceful,
    /// The connection failed.
    Error(String),
}

/// Task that polls the hyper connection future for its whole lifetime.
///
/// HTTP/2 needs the connection driven independently of any request in flight,
/// since PING frames, flow control and GOAWAY all arrive out of band.
type Driver = tokio::task::JoinHandle<ClosedReason>;

/// Open one TCP + TLS + HTTP connection and spawn its driver task.
async fn establish(ip: IpAddr, cfg: &Config, tls: &Arc<ClientConfig>) -> Result<(Sender, Driver)> {
    let addr = SocketAddr::new(ip, cfg.port);

    let tcp = tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Transport {
            ip,
            message: format!("TCP connect timed out after {:?}", cfg.connect_timeout),
        })?
        .map_err(|e| Error::Transport {
            ip,
            message: format!("TCP connect failed: {e}"),
        })?;

    // Nagle would hold a small JSON body waiting for more data. On a path where
    // the sequencer itself answers in under a millisecond, that delay would be
    // most of the latency budget.
    tcp.set_nodelay(true).map_err(|e| Error::Transport {
        ip,
        message: format!("failed to set TCP_NODELAY: {e}"),
    })?;

    // The socket is opened to a resolved address, but SNI and certificate
    // validation use the hostname, so each endpoint is verified against the
    // sequencer's certificate rather than its IP.
    let server_name = ServerName::try_from(cfg.host.clone()).map_err(|e| {
        Error::Config(format!(
            "`{}` is not a valid TLS server name: {e}",
            cfg.host
        ))
    })?;

    let tls_stream = tokio::time::timeout(
        cfg.connect_timeout,
        TlsConnector::from(tls.clone()).connect(server_name, tcp),
    )
    .await
    .map_err(|_| Error::Transport {
        ip,
        message: format!("TLS handshake timed out after {:?}", cfg.connect_timeout),
    })?
    .map_err(|e| Error::Transport {
        ip,
        message: format!("TLS handshake failed: {e}"),
    })?;

    // HTTP/2 is required for its multiplexing: an HTTP/1.1 connection carries
    // one request at a time, which would serialise concurrent submissions. A
    // peer that will not negotiate h2 is reported as a connect error rather
    // than silently downgraded.
    let alpn = tls_stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    if alpn.as_deref() != Some(b"h2") {
        let negotiated = alpn.as_deref().map_or_else(
            || "none".to_owned(),
            |p| String::from_utf8_lossy(p).into_owned(),
        );
        return Err(Error::Transport {
            ip,
            message: format!(
                "peer did not negotiate HTTP/2 over ALPN (got: {negotiated}); \
                 this client speaks HTTP/2 only"
            ),
        });
    }

    let io = TokioIo::new(tls_stream);
    let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        // hyper has no ambient runtime, so PING scheduling needs a timer handed
        // to it explicitly; without one it panics on first use.
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(cfg.h2_ping_interval))
        .keep_alive_timeout(cfg.h2_ping_timeout)
        // Idle is the normal state for a pre-warmed connection, so PINGs have
        // to continue when nothing is in flight; otherwise the keepalive would
        // only run exactly when it is not needed.
        .keep_alive_while_idle(true)
        .adaptive_window(true)
        .handshake(io)
        .await
        .map_err(|e| Error::Transport {
            ip,
            message: format!("HTTP/2 handshake failed: {e}"),
        })?;

    let driver = tokio::spawn(async move {
        match connection.await {
            Ok(()) => ClosedReason::Graceful,
            Err(e) => ClosedReason::Error(e.to_string()),
        }
    });
    Ok((sender, driver))
}
