//! One sequencer IP: its warm connections, health, and latency score.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::LengthLimitError;
use http_body_util::{BodyExt, Full, Limited};
use rustls::ClientConfig;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::conn::{WarmConn, supervise};
use crate::error::{Error, Result};
use crate::request::RequestTemplate;
use crate::rpc;
use crate::types::EndpointStats;

/// Ceiling on a response body, enforced while reading rather than after.
///
/// Sequencer replies run to a few hundred bytes; anything approaching this is a
/// misrouted request or an error page from something in the path.
const MAX_BODY: usize = 64 * 1024;

/// Shift that weights the latency EWMA: new = old - old/8 + sample/8.
const EWMA_SHIFT: u64 = 3;

/// Health counters, shared with the background probe task.
///
/// Kept separate from [`Endpoint`] so the probe task holds no strong reference
/// back to the endpoint that owns its `JoinHandle`, which would leak the task.
pub(crate) struct EndpointState {
    /// Smoothed round-trip latency in microseconds; 0 means "no sample yet".
    ewma_us: AtomicU64,
    /// Failures since the last success; reset by [`EndpointState::record_success`].
    consecutive_failures: AtomicU32,
    /// Why the most recent failure happened.
    ///
    /// A plain mutex: written on failure, read only by [`Endpoint::stats`], and
    /// never held across an await.
    last_failure: Mutex<Option<String>>,
}

impl EndpointState {
    /// Start with no latency sample and a clean failure count.
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ewma_us: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            last_failure: Mutex::new(None),
        })
    }

    /// Fold a completed round trip into the EWMA and clear the failure count.
    pub(crate) fn record_success(&self, latency: Duration) {
        // Saturating rather than casting: a latency past 584 000 years is not
        // worth recording precisely, but wrapping it to a small value would
        // silently promote the endpoint to the front of the ranking.
        let sample = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        // Relaxed throughout: these are advisory ranking hints, and a lost
        // update costs at most one slightly stale sort key.
        let prev = self.ewma_us.load(Ordering::Relaxed);
        let next = if prev == 0 {
            sample
        } else {
            prev - (prev >> EWMA_SHIFT) + (sample >> EWMA_SHIFT)
        };
        self.ewma_us.store(next, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self
            .last_failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Count a failure and keep its reason, demoting this endpoint in
    /// [`Endpoint::rank`].
    ///
    /// Called for a failed connection attempt, a failed probe, and a failed
    /// submission alike, so an endpoint that has never once connected reports
    /// a rising count rather than looking untouched.
    pub(crate) fn record_failure(&self, error: &Error) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        *self
            .last_failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(error.to_string());
    }

    /// Why the most recent failure happened, if the endpoint is failing.
    fn last_failure(&self) -> Option<String> {
        self.last_failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The smoothed latency, or `None` before the first sample.
    fn ewma(&self) -> Option<Duration> {
        match self.ewma_us.load(Ordering::Relaxed) {
            0 => None,
            us => Some(Duration::from_micros(us)),
        }
    }

    /// Consecutive failures since the last success.
    fn failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Sort key: fewest failures first, then lowest latency.
    fn rank(&self) -> (u32, u64) {
        let ewma = self.ewma_us.load(Ordering::Relaxed);
        // The sentinel is far above any real latency in microseconds, so an
        // endpoint with no sample yet sorts behind every probed one. On a cold
        // pool nothing has a sample, so all endpoints tie and the caller's
        // existing order stands.
        let key = if ewma == 0 { u64::MAX / 2 } else { ewma };
        (self.failures(), key)
    }
}

/// A sequencer endpoint and the pool of warm connections pointing at it.
pub(crate) struct Endpoint {
    /// Address every connection here dials.
    pub(crate) ip: IpAddr,
    /// Warm connections, `conns_per_ip` of them.
    conns: Vec<Arc<WarmConn>>,
    /// Health and latency, shared with the probe tasks.
    state: Arc<EndpointState>,
    /// Round-robin cursor for [`Endpoint::pick_conn`].
    next: AtomicUsize,
    /// Supervisor and probe tasks, aborted when this endpoint is retired.
    tasks: Vec<JoinHandle<()>>,
}

impl Endpoint {
    /// Create the endpoint and start warming its connections immediately.
    pub(crate) fn spawn(
        ip: IpAddr,
        cfg: &Arc<Config>,
        tls: &Arc<ClientConfig>,
        template: &RequestTemplate,
        became_ready: &Arc<Notify>,
    ) -> Arc<Self> {
        let state = EndpointState::new();
        let mut conns = Vec::with_capacity(cfg.conns_per_ip);
        let mut tasks = Vec::with_capacity(cfg.conns_per_ip * 2);

        for _ in 0..cfg.conns_per_ip {
            let conn = WarmConn::new(ip, became_ready.clone());
            tasks.push(tokio::spawn(supervise(
                conn.clone(),
                state.clone(),
                cfg.clone(),
                tls.clone(),
            )));

            if !cfg.probe_interval.is_zero() {
                tasks.push(tokio::spawn(probe_loop(
                    conn.clone(),
                    state.clone(),
                    cfg.clone(),
                    template.clone(),
                )));
            }

            conns.push(conn);
        }

        Arc::new(Self {
            ip,
            conns,
            state,
            next: AtomicUsize::new(0),
            tasks,
        })
    }

    /// A connection that can take a request right now, round-robin.
    pub(crate) fn pick_conn(&self) -> Option<Arc<WarmConn>> {
        let n = self.conns.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        (0..n).find_map(|i| {
            let conn = &self.conns[(start.wrapping_add(i)) % n];
            conn.is_ready().then(|| conn.clone())
        })
    }

    /// Whether any connection here can take a request right now.
    pub(crate) fn is_ready(&self) -> bool {
        self.conns.iter().any(|c| c.is_ready())
    }

    /// Shared health counters, for a caller that wants to record an outcome.
    pub(crate) fn state(&self) -> &Arc<EndpointState> {
        &self.state
    }

    /// Sort key for the fan-out; see [`EndpointState::rank`].
    pub(crate) fn rank(&self) -> (u32, u64) {
        self.state.rank()
    }

    /// Public snapshot of this endpoint's health.
    pub(crate) fn stats(&self) -> EndpointStats {
        EndpointStats {
            ip: self.ip,
            live_conns: self.conns.iter().filter(|c| c.is_ready()).count(),
            total_conns: self.conns.len(),
            ewma_latency: self.state.ewma(),
            consecutive_failures: self.state.failures(),
            last_failure: self.state.last_failure(),
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        // Retiring an endpoint must stop its supervisors, or they would keep
        // reconnecting to an address DNS no longer advertises.
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Send one request on a specific connection and collect the response body.
///
/// # Errors
///
/// [`Error::Timeout`] if either the exchange or the body read exceeds
/// `timeout`, [`Error::HttpStatus`] for a non-200 answer, [`Error::Transport`]
/// if the connection fails mid-read, and [`Error::BadResponse`] for a body that
/// runs past [`MAX_BODY`].
pub(crate) async fn exchange(
    conn: &WarmConn,
    req: Request<Full<Bytes>>,
    timeout: Duration,
) -> Result<Bytes> {
    let response = tokio::time::timeout(timeout, conn.send(req))
        .await
        .map_err(|_| Error::Timeout(timeout))??;

    let status = response.status();

    // Limited enforces the cap while reading. Checking the length afterwards
    // would mean the whole body had already been buffered, which is the cost
    // the cap exists to avoid.
    let body = tokio::time::timeout(
        timeout,
        Limited::new(response.into_body(), MAX_BODY).collect(),
    )
    .await
    .map_err(|_| Error::Timeout(timeout))?
    .map_err(|e| {
        if e.downcast_ref::<LengthLimitError>().is_some() {
            Error::BadResponse {
                ip: conn.ip,
                message: format!("response body exceeded {MAX_BODY} bytes"),
            }
        } else {
            Error::Transport {
                ip: conn.ip,
                message: format!("reading response body failed: {e}"),
            }
        }
    })?
    .to_bytes();

    if status != StatusCode::OK {
        let text = String::from_utf8_lossy(&body[..body.len().min(512)]).into_owned();
        return Err(Error::HttpStatus {
            ip: conn.ip,
            status: status.as_u16(),
            body: text,
        });
    }

    Ok(body)
}

/// Periodically exercise the connection end to end.
///
/// Two jobs in one: keep intermediaries from reaping an idle connection, and
/// keep a fresh latency sample so [`Endpoint::rank`] reflects reality.
async fn probe_loop(
    conn: Arc<WarmConn>,
    state: Arc<EndpointState>,
    cfg: Arc<Config>,
    template: RequestTemplate,
) {
    let body = Bytes::from_static(rpc::PING_BODY);
    let mut ticker = tokio::time::interval(cfg.probe_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        if !conn.is_ready() {
            continue;
        }

        let started = Instant::now();
        match exchange(&conn, template.build(body.clone()), cfg.request_timeout).await {
            Ok(_) => state.record_success(started.elapsed()),
            Err(e) => {
                state.record_failure(&e);
                tracing::debug!(ip = %conn.ip, error = %e, "probe failed");
            }
        }
    }
}
