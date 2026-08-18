//! The public client.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::endpoint::{Endpoint, exchange};
use crate::error::{Error, Result};
use crate::pool::{Pool, dns_refresh_loop};
use crate::request::RequestTemplate;
use crate::rpc::{self, ConditionalOptions};
use crate::tls;
use crate::types::{EndpointStats, Submission, TxHash};

/// A client that holds warm connections to every sequencer endpoint and
/// submits pre-signed transactions across them.
///
/// Cloning is cheap and shares all connections, so build one per process and
/// clone it wherever it is needed. Dropping the last clone aborts the
/// background supervisor, probe and DNS tasks and closes every connection.
#[derive(Clone)]
pub struct SequencerClient {
    inner: Arc<Inner>,
}

/// Shared behind an `Arc`, so every clone of the client sees one pool.
struct Inner {
    /// Settings the client was built with.
    cfg: Arc<Config>,
    /// Request skeleton, cloned per submission.
    template: RequestTemplate,
    /// Endpoints and their warm connections.
    pool: Arc<Pool>,
    /// Background DNS refresher; `None` when the interval is zero.
    dns_task: Option<JoinHandle<()>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(task) = &self.dns_task {
            task.abort();
        }
    }
}

impl SequencerClient {
    /// Connect to the Robinhood mainnet sequencer with default settings and
    /// wait until at least one connection is warm.
    ///
    /// ```no_run
    /// # async fn f() -> Result<(), pilotlight::Error> {
    /// let client = pilotlight::SequencerClient::connect().await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Dns`] if the sequencer hostname cannot be resolved, or
    /// [`Error::Timeout`] if no connection finishes its handshake in time.
    pub async fn connect() -> Result<Self> {
        Self::builder().connect().await
    }

    /// Start configuring a client.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            cfg: Config::default(),
        }
    }

    /// Block until at least one endpoint has a live connection.
    ///
    /// Sending before this returns is allowed but will fail with
    /// [`Error::NotReady`] while the first handshake is still in flight.
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] if no endpoint has a live connection within
    /// `timeout`. The client keeps trying to connect regardless.
    pub async fn wait_until_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;

        loop {
            // Arm the notification *before* checking, so a connection that
            // comes up in between cannot be missed.
            let notified = self.inner.pool.became_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if self.inner.pool.snapshot().iter().any(|e| e.is_ready()) {
                return Ok(());
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout(timeout));
            }
            if tokio::time::timeout(remaining, notified).await.is_err() {
                return Err(Error::Timeout(timeout));
            }
        }
    }

    /// Submit a signed, RLP/EIP-2718 encoded transaction.
    ///
    /// The transaction is broadcast to [`fanout`](ClientBuilder::fanout)
    /// endpoints at once and the first success wins. The sequencer orders
    /// transactions synchronously, so the copies that lose the race are
    /// answered `nonce too low` against the state the winner just advanced.
    /// Those answers are discarded rather than reported: a rejection is only
    /// returned once every copy has answered and none succeeded.
    ///
    /// The returned hash is computed locally, so it is correct regardless of
    /// which endpoint answered — or whether one answered at all.
    ///
    /// ```no_run
    /// # async fn f(client: &pilotlight::SequencerClient, raw: &[u8]) -> Result<(), pilotlight::Error> {
    /// let sent = client.send_raw_transaction(raw).await?;
    /// println!("{} via {} in {:?}", sent.tx_hash, sent.endpoint, sent.latency);
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Rejected`] if the sequencer refused the transaction. That is
    /// final — every endpoint fronts the same sequencer, so resubmitting the
    /// same bytes will be refused the same way.
    ///
    /// [`Error::NotReady`], [`Error::Timeout`] or [`Error::AllFailed`] if no
    /// endpoint could deliver it. These are retryable, and the transaction may
    /// or may not have reached the sequencer. Resubmitting the same bytes
    /// cannot include it twice, since the nonce is already fixed by the
    /// signature: it either lands, or comes back as `nonce too low`. Telling
    /// that apart from a nonce another transaction consumed needs a read node,
    /// which this crate does not talk to.
    ///
    /// [`Error::InvalidRawTx`] if `raw` is empty.
    ///
    /// [`Error::is_retryable`] draws this line for you.
    pub async fn send_raw_transaction(&self, raw: &[u8]) -> Result<Submission> {
        let tx_hash = check_raw(raw)?;
        self.dispatch(rpc::send_raw_body(raw), tx_hash).await
    }

    /// Submit a transaction given as a `0x`-prefixed hex string.
    ///
    /// Convenience wrapper; prefer [`Self::send_raw_transaction`] when you
    /// already hold bytes, since this has to decode first.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRawTx`] if `raw_hex` is not valid hex, plus everything
    /// [`Self::send_raw_transaction`] can return.
    pub async fn send_raw_transaction_hex(&self, raw_hex: &str) -> Result<Submission> {
        let bytes = const_hex::decode(raw_hex.strip_prefix("0x").unwrap_or(raw_hex))
            .map_err(|e| Error::InvalidRawTx(format!("expected hex: {e}")))?;
        self.send_raw_transaction(&bytes).await
    }

    /// Submit via `eth_sendRawTransactionConditional`.
    ///
    /// The sequencer checks every constraint before ordering the transaction
    /// and refuses it outright if one does not hold, which is useful when a
    /// stale state read would make the transaction harmful rather than merely
    /// wasteful.
    ///
    /// The refusal is immediate and explicit — `Storage slot value condition
    /// not met`, `BlockNumberMax condition not met` — rather than a silent
    /// drop, and the nonce is left unconsumed.
    ///
    /// # Errors
    ///
    /// Everything [`Self::send_raw_transaction`] can return. A
    /// [`Error::Rejected`] carrying code `-32602` means the sequencer could not
    /// parse `options` rather than that it disliked the transaction.
    pub async fn send_raw_transaction_conditional(
        &self,
        raw: &[u8],
        options: &ConditionalOptions,
    ) -> Result<Submission> {
        let tx_hash = check_raw(raw)?;
        let body = rpc::send_raw_conditional_body(raw, options)?;
        self.dispatch(body, tx_hash).await
    }

    /// Per-endpoint health and latency, for metrics and debugging.
    #[must_use]
    pub fn stats(&self) -> Vec<EndpointStats> {
        self.inner
            .pool
            .snapshot()
            .iter()
            .map(|e| e.stats())
            .collect()
    }

    /// Force an immediate DNS re-resolution and endpoint reconciliation.
    ///
    /// Happens automatically on the
    /// [`dns_refresh_interval`](ClientBuilder::dns_refresh_interval). Call this
    /// to react to an external signal, such as a deployment known to have moved
    /// the endpoints, without waiting for the next tick.
    ///
    /// # Errors
    ///
    /// [`Error::Dns`] if the lookup fails. The existing endpoints are left
    /// untouched, so a resolver blip does not cost you warm connections.
    pub async fn refresh_endpoints(&self) -> Result<()> {
        self.inner.pool.refresh().await
    }

    /// Broadcast one body across the ranked endpoint set and take the first
    /// usable answer.
    async fn dispatch(&self, body: Bytes, tx_hash: TxHash) -> Result<Submission> {
        let started = Instant::now();
        let cfg = &self.inner.cfg;

        let all = self.inner.pool.snapshot();
        let mut targets: Vec<Arc<Endpoint>> =
            all.iter().filter(|e| e.is_ready()).cloned().collect();

        if targets.is_empty() {
            return Err(Error::NotReady { known: all.len() });
        }

        targets.sort_by_key(|e| e.rank());
        let width = fanout_width(cfg.fanout, targets.len());
        targets.truncate(width);

        let (tx, mut rx) = mpsc::channel(width.max(1));
        let mut in_flight = 0usize;

        for endpoint in targets {
            let Some(conn) = endpoint.pick_conn() else {
                continue;
            };
            let req = self.inner.template.build(body.clone());
            let timeout = cfg.request_timeout;
            let state = endpoint.state().clone();
            let tx = tx.clone();

            // Detached on purpose: a copy already on the wire runs to
            // completion even after another endpoint has won the race.
            // Aborting could cancel a write mid-flight, losing the redundancy
            // the fan-out exists to provide.
            tokio::spawn(async move {
                let at = Instant::now();
                let outcome = match exchange(&conn, req, timeout).await {
                    Ok(body) => rpc::parse_send_response(conn.ip, &body),
                    Err(e) => Err(e),
                };

                match &outcome {
                    // A rejection is a healthy, fast answer from a working
                    // endpoint, so it counts as a latency sample, not a fault.
                    Ok(()) | Err(Error::Rejected { .. }) => state.record_success(at.elapsed()),
                    Err(e) => state.record_failure(e),
                }

                let _ = tx.send((conn.ip, outcome)).await;
            });
            in_flight += 1;
        }
        drop(tx);

        if in_flight == 0 {
            return Err(Error::NotReady { known: all.len() });
        }

        let endpoint = collect_verdict(
            &mut rx,
            started + cfg.request_timeout,
            cfg.request_timeout,
            in_flight,
            all.len(),
        )
        .await?;

        Ok(Submission {
            tx_hash,
            endpoint,
            latency: started.elapsed(),
            fanout: in_flight,
        })
    }
}

/// Reduce the answers from a fan-out to the endpoint that carried the
/// transaction, or to the failure that describes all of them.
///
/// The first success settles it. A failure never settles it while copies are
/// still outstanding: the copies are duplicates of one transaction, not
/// independent queries, and this sequencer orders synchronously, so a copy that
/// loses the race is answered `nonce too low` against the state the winner just
/// advanced. Returning that answer would report a transaction that had been
/// sequenced as failed.
///
/// Once every copy has answered and none succeeded, a rejection from the
/// sequencer is the real answer; if nothing came back but transport failures,
/// the transaction was never delivered.
async fn collect_verdict(
    rx: &mut mpsc::Receiver<(IpAddr, Result<()>)>,
    deadline: Instant,
    budget: Duration,
    attempts: usize,
    known: usize,
) -> Result<IpAddr> {
    let mut rejection: Option<Error> = None;
    let mut transport_failure: Option<Error> = None;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout(budget));
        }

        match tokio::time::timeout(remaining, rx.recv()).await {
            Err(_) => return Err(Error::Timeout(budget)),
            Ok(None) => break,
            Ok(Some((ip, Ok(())))) => return Ok(ip),
            Ok(Some((_, Err(e)))) => {
                if e.is_retryable() {
                    transport_failure = Some(e);
                } else {
                    // Keep the first verdict; later copies describe the state
                    // the winner left behind rather than the transaction.
                    rejection.get_or_insert(e);
                }
            }
        }
    }

    Err(match (rejection, transport_failure) {
        (Some(rejected), _) => rejected,
        (None, Some(last)) => Error::AllFailed {
            attempts,
            last: Box::new(last),
        },
        (None, None) => Error::NotReady { known },
    })
}

/// How many endpoints one submission is broadcast to.
///
/// A configured `0` means every endpoint that is ready; anything larger is
/// capped at what is actually available.
fn fanout_width(configured: usize, available: usize) -> usize {
    if configured == 0 {
        available
    } else {
        configured.min(available)
    }
}

/// Reject transactions that cannot be valid, before touching the network.
fn check_raw(raw: &[u8]) -> Result<TxHash> {
    if raw.is_empty() {
        return Err(Error::InvalidRawTx("transaction is empty".into()));
    }
    Ok(TxHash::of_raw_tx(raw))
}

impl std::fmt::Debug for SequencerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SequencerClient")
            .field("host", &self.inner.cfg.host)
            .field("endpoints", &self.stats())
            .finish()
    }
}

/// Builder for [`SequencerClient`].
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    cfg: Config,
}

impl ClientBuilder {
    /// Hostname of the sequencer to submit to.
    ///
    /// Used for DNS resolution, for TLS SNI, and as the HTTP/2 `:authority`
    /// pseudo-header, so this is what the server certificate is validated
    /// against. Defaults to [`SEQUENCER_HOST`](crate::SEQUENCER_HOST).
    #[must_use]
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.cfg.host = host.into();
        self
    }

    /// TLS port. Default 443.
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.cfg.port = port;
        self
    }

    /// Warm connections held open per endpoint address. Default 2.
    ///
    /// This buys redundancy, not throughput: HTTP/2 already multiplexes any
    /// number of concurrent submissions over a single connection, so a second
    /// connection matters when the first is torn down — a GOAWAY, an idle
    /// reap, a broken socket — and a submission would otherwise have to fall
    /// back to another endpoint.
    #[must_use]
    pub fn conns_per_ip(mut self, n: usize) -> Self {
        self.cfg.conns_per_ip = n;
        self
    }

    /// How many endpoints each transaction is broadcast to at once, the first
    /// usable answer winning. Default 0.
    ///
    /// `0` means every endpoint the pool knows about. Broadcasting duplicates
    /// cannot include the transaction twice — the nonce is fixed by the
    /// signature — and the copies that lose the race are answered `nonce too
    /// low`, which [`SequencerClient::send_raw_transaction`] discards in favour
    /// of the copy that succeeded.
    #[must_use]
    pub fn fanout(mut self, n: usize) -> Self {
        self.cfg.fanout = n;
        self
    }

    /// Budget for one TCP connect plus TLS handshake. Default 3 s.
    ///
    /// Off the hot path, since connections are warmed in the background.
    /// [`ClientBuilder::connect`] waits up to twice this value for the first
    /// connection to come up.
    #[must_use]
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.cfg.connect_timeout = d;
        self
    }

    /// Budget for a whole submission. Default 5 s.
    ///
    /// Measured across the entire fan-out rather than per endpoint.
    #[must_use]
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.cfg.request_timeout = d;
        self
    }

    /// How often each connection issues an `rpc_modules` probe. Default 15 s.
    ///
    /// Two jobs: it keeps intermediate load balancers from reaping the
    /// connection as idle, and it supplies the latency sample used to rank
    /// endpoints so the fastest healthy one is preferred. [`Duration::ZERO`]
    /// turns probing off.
    #[must_use]
    pub fn probe_interval(mut self, d: Duration) -> Self {
        self.cfg.probe_interval = d;
        self
    }

    /// How often the hostname is re-resolved and the endpoint set reconciled.
    /// Default 30 s.
    ///
    /// The A records carry a 60 s TTL and do rotate, so this stays well under
    /// it. Surviving endpoints keep their warm connections, and a failed
    /// lookup leaves the current set alone. [`Duration::ZERO`] resolves once at
    /// startup and never again.
    #[must_use]
    pub fn dns_refresh_interval(mut self, d: Duration) -> Self {
        self.cfg.dns_refresh_interval = d;
        self
    }

    /// How often an established connection sends an HTTP/2 PING frame.
    /// Default 10 s.
    ///
    /// PINGs continue while the connection is idle, which is its normal state
    /// for a pre-warmed pool.
    #[must_use]
    pub fn h2_ping_interval(mut self, d: Duration) -> Self {
        self.cfg.h2_ping_interval = d;
        self
    }

    /// How long a PING may go unacknowledged before the connection is declared
    /// dead and rebuilt. Default 5 s.
    #[must_use]
    pub fn h2_ping_timeout(mut self, d: Duration) -> Self {
        self.cfg.h2_ping_timeout = d;
        self
    }

    /// Delay before the first reconnect attempt after a connection drops.
    /// Default 100 ms.
    ///
    /// It doubles after each consecutive failure, up to
    /// [`ClientBuilder::reconnect_max_backoff`].
    #[must_use]
    pub fn reconnect_min_backoff(mut self, d: Duration) -> Self {
        self.cfg.reconnect_min_backoff = d;
        self
    }

    /// Ceiling for the reconnect backoff. Default 5 s.
    ///
    /// A sustained outage keeps retrying at this interval instead of drifting
    /// out to minutes. Must not be below
    /// [`ClientBuilder::reconnect_min_backoff`], or the clamp would pin the
    /// delay at the ceiling and it would never grow.
    #[must_use]
    pub fn reconnect_max_backoff(mut self, d: Duration) -> Self {
        self.cfg.reconnect_max_backoff = d;
        self
    }

    /// Value sent in the `user-agent` header.
    #[must_use]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.cfg.user_agent = ua.into();
        self
    }

    /// Build the client and start warming connections, without waiting.
    ///
    /// Submissions made before a connection is up fail with
    /// [`Error::NotReady`]; call [`SequencerClient::wait_until_ready`] first,
    /// or use [`ClientBuilder::connect`].
    ///
    /// # Errors
    ///
    /// [`Error::Config`] if the settings cannot produce a working client, or
    /// [`Error::Dns`] if the initial hostname lookup fails.
    pub async fn build(self) -> Result<SequencerClient> {
        self.cfg.validate()?;

        let cfg = Arc::new(self.cfg);
        let tls = tls::client_config()?;
        let template = RequestTemplate::new(&cfg)?;
        let pool = Pool::new(cfg.clone(), tls, template.clone()).await?;

        let dns_task = if cfg.dns_refresh_interval.is_zero() {
            None
        } else {
            Some(tokio::spawn(dns_refresh_loop(
                pool.clone(),
                cfg.dns_refresh_interval,
            )))
        };

        Ok(SequencerClient {
            inner: Arc::new(Inner {
                cfg,
                template,
                pool,
                dns_task,
            }),
        })
    }

    /// Build the client and wait for the first warm connection.
    ///
    /// Waits up to [`connect_timeout`](ClientBuilder::connect_timeout) doubled,
    /// which covers a TCP
    /// connect plus a TLS handshake with room to spare.
    ///
    /// # Errors
    ///
    /// Everything [`Self::build`] can return, plus [`Error::Timeout`] if no
    /// connection is warm before the budget expires.
    pub async fn connect(self) -> Result<SequencerClient> {
        let warm_budget = self.cfg.connect_timeout * 2;
        let client = self.build().await?;
        client.wait_until_ready(warm_budget).await?;
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn nonce_too_low() -> Error {
        Error::Rejected {
            code: -32000,
            message: "nonce too low: tx: 7 state: 8".into(),
        }
    }

    fn unreachable_endpoint() -> Error {
        Error::Transport {
            ip: ip(9),
            message: "connection is not established".into(),
        }
    }

    /// Feed a fixed sequence of answers through the reduction, in order.
    async fn verdict_of(answers: Vec<(IpAddr, Result<()>)>, known: usize) -> Result<IpAddr> {
        let attempts = answers.len();
        let (tx, mut rx) = mpsc::channel(attempts.max(1));
        for a in answers {
            tx.send(a).await.expect("send");
        }
        drop(tx);
        let budget = Duration::from_secs(30);
        collect_verdict(&mut rx, Instant::now() + budget, budget, attempts, known).await
    }

    /// A rejection from one copy does not decide the fan-out.
    ///
    /// Every copy but one is answered `nonce too low`, because this sequencer
    /// orders synchronously and the winner has already advanced the account
    /// state. Those answers arrive in whatever order the network delivers them,
    /// so a rejection routinely lands first. Reporting it would tell the caller
    /// a sequenced transaction had failed, and the caller may then reissue it
    /// under a fresh nonce.
    #[tokio::test]
    async fn a_success_wins_however_late_it_arrives() {
        let winner = verdict_of(
            vec![
                (ip(1), Err(nonce_too_low())),
                (ip(2), Err(nonce_too_low())),
                (ip(3), Ok(())),
            ],
            3,
        )
        .await
        .expect("the copy that landed must decide the outcome");
        assert_eq!(winner, ip(3));
    }

    /// A transport failure must not settle it either.
    #[tokio::test]
    async fn a_success_wins_over_an_earlier_transport_failure() {
        let winner = verdict_of(
            vec![(ip(1), Err(unreachable_endpoint())), (ip(2), Ok(()))],
            2,
        )
        .await
        .expect("delivery on one endpoint is enough");
        assert_eq!(winner, ip(2));
    }

    #[tokio::test]
    async fn the_first_success_is_the_one_reported() {
        let winner = verdict_of(vec![(ip(1), Ok(())), (ip(2), Ok(()))], 2)
            .await
            .expect("success");
        assert_eq!(winner, ip(1));
    }

    /// With nothing to override it, the sequencer's verdict is the answer.
    #[tokio::test]
    async fn every_copy_rejected_reports_the_rejection() {
        let err = verdict_of(
            vec![
                (ip(1), Err(nonce_too_low())),
                (ip(2), Err(nonce_too_low())),
                (ip(3), Err(nonce_too_low())),
            ],
            3,
        )
        .await
        .expect_err("no copy succeeded");
        assert!(
            matches!(err, Error::Rejected { code: -32000, .. }),
            "got {err:?}"
        );
        assert!(!err.is_retryable());
    }

    /// A rejection outranks a transport failure: one endpoint reaching the
    /// sequencer and being refused says more than another failing to reach it.
    #[tokio::test]
    async fn a_rejection_outranks_a_transport_failure() {
        let err = verdict_of(
            vec![
                (ip(1), Err(unreachable_endpoint())),
                (ip(2), Err(nonce_too_low())),
            ],
            2,
        )
        .await
        .expect_err("no copy succeeded");
        assert!(matches!(err, Error::Rejected { .. }), "got {err:?}");
    }

    /// Nothing reached the sequencer, so nothing is known about the
    /// transaction and the caller may resend.
    #[tokio::test]
    async fn only_transport_failures_report_as_undelivered() {
        let err = verdict_of(
            vec![
                (ip(1), Err(unreachable_endpoint())),
                (ip(2), Err(unreachable_endpoint())),
            ],
            2,
        )
        .await
        .expect_err("no copy succeeded");
        match err {
            Error::AllFailed { attempts, .. } => assert_eq!(attempts, 2),
            other => panic!("expected AllFailed, got {other:?}"),
        }
        assert!(
            Error::AllFailed {
                attempts: 2,
                last: Box::new(unreachable_endpoint())
            }
            .is_retryable()
        );
    }

    #[tokio::test]
    async fn no_copy_answered_at_all_reports_not_ready() {
        let err = verdict_of(vec![], 3).await.expect_err("nothing answered");
        assert!(matches!(err, Error::NotReady { known: 3 }), "got {err:?}");
    }
}
