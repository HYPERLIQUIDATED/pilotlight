use std::{fmt, sync::Arc, time::Duration};

use alloy_primitives::{B256, Bytes};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::time::Instant;

use crate::{
    BroadcastError, Config, ConnectError, EndpointFailure,
    connection::{self, ConnectionSettings},
    endpoint::{Endpoint, Target},
    pool::StartupReport,
    rpc,
};

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    endpoints: Vec<Endpoint>,
    request_timeout: Duration,
    initial_failures: Vec<EndpointFailure>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("endpoints", &self.inner.endpoints.len())
            .field("request_timeout", &self.inner.request_timeout)
            .field("initial_failures", &self.inner.initial_failures)
            .finish()
    }
}

impl Client {
    /// Resolves every endpoint and establishes a pool of HTTP/2 connections per unique IP.
    /// At least one connection must succeed. Unavailable connections retry in the background.
    ///
    /// # Errors
    /// Returns sanitized configuration or connection failures.
    pub async fn connect(config: Config) -> Result<Self, ConnectError> {
        let tls = connection::tls_config();
        config.validate()?;
        let targets: Vec<_> = config
            .endpoints
            .iter()
            .map(|url| Target::parse(url))
            .collect::<Result<_, _>>()?;
        let mut endpoints = Vec::with_capacity(targets.len());
        let mut pending = FuturesUnordered::new();
        let deadline = Instant::now() + config.connect_timeout;

        for (index, target) in targets.into_iter().enumerate() {
            let (endpoint, ready) = Endpoint::start(
                index,
                target,
                tls.clone(),
                ConnectionSettings {
                    connect_timeout: config.connect_timeout,
                    reconnect_min_delay: config.reconnect_min_delay,
                    reconnect_max_delay: config.reconnect_max_delay,
                    reset_stream_capacity: config.reset_stream_capacity,
                    initial_deadline: deadline,
                },
                config.connections_per_ip,
                config.dns_refresh_interval,
            );
            endpoints.push(endpoint);
            pending.push(ready);
        }

        let mut failures = Vec::new();
        let mut connected = false;

        while let Some(StartupReport {
            connected: established,
            failures: failed,
        }) = pending.next().await
        {
            connected |= established;
            failures.extend(failed);
        }

        failures.sort_unstable_by_key(|failure| (failure.endpoint, failure.peer));

        if !connected {
            return Err(ConnectError::NoConnections(failures));
        }

        Ok(Self {
            inner: Arc::new(ClientInner {
                endpoints,
                request_timeout: config.request_timeout,
                initial_failures: failures,
            }),
        })
    }

    /// Startup failures, retained for diagnostics even if a connection later recovers.
    #[must_use]
    pub fn initial_failures(&self) -> &[EndpointFailure] {
        &self.inner.initial_failures
    }

    /// Broadcasts identical bytes concurrently; the first matching hash wins.
    /// Remaining local request futures are canceled. Already-submitted transactions cannot be undone.
    ///
    /// # Errors
    /// Invalid transaction encoding or failure to receive any valid success response.
    /// Neither failure nor cancellation proves that the transaction was not included.
    pub async fn broadcast(&self, raw: Bytes) -> Result<B256, BroadcastError> {
        let deadline = Instant::now() + self.inner.request_timeout;
        let (body, hash) = rpc::encode_request(raw)?;
        let mut pending = FuturesUnordered::new();
        let mut failures = Vec::new();

        for endpoint in &self.inner.endpoints {
            let pools = endpoint.snapshot();

            if pools.is_empty() {
                failures.push(endpoint.unavailable());
            }

            for pool in pools.iter() {
                let pool = Arc::clone(pool);
                let body = body.clone();
                pending.push(async move {
                    let response = pool.send(body, deadline).await?;
                    rpc::decode_response(&response, hash).map_err(|kind| pool.failure(kind))
                });
            }
        }

        while let Some(result) = pending.next().await {
            match result {
                Ok(()) => return Ok(hash),
                Err(failure) => failures.push(failure),
            }
        }

        failures.sort_unstable_by_key(|failure| (failure.endpoint, failure.peer));
        Err(BroadcastError::NoSuccess(failures))
    }
}
