//! The endpoint set: DNS resolution and reconciliation.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use rustls::ClientConfig;
use tokio::sync::Notify;

use crate::config::Config;
use crate::endpoint::Endpoint;
use crate::error::{Error, Result};
use crate::request::RequestTemplate;

/// Owns every [`Endpoint`] and keeps the set in step with DNS.
pub(crate) struct Pool {
    /// Shared with every endpoint and connection this pool creates.
    cfg: Arc<Config>,
    /// One rustls config for the whole pool, so session tickets are shared.
    tls: Arc<ClientConfig>,
    /// Handed to new endpoints for their probe requests.
    template: RequestTemplate,
    /// Swapped wholesale on reconcile; readers clone the `Arc` and let go of
    /// the lock immediately.
    endpoints: RwLock<Arc<Vec<Arc<Endpoint>>>>,
    /// Fired by any connection that becomes usable.
    pub(crate) became_ready: Arc<Notify>,
}

impl Pool {
    /// Resolve the initial endpoint set and start warming it.
    pub(crate) async fn new(
        cfg: Arc<Config>,
        tls: Arc<ClientConfig>,
        template: RequestTemplate,
    ) -> Result<Arc<Self>> {
        let pool = Arc::new(Self {
            cfg,
            tls,
            template,
            endpoints: RwLock::new(Arc::new(Vec::new())),
            became_ready: Arc::new(Notify::new()),
        });

        let ips = pool.resolve().await?;
        pool.reconcile(&ips);
        Ok(pool)
    }

    /// Current endpoints. Cheap enough to call on the hot path.
    pub(crate) fn snapshot(&self) -> Arc<Vec<Arc<Endpoint>>> {
        self.endpoints
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Re-resolve and apply any change to the endpoint set.
    pub(crate) async fn refresh(&self) -> Result<()> {
        let ips = self.resolve().await?;
        self.reconcile(&ips);
        Ok(())
    }

    /// Look up the sequencer's addresses.
    async fn resolve(&self) -> Result<BTreeSet<IpAddr>> {
        let host = self.cfg.host.clone();
        let addrs = tokio::net::lookup_host((host.as_str(), self.cfg.port))
            .await
            .map_err(|source| Error::Dns {
                host: host.clone(),
                source,
            })?;

        let ips: BTreeSet<IpAddr> = addrs.map(|sa| sa.ip()).collect();

        if ips.is_empty() {
            return Err(Error::Dns {
                host,
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "resolver returned no addresses",
                ),
            });
        }

        Ok(ips)
    }

    /// Add endpoints for new addresses, retire those DNS has dropped.
    ///
    /// Endpoints that survive keep their existing warm connections, so a
    /// routine DNS refresh costs nothing.
    fn reconcile(&self, ips: &BTreeSet<IpAddr>) {
        let current = self.snapshot();

        let unchanged = current.len() == ips.len() && current.iter().all(|e| ips.contains(&e.ip));
        if unchanged {
            return;
        }

        let mut next: Vec<Arc<Endpoint>> = Vec::with_capacity(ips.len());
        for ip in ips {
            if let Some(existing) = current.iter().find(|e| e.ip == *ip) {
                next.push(existing.clone());
            } else {
                tracing::info!(%ip, "adding endpoint");
                next.push(Endpoint::spawn(
                    *ip,
                    &self.cfg,
                    &self.tls,
                    &self.template,
                    &self.became_ready,
                ));
            }
        }

        for gone in current.iter().filter(|e| !ips.contains(&e.ip)) {
            tracing::info!(ip = %gone.ip, "retiring endpoint");
        }

        // Dropping the old `Arc<Vec<..>>` releases retired endpoints, whose
        // `Drop` aborts their supervisor and probe tasks.
        *self
            .endpoints
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
    }
}

/// Background task that keeps the endpoint set in step with DNS.
///
/// A failed lookup leaves the existing endpoints untouched: a resolver blip
/// should not take down warm connections that are still working.
pub(crate) async fn dns_refresh_loop(pool: Arc<Pool>, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires immediately, and the caller has already resolved.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        if let Err(e) = pool.refresh().await {
            tracing::warn!(error = %e, "DNS refresh failed, keeping the current endpoints");
        }
    }
}
