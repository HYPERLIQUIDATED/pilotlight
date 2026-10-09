use std::{collections::BTreeMap, future::Future, net::SocketAddr, sync::Arc, time::Duration};

use futures_util::{StreamExt, stream::FuturesUnordered};
use hyper::Uri;
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{
    net::lookup_host,
    sync::{oneshot, watch},
    time::{Instant, sleep, timeout_at},
};
use url::{Host, Url};

use crate::{
    ConnectError, EndpointFailure, FailureKind,
    connection::{ConnectionSettings, Transport},
    pool::{ConnectionPool, StartupReport},
};

pub(crate) struct Target {
    uri: Uri,
    host: String,
    port: u16,
    transport: Transport,
}

pub(crate) struct Endpoint {
    index: usize,
    pools: watch::Receiver<Arc<[Arc<ConnectionPool>]>>,
}

impl Endpoint {
    pub(crate) fn start(
        index: usize,
        target: Target,
        tls: Arc<ClientConfig>,
        settings: ConnectionSettings,
        connections_per_ip: usize,
        dns_refresh_interval: Duration,
    ) -> (Self, impl Future<Output = StartupReport>) {
        let (published, pools) = watch::channel(Arc::from([]));
        let (initial, ready) = oneshot::channel();
        let endpoint = Self { index, pools };

        tokio::spawn(async move {
            let maintain = async {
                let mut pools = BTreeMap::new();
                let mut initial = Some(initial);
                let mut retry_delay = settings.reconnect_min_delay;
                let mut dns_failed = false;

                loop {
                    let deadline = if initial.is_some() {
                        settings.initial_deadline
                    } else {
                        Instant::now() + settings.connect_timeout
                    };
                    let resolved = timeout_at(deadline, lookup(&target.host, target.port))
                        .await
                        .unwrap_or(Err(FailureKind::Timeout))
                        .and_then(normalize);

                    let delay = match resolved {
                        Ok(peers) => {
                            if dns_failed {
                                tracing::info!(
                                    event = "dns_recovered",
                                    endpoint = index,
                                    "DNS resolution recovered"
                                );
                                dns_failed = false;
                            }
                            retry_delay = settings.reconnect_min_delay;

                            let mut connecting = reconcile(
                                index,
                                &mut pools,
                                &peers,
                                &target,
                                &tls,
                                ConnectionSettings {
                                    initial_deadline: deadline,
                                    ..settings
                                },
                                connections_per_ip,
                            );
                            published.send_replace(pools.values().cloned().collect());

                            if let Some(initial) = initial.take() {
                                let mut report = StartupReport::default();

                                while let Some(result) = connecting.next().await {
                                    report.connected |= result.connected;
                                    report.failures.extend(result.failures);
                                }

                                let _ = initial.send(report);
                            }

                            dns_refresh_interval
                        }
                        Err(kind) => {
                            dns_failed = true;
                            let delay = retry_delay;
                            retry_delay = retry_delay
                                .saturating_mul(2)
                                .min(settings.reconnect_max_delay);
                            tracing::warn!(
                                event = "dns_retry_scheduled",
                                endpoint = index,
                                error = ?kind,
                                retry_delay = ?delay,
                                "DNS retry scheduled"
                            );
                            if let Some(initial) = initial.take() {
                                let _ = initial.send(StartupReport {
                                    connected: false,
                                    failures: vec![EndpointFailure {
                                        endpoint: index,
                                        peer: None,
                                        kind,
                                    }],
                                });
                            }

                            delay
                        }
                    };

                    sleep(delay).await;
                }
            };

            tokio::select! {
                biased;
                () = published.closed() => {
                    tracing::debug!(event = "endpoint_stopped", endpoint = index, "Endpoint maintenance stopped");
                },
                () = maintain => {},
            }
        });

        (endpoint, async move {
            ready.await.unwrap_or_else(|_| StartupReport {
                connected: false,
                failures: vec![EndpointFailure {
                    endpoint: index,
                    peer: None,
                    kind: FailureKind::Transport,
                }],
            })
        })
    }

    pub(crate) fn snapshot(&self) -> Arc<[Arc<ConnectionPool>]> {
        self.pools.borrow().clone()
    }

    pub(crate) fn unavailable(&self) -> EndpointFailure {
        EndpointFailure {
            endpoint: self.index,
            peer: None,
            kind: FailureKind::Unavailable,
        }
    }
}

fn reconcile(
    index: usize,
    pools: &mut BTreeMap<SocketAddr, Arc<ConnectionPool>>,
    peers: &[SocketAddr],
    target: &Target,
    tls: &Arc<ClientConfig>,
    settings: ConnectionSettings,
    connections_per_ip: usize,
) -> FuturesUnordered<impl Future<Output = StartupReport> + use<>> {
    pools.retain(|peer, _| {
        let retained = peers.binary_search(peer).is_ok();
        if !retained {
            tracing::info!(event = "endpoint_address_removed", endpoint = index, %peer, "Endpoint address removed");
        }
        retained
    });
    let connecting = FuturesUnordered::new();

    for &peer in peers {
        if let std::collections::btree_map::Entry::Vacant(entry) = pools.entry(peer) {
            tracing::info!(event = "endpoint_address_added", endpoint = index, %peer, "Endpoint address added");
            let (connection_pool, ready) = ConnectionPool::start(
                index,
                peer,
                target.uri.clone(),
                &target.transport,
                tls,
                settings,
                connections_per_ip,
            );
            entry.insert(Arc::new(connection_pool));
            connecting.push(ready);
        }
    }

    connecting
}

fn normalize(mut peers: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, FailureKind> {
    peers.sort_unstable();
    peers.dedup();

    if peers.is_empty() {
        Err(FailureKind::Dns)
    } else {
        Ok(peers)
    }
}

async fn lookup(host: &str, port: u16) -> Result<Vec<SocketAddr>, FailureKind> {
    let peers = lookup_host((host, port))
        .await
        .map_err(|_| FailureKind::Dns)?
        .collect();
    Ok(peers)
}

impl Target {
    pub(crate) fn parse(value: &str) -> Result<Self, ConnectError> {
        let invalid = || {
            ConnectError::InvalidConfig(
                "Endpoints must be HTTP(S) URLs without credentials or fragments",
            )
        };
        let url = Url::parse(value).map_err(|_| invalid())?;

        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(invalid());
        }

        let host = match url.host().ok_or_else(invalid)? {
            Host::Domain(domain) => domain.to_owned(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        };

        let transport = match url.scheme() {
            "http" => Transport::Http,
            "https" => Transport::Https(ServerName::try_from(host.clone()).map_err(|_| invalid())?),
            _ => return Err(invalid()),
        };

        Ok(Self {
            uri: url.as_str().parse().map_err(|_| invalid())?,
            host,
            port: url.port_or_known_default().ok_or_else(invalid)?,
            transport,
        })
    }
}
