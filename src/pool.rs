use std::{future::Future, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use futures_util::{StreamExt, stream::FuturesUnordered};
use hyper::Uri;
use rustls::ClientConfig;
use tokio::time::Instant;

use crate::{
    EndpointFailure, FailureKind,
    connection::{Capacity, Connection, ConnectionId, ConnectionSettings, Reservation, Transport},
};

#[derive(Default)]
pub(crate) struct StartupReport {
    pub connected: bool,
    pub failures: Vec<EndpointFailure>,
}

pub(crate) struct ConnectionPool {
    endpoint: usize,
    address: SocketAddr,
    uri: Uri,
    connections: Vec<Connection>,
}

impl ConnectionPool {
    pub(crate) fn start(
        index: usize,
        peer: SocketAddr,
        uri: Uri,
        transport: &Transport,
        tls: &Arc<ClientConfig>,
        settings: ConnectionSettings,
        connections_per_ip: usize,
    ) -> (Self, impl Future<Output = StartupReport> + use<>) {
        let mut connections = Vec::with_capacity(connections_per_ip);
        let mut pending = FuturesUnordered::new();

        for slot in 0..connections_per_ip {
            let (connection, ready) = Connection::start(
                transport.clone(),
                ConnectionId {
                    endpoint: index,
                    peer,
                    slot,
                },
                tls.clone(),
                settings,
            );
            connections.push(connection);
            pending.push(ready);
        }

        let pool = Self {
            endpoint: index,
            address: peer,
            uri,
            connections,
        };

        (pool, async move {
            let mut report = StartupReport::default();

            while let Some(result) = pending.next().await {
                match result.unwrap_or(Err(FailureKind::Transport)) {
                    Ok(()) => report.connected = true,
                    Err(kind) => report.failures.push(EndpointFailure {
                        endpoint: index,
                        peer: Some(peer),
                        kind,
                    }),
                }
            }

            report
        })
    }

    fn reserve(&self) -> Result<Reservation, FailureKind> {
        loop {
            let mut selected = None;
            let mut failure = FailureKind::Unavailable;

            for connection in &self.connections {
                let Some(session) = connection.session() else {
                    continue;
                };

                let in_flight = match session.capacity() {
                    Capacity::Available { in_flight } => in_flight,
                    Capacity::Busy => {
                        failure = FailureKind::Busy;
                        continue;
                    }
                    Capacity::Unavailable => continue,
                };

                if selected
                    .as_ref()
                    .is_none_or(|(_, count)| in_flight < *count)
                {
                    selected = Some((session, in_flight));

                    if in_flight == 0 {
                        break;
                    }
                }
            }

            let Some((session, in_flight)) = selected else {
                return Err(failure);
            };

            if let Some(reservation) = session.try_reserve(in_flight) {
                return Ok(reservation);
            }
        }
    }

    pub(crate) async fn send(
        &self,
        body: Bytes,
        deadline: Instant,
    ) -> Result<Bytes, EndpointFailure> {
        let reservation = self.reserve().map_err(|kind| self.failure(kind))?;

        reservation
            .send(self.uri.clone(), body, deadline)
            .await
            .map_err(|kind| self.failure(kind))
    }

    pub(crate) fn failure(&self, kind: FailureKind) -> EndpointFailure {
        EndpointFailure {
            endpoint: self.endpoint,
            peer: Some(self.address),
            kind,
        }
    }
}
