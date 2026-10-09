use std::net::SocketAddr;

use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FailureKind {
    #[error("Connection unavailable")]
    Unavailable,
    #[error("All connections to this IP are at capacity")]
    Busy,
    #[error("Operation timed out")]
    Timeout,
    #[error("DNS resolution failed")]
    Dns,
    #[error("Transport failed")]
    Transport,
    #[error("TLS handshake failed or HTTP/2 was not negotiated")]
    Tls,
    #[error("HTTP status {0}")]
    Http(u16),
    #[error("RPC error {0}")]
    Rpc(i64),
    #[error("Invalid RPC response")]
    InvalidResponse,
    #[error("Response exceeds size limit")]
    ResponseTooLarge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointFailure {
    /// Zero-based index in `Config::endpoints`. URL contents are never retained in errors.
    pub endpoint: usize,
    pub peer: Option<SocketAddr>,
    pub kind: FailureKind,
}

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("{0}")]
    InvalidConfig(&'static str),
    #[error("No connections established: {0:?}")]
    NoConnections(Vec<EndpointFailure>),
}

#[derive(Debug, Error)]
pub enum BroadcastError {
    #[error("Invalid signed transaction encoding")]
    InvalidTransaction,
    /// No valid success response was received; inclusion may still have occurred.
    #[error("No successful response: {0:?}")]
    NoSuccess(Vec<EndpointFailure>),
}
