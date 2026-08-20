//! Error types.

use std::net::IpAddr;
use std::time::Duration;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong when talking to the sequencer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration could not be used to build a client.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Resolving the sequencer hostname failed.
    #[error("DNS resolution for `{host}` failed: {source}")]
    Dns {
        /// Hostname that failed to resolve.
        host: String,
        /// Underlying resolver error.
        #[source]
        source: std::io::Error,
    },

    /// The pool has no endpoint with a live connection.
    ///
    /// Either the client has not finished warming up yet (call
    /// [`wait_until_ready`](crate::SequencerClient::wait_until_ready)) or every
    /// endpoint is currently down.
    #[error("no warm connection to the sequencer ({known} endpoint(s) known, none ready)")]
    NotReady {
        /// How many endpoints the pool knows about.
        known: usize,
    },

    /// A connection-level failure while sending to one specific endpoint.
    #[error("transport failure talking to {ip}: {message}")]
    Transport {
        /// Endpoint the failure happened on.
        ip: IpAddr,
        /// Human-readable cause.
        message: String,
    },

    /// The sequencer answered, but not with 2xx.
    #[error("sequencer at {ip} returned HTTP {status}: {body}")]
    HttpStatus {
        /// Endpoint that answered.
        ip: IpAddr,
        /// HTTP status code.
        status: u16,
        /// Response body, truncated to a sane length.
        body: String,
    },

    /// The response was not a well-formed JSON-RPC envelope.
    #[error("malformed JSON-RPC response from {ip}: {message}")]
    BadResponse {
        /// Endpoint that answered.
        ip: IpAddr,
        /// What went wrong while parsing.
        message: String,
    },

    /// The error carries no verdict on the transaction that this client can
    /// read.
    ///
    /// It says nothing about what the sequencer did. An internal error can
    /// arrive after the transaction was accepted, from a server that failed
    /// while composing its answer, so the transaction may have been read,
    /// accepted, both, or neither.
    ///
    /// These are retryable, since resending cannot include the transaction
    /// twice. The exceptions are the codes that describe the request itself,
    /// which will be refused the same way until the request changes.
    #[error("sequencer RPC fault: [{code}] {message}")]
    Rpc {
        /// JSON-RPC error code.
        ///
        /// Usually one the specification defines, but any code that is not a
        /// verdict on the transaction arrives here, including one this crate
        /// does not recognise.
        code: i64,
        /// JSON-RPC error message.
        message: String,
    },

    /// The sequencer explicitly rejected the transaction.
    ///
    /// This is a definitive answer, not a retryable failure — every endpoint
    /// fronts the same sequencer, so the other racers would say the same thing.
    #[error("sequencer rejected the transaction: [{code}] {message}")]
    Rejected {
        /// JSON-RPC error code (Nitro uses -32000 for most tx rejections).
        code: i64,
        /// JSON-RPC error message, e.g. `nonce too low`.
        message: String,
    },

    /// The request did not complete within the configured budget.
    #[error("request timed out after {0:?}")]
    Timeout(Duration),

    /// Every endpoint in the fan-out failed at the transport level.
    #[error("all {attempts} endpoint(s) failed; last error: {last}")]
    AllFailed {
        /// How many endpoints were tried.
        attempts: usize,
        /// The last transport error observed.
        #[source]
        last: Box<Error>,
    },

    /// The raw transaction bytes were not usable.
    #[error("invalid raw transaction: {0}")]
    InvalidRawTx(String),
}

impl Error {
    /// Whether retrying on a different connection could plausibly succeed.
    ///
    /// [`Error::Rejected`] is *not* retryable: all endpoints front the same
    /// sequencer, so a rejection is final.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Transport { .. }
            | Error::HttpStatus { .. }
            | Error::BadResponse { .. }
            | Error::NotReady { .. }
            | Error::Timeout(_)
            | Error::AllFailed { .. } => true,

            // A fault in the call says nothing about the transaction, so the
            // submission is worth repeating — unless the fault is in the
            // request itself, which will be refused the same way until it
            // changes: unparseable, malformed, an unknown or unsupported
            // method, bad parameters, a missing resource, or a protocol
            // version this server does not speak.
            Error::Rpc { code, .. } => !matches!(
                code,
                -32700 | -32600 | -32601 | -32602 | -32001 | -32004 | -32006
            ),

            Error::Config(_)
            | Error::Dns { .. }
            | Error::Rejected { .. }
            | Error::InvalidRawTx(_) => false,
        }
    }
}
