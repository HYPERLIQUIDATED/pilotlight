//! Small value types returned by the client.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use tiny_keccak::{Hasher, Keccak};

/// A 32-byte Ethereum transaction hash.
///
/// Deliberately dependency-free so this crate stays usable next to any of
/// `alloy`, `ethers`, or hand-rolled signing code. Convert through
/// [`TxHash::as_bytes`] and [`TxHash::from_bytes`], or the `From` impls in
/// either direction. [`Display`](std::fmt::Display) writes lowercase
/// `0x`-prefixed hex and [`FromStr`] parses it back, with or without the
/// prefix.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxHash([u8; 32]);

impl TxHash {
    /// Compute the hash of an already-signed, RLP/EIP-2718 encoded transaction.
    ///
    /// This is plain `keccak256(raw)`, which is exactly how the sequencer will
    /// key the transaction — so the caller knows the hash without waiting for,
    /// or trusting, the RPC response.
    #[must_use]
    pub fn of_raw_tx(raw: &[u8]) -> Self {
        let mut out = [0u8; 32];
        let mut k = Keccak::v256();
        k.update(raw);
        k.finalize(&mut out);
        Self(out)
    }

    /// Wrap raw bytes that are already a hash.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", const_hex::encode(self.0))
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxHash(0x{})", const_hex::encode(self.0))
    }
}

impl FromStr for TxHash {
    type Err = const_hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 32];
        const_hex::decode_to_slice(s.strip_prefix("0x").unwrap_or(s), &mut out)?;
        Ok(Self(out))
    }
}

impl From<[u8; 32]> for TxHash {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<TxHash> for [u8; 32] {
    fn from(h: TxHash) -> Self {
        h.0
    }
}

/// Outcome of a successful submission.
///
/// The sequencer accepted the transaction and ordered it. There is no second
/// success shape: a duplicate is refused rather than acknowledged, so anything
/// other than this is an [`Error`](crate::Error).
#[derive(Debug, Clone)]
pub struct Submission {
    /// `keccak256` of the raw transaction, computed locally.
    pub tx_hash: TxHash,
    /// Which endpoint won the race.
    pub endpoint: IpAddr,
    /// Wall-clock time from entering `send_*` to this response landing.
    pub latency: Duration,
    /// How many endpoints the transaction was broadcast to.
    pub fanout: usize,
}

/// Health and latency snapshot for one sequencer IP.
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// The endpoint address.
    pub ip: IpAddr,
    /// Connections the supervisor last observed as established.
    ///
    /// A connection can break between that observation and the next send, so
    /// this can briefly overstate. A submission that picks one in that window
    /// fails with a retryable [`Error::AllFailed`](crate::Error::AllFailed)
    /// rather than reporting anything about the transaction.
    pub live_conns: usize,
    /// Connections configured for this endpoint.
    pub total_conns: usize,
    /// Exponentially weighted moving average of observed round-trip latency.
    ///
    /// `None` until the first probe or request completes.
    pub ewma_latency: Option<Duration>,
    /// Consecutive failures since the last success.
    ///
    /// Counts failed connection attempts as well as failed probes and
    /// submissions, so an endpoint that has never connected reports a rising
    /// count rather than a resting zero.
    pub consecutive_failures: u32,
    /// Why the most recent failure happened, cleared by the next success.
    ///
    /// This is the only place the reason is available without a `tracing`
    /// subscriber, and it is what distinguishes an endpoint still warming up
    /// from one that can never connect.
    pub last_failure: Option<String>,
}
