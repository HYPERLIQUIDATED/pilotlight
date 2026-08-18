//! A low-latency transaction submitter for the Robinhood chain sequencer.
//!
//! The sequencer at `sequencer.mainnet.chain.robinhood.com` is an Arbitrum
//! Nitro write endpoint fronted by Envoy in AWS `us-east-2`. It answers in
//! well under a millisecond — `x-envoy-upstream-service-time: 0` — so
//! essentially the entire latency of a submission is TCP, TLS, and round-trip
//! time. That shapes everything this crate does:
//!
//! * **Connections are established up front and kept warm.** A cold submission
//!   pays a TCP handshake plus a TLS handshake before the first byte of the
//!   transaction moves, which is two extra round trips. Measured from a host
//!   in the same region, a cold submission takes 6.7 ms against 3.2 ms warm;
//!   the further the caller sits from the sequencer, the more those two round
//!   trips cost.
//! * **Every endpoint is used.** The hostname resolves to several independent
//!   addresses. Each transaction can be broadcast to all of them at once and
//!   the first success wins, so one slow or recycling path does not become
//!   your tail latency. Duplicates cannot be included twice, since the nonce
//!   is fixed by the signature. The sequencer orders synchronously, so the
//!   copies that lose the race are answered `nonce too low` against the state
//!   the winner advanced; those answers are discarded, and a rejection is
//!   returned only once every copy has answered and none succeeded.
//! * **HTTP/2 is required.** ALPN offers `h2` alone, so concurrent
//!   submissions multiplex over one connection per endpoint instead of
//!   queueing behind each other. A peer that will not negotiate it is
//!   reported as a connect error.
//! * **Nothing blocks on a handshake.** Reconnects happen in the background
//!   with exponential backoff. A submission either finds a warm connection or
//!   fails fast against that endpoint and lets the others race.
//! * **Connections are kept alive deliberately.** HTTP/2 PING frames run even
//!   while idle, and a periodic `rpc_modules` request exercises the full path
//!   so intermediaries do not reap the connection. That probe doubles as the
//!   latency sample used to rank endpoints.
//! * **The address set tracks DNS.** The A records are re-resolved on an
//!   interval and reconciled; surviving endpoints keep their warm connections,
//!   and a failed lookup leaves the current set in place.
//!
//! # Scope
//!
//! Submission only. This crate takes transactions that are **already signed**
//! and hands back the hash it computed locally. It does not sign, and it
//! cannot read chain state — the endpoint exposes no read methods at all
//! (`eth_chainId`, `eth_blockNumber` and `eth_getTransactionCount` all return
//! -32601). Fetch nonces and gas prices from a normal RPC node, sign with
//! whatever you like, and pass the bytes here.
//!
//! # Errors
//!
//! [`Error::is_retryable`] draws the line that matters. An [`Error::Rejected`]
//! is the sequencer's verdict on those exact bytes, and every endpoint fronts
//! the same sequencer, so resending changes nothing. A transport failure, a
//! timeout or [`Error::AllFailed`] leaves delivery unknown. Resending the same
//! bytes cannot include the transaction twice, because the nonce is fixed by
//! the signature; it either lands or is answered `nonce too low`. There is no
//! acknowledgement of a duplicate to distinguish those two, so telling them
//! apart needs a read node.
//!
//! # Example
//!
//! ```no_run
//! use pilotlight::SequencerClient;
//!
//! # async fn run(signed_tx: Vec<u8>) -> Result<(), pilotlight::Error> {
//! // Resolves the sequencer's addresses and warms a connection to each.
//! let client = SequencerClient::connect().await?;
//!
//! let sent = client.send_raw_transaction(&signed_tx).await?;
//! println!("{} accepted by {} in {:?}", sent.tx_hash, sent.endpoint, sent.latency);
//! # Ok(())
//! # }
//! ```
//!
//! # Tuning
//!
//! ```no_run
//! use std::time::Duration;
//! use pilotlight::SequencerClient;
//!
//! # async fn run() -> Result<(), pilotlight::Error> {
//! let client = SequencerClient::builder()
//!     .conns_per_ip(2)                              // redundancy per address
//!     .fanout(0)                                    // 0 = broadcast to every endpoint
//!     .request_timeout(Duration::from_millis(800))
//!     .probe_interval(Duration::from_secs(10))      // keepalive + latency sampling
//!     .connect()
//!     .await?;
//! # Ok(())
//! # }
//! ```

mod client;
mod config;
mod conn;
mod endpoint;
mod error;
mod pool;
mod request;
mod rpc;
mod tls;
mod types;

pub use client::{ClientBuilder, SequencerClient};
pub use config::{SEQUENCER_HOST, SEQUENCER_PORT};
pub use error::{Error, Result};
pub use rpc::{ConditionalOptions, KnownAccount};
pub use types::{EndpointStats, Submission, TxHash};
