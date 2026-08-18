//! Submit a signed transaction, with every configuration knob spelled out.
//!
//! This crate does not sign. Produce the raw bytes however you like — `alloy`,
//! `ethers`, `cast mktx`, a hardware wallet — and pass the hex in:
//!
//! ```text
//! RAW_TX=0x02f86b... cargo run --release --example send
//! ```
//!
//! Every setting below is left at its default value, so this behaves exactly
//! like `SequencerClient::connect()`. The point is to show what each one
//! controls.

use std::time::Duration;

use pilotlight::{Error, SEQUENCER_HOST, SEQUENCER_PORT, SequencerClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_tx =
        std::env::var("RAW_TX").map_err(|_| "set RAW_TX to a 0x-prefixed signed transaction")?;

    let client = SequencerClient::builder()
        // Where to submit. Also used for TLS SNI and the HTTP/2 `:authority`
        // pseudo-header, so this is what the server certificate is validated
        // against.
        .host(SEQUENCER_HOST)
        .port(SEQUENCER_PORT)
        // Warm connections held open per endpoint address.
        //
        // Redundancy, not throughput: HTTP/2 already multiplexes any number of
        // concurrent submissions over a single connection. A second connection
        // matters when the first is torn down — a GOAWAY, an idle reap, a
        // broken socket — so a submission does not have to fall back to
        // another endpoint.
        .conns_per_ip(2)
        // How many endpoints each transaction is broadcast to at once, with
        // the first usable answer winning.
        //
        // `0` means every endpoint the pool knows about, whatever DNS returns.
        // Broadcasting duplicates cannot include the transaction twice — the
        // nonce is fixed by the signature — and the copies that lose the race
        // are answered `nonce too low`, which the client discards in favour of
        // the copy that succeeded.
        .fanout(0)
        // Budget for one TCP connect plus TLS handshake. Off the hot path,
        // since connections are warmed in the background. `connect()` below
        // waits up to twice this value for the first connection to come up.
        .connect_timeout(Duration::from_secs(3))
        // Budget for a whole submission, measured across the entire fan-out
        // rather than per endpoint.
        .request_timeout(Duration::from_secs(5))
        // How often each connection issues an `rpc_modules` probe.
        //
        // Two jobs: it keeps intermediate load balancers from reaping the
        // connection as idle, and it supplies the latency sample used to rank
        // endpoints so the fastest healthy one is preferred. `Duration::ZERO`
        // turns probing off.
        .probe_interval(Duration::from_secs(15))
        // How often the hostname is re-resolved and the endpoint set
        // reconciled.
        //
        // The A records carry a 60 s TTL and do rotate, so this stays well
        // under it. Surviving endpoints keep their warm connections, and a
        // failed lookup leaves the current set alone. `Duration::ZERO` resolves
        // once at startup and never again.
        .dns_refresh_interval(Duration::from_secs(30))
        // HTTP/2 PING cadence. These run even while the connection is idle,
        // which is its normal state here.
        .h2_ping_interval(Duration::from_secs(10))
        // How long a PING may go unacknowledged before the connection is
        // declared dead and the supervisor rebuilds it.
        .h2_ping_timeout(Duration::from_secs(5))
        // Delay before the first reconnect attempt after a connection drops.
        // It doubles after each consecutive failure.
        .reconnect_min_backoff(Duration::from_millis(100))
        // Ceiling for that doubling. A sustained outage keeps retrying at this
        // interval instead of drifting out to minutes.
        .reconnect_max_backoff(Duration::from_secs(5))
        // Value sent in the `user-agent` header.
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        // Build the client, start warming connections, and wait for the first
        // one. Use `build()` instead to return immediately and drive readiness
        // yourself with `wait_until_ready`.
        .connect()
        .await?;

    match client.send_raw_transaction_hex(&raw_tx).await {
        Ok(sent) => {
            println!("hash     {}", sent.tx_hash);
            println!("endpoint {} (won a race of {})", sent.endpoint, sent.fanout);
            println!("latency  {:.2?}", sent.latency);
        }
        // Every copy of the transaction was refused and none succeeded, so
        // this is the sequencer's verdict on these bytes rather than one
        // copy losing the race to another.
        Err(e @ Error::Rejected { .. }) => {
            eprintln!("rejected: {e}");
        }
        // Delivery failed below the JSON-RPC layer. Whether the transaction
        // reached the sequencer is unknown. Resending the same bytes cannot
        // include it twice, since the nonce is fixed by the signature.
        Err(e) if e.is_retryable() => {
            eprintln!("not delivered, safe to retry: {e}");
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
