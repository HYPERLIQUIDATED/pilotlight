//! JSON-RPC payload construction and response parsing.
//!
//! The submit payload is hand-rolled rather than built through `serde_json`:
//! the shape is fixed, so the whole body is one exact-capacity allocation plus
//! a hex encode, with no intermediate `Value` tree.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::TxHash;

/// Fixed fragments of the two submit payloads. The hex-encoded transaction is
/// written between them, so a body costs one allocation and one hex pass.
const SEND_PREFIX: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x"#;
const SEND_SUFFIX: &[u8] = br#""]}"#;

const COND_PREFIX: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransactionConditional","params":["0x"#;
const COND_MID: &[u8] = br#"","#;
const COND_SUFFIX: &[u8] = br"]}";

/// Cheap no-argument method used as a keepalive and latency probe.
///
/// This sequencer exposes no read methods at all — `eth_chainId`,
/// `eth_blockNumber` and friends all return -32601 — but `rpc_modules` is
/// answered, which makes it the only viable end-to-end health check.
pub(crate) const PING_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"rpc_modules","params":[]}"#;

/// Build the body for `eth_sendRawTransaction`.
///
/// A single allocation sized exactly to the final payload.
pub(crate) fn send_raw_body(raw: &[u8]) -> bytes::Bytes {
    let mut buf = BytesMut::with_capacity(SEND_PREFIX.len() + raw.len() * 2 + SEND_SUFFIX.len());
    buf.put_slice(SEND_PREFIX);
    put_hex(&mut buf, raw);
    buf.put_slice(SEND_SUFFIX);
    buf.freeze()
}

/// Build the body for `eth_sendRawTransactionConditional`.
pub(crate) fn send_raw_conditional_body(
    raw: &[u8],
    opts: &ConditionalOptions,
) -> Result<bytes::Bytes> {
    let opts_json = serde_json::to_vec(opts)
        .map_err(|e| Error::Config(format!("cannot serialize the conditional options: {e}")))?;

    let mut buf = BytesMut::with_capacity(
        COND_PREFIX.len() + raw.len() * 2 + COND_MID.len() + opts_json.len() + COND_SUFFIX.len(),
    );
    buf.put_slice(COND_PREFIX);
    put_hex(&mut buf, raw);
    buf.put_slice(COND_MID);
    buf.put_slice(&opts_json);
    buf.put_slice(COND_SUFFIX);
    Ok(buf.freeze())
}

/// Hex-encode straight into the output buffer, no intermediate `String`.
fn put_hex(buf: &mut BytesMut, raw: &[u8]) {
    let start = buf.len();
    buf.resize(start + raw.len() * 2, 0);
    const_hex::encode_to_slice(raw, &mut buf[start..])
        .expect("output slice is exactly 2x input length");
}

#[derive(Deserialize)]
struct Envelope {
    result: Option<String>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

/// Whether an error code is the sequencer's verdict on the transaction rather
/// than a report about the call.
///
/// JSON-RPC reserves `-32000` to `-32099` for implementation-defined server
/// errors, and EIP-1474 assigns meanings within it: `-32003` names a refused
/// transaction, and Nitro uses `-32000` for one. The rest of the space
/// describes the request or the server's ability to serve it, and an
/// unrecognised code establishes nothing — reading it as a verdict would have
/// the caller abandon a transaction that may never have been read.
fn is_transaction_verdict(code: i64) -> bool {
    matches!(code, -32000 | -32003)
}

/// Interpret a sequencer response to a submit call.
///
/// `expected` is the hash computed from the bytes that were sent. A successful
/// response carries the hash the sequencer assigned, and the two must agree:
/// anything else means the answer describes some other transaction, or came
/// from something that is not this sequencer.
pub(crate) fn parse_send_response(ip: IpAddr, body: &[u8], expected: TxHash) -> Result<()> {
    let env: Envelope = serde_json::from_slice(body).map_err(|e| Error::BadResponse {
        ip,
        message: format!("{e} (body: {})", truncate(body, 256)),
    })?;

    if let Some(err) = env.error {
        return Err(if is_transaction_verdict(err.code) {
            Error::Rejected {
                code: err.code,
                message: err.message,
            }
        } else {
            Error::Rpc {
                code: err.code,
                message: err.message,
            }
        });
    }

    match env.result {
        Some(hash) => match hash.parse::<TxHash>() {
            Ok(returned) if returned == expected => Ok(()),
            Ok(returned) => Err(Error::BadResponse {
                ip,
                message: format!("accepted {returned} but {expected} was submitted"),
            }),
            Err(e) => Err(Error::BadResponse {
                ip,
                message: format!("`result` is not a transaction hash: {e} (got {hash})"),
            }),
        },
        None => Err(Error::BadResponse {
            ip,
            message: format!(
                "response had neither `result` nor `error` (body: {})",
                truncate(body, 256)
            ),
        }),
    }
}

/// Lossily render the head of a response body for an error message.
fn truncate(body: &[u8], max: usize) -> String {
    let s = String::from_utf8_lossy(&body[..body.len().min(max)]);
    if body.len() > max {
        format!("{s}…")
    } else {
        s.into_owned()
    }
}

/// Constraints for `eth_sendRawTransactionConditional`.
///
/// The sequencer checks every constraint before ordering the transaction and
/// refuses it outright if one does not hold, rather than including it against
/// state that has moved. The refusal is explicit — `Storage slot value
/// condition not met`, `BlockNumberMax condition not met` — and arrives as
/// [`Error::Rejected`], leaving the nonce unconsumed. All fields are optional;
/// an empty value means "no constraint".
///
/// Addresses and hashes are passed as `0x`-prefixed strings, so this stays free
/// of any address type dependency.
///
/// Storage roots, slot keys and slot values are widened to a full 32 bytes on
/// insertion. Nitro decodes them into Go's `common.Hash` and rejects anything
/// shorter, so writing slot `0x0` unpadded would otherwise come back as
/// `cannot unmarshal hex string of odd length`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalOptions {
    /// Per-account storage expectations, keyed by `0x`-prefixed address.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub known_accounts: BTreeMap<String, KnownAccount>,

    /// Earliest parent-chain block the transaction may be included in.
    ///
    /// Counted on the parent chain, not on this one. `eth_blockNumber` against
    /// a Robinhood RPC node returns the L2 height, which runs roughly an order
    /// of magnitude ahead, so a bound derived from it is far above anything
    /// the parent chain will reach and the constraint silently never binds.
    /// Take the value from `l1BlockNumber` on a block instead.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_quantity"
    )]
    pub block_number_min: Option<u64>,

    /// Latest parent-chain block the transaction may be included in.
    ///
    /// Counted on the parent chain; see [`ConditionalOptions::block_number_min`]
    /// for why an L2-derived bound never binds.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_quantity"
    )]
    pub block_number_max: Option<u64>,

    /// Earliest block timestamp, as a Unix second count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_min: Option<u64>,

    /// Latest block timestamp, as a Unix second count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_max: Option<u64>,
}

impl ConditionalOptions {
    /// An empty constraint set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Require an account's whole storage root to match `root`.
    #[must_use]
    pub fn with_storage_root(
        mut self,
        address: impl Into<String>,
        root: impl Into<String>,
    ) -> Self {
        self.known_accounts.insert(
            address.into(),
            KnownAccount::StorageRoot(pad_hash(&root.into())),
        );
        self
    }

    /// Require a specific storage slot of an account to hold `value`.
    ///
    /// Repeated calls for the same address accumulate slots.
    #[must_use]
    pub fn with_storage_slot(
        mut self,
        address: impl Into<String>,
        slot: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        let entry = self
            .known_accounts
            .entry(address.into())
            .or_insert_with(|| KnownAccount::Slots(BTreeMap::new()));
        // A slot constraint and a whole-root constraint are mutually exclusive;
        // the most recent call wins.
        if matches!(entry, KnownAccount::StorageRoot(_)) {
            *entry = KnownAccount::Slots(BTreeMap::new());
        }
        if let KnownAccount::Slots(slots) = entry {
            slots.insert(pad_hash(&slot.into()), pad_hash(&value.into()));
        }
        self
    }

    /// Restrict inclusion to a parent-chain block range.
    ///
    /// Both bounds are parent-chain heights. Deriving them from
    /// `eth_blockNumber`, which reports the L2 height, produces a constraint
    /// that never binds.
    #[must_use]
    pub fn with_block_range(mut self, min: Option<u64>, max: Option<u64>) -> Self {
        self.block_number_min = min;
        self.block_number_max = max;
        self
    }

    /// Restrict inclusion to a timestamp range, in Unix seconds.
    #[must_use]
    pub fn with_timestamp_range(mut self, min: Option<u64>, max: Option<u64>) -> Self {
        self.timestamp_min = min;
        self.timestamp_max = max;
        self
    }
}

/// A storage expectation for one account.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum KnownAccount {
    /// The account's entire storage root must equal this hash.
    StorageRoot(String),
    /// These individual slots must hold these values.
    Slots(BTreeMap<String, String>),
}

/// Widen a hex string to the 32 bytes Nitro's `common.Hash` decoder requires.
///
/// Anything that is not plain `0x`-prefixed hex of at most 32 bytes is passed
/// through untouched, so a genuinely malformed value still surfaces as a
/// server-side error rather than being silently reshaped into a valid-looking
/// but wrong one.
fn pad_hash(value: &str) -> String {
    let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return value.to_string();
    };
    if digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return value.to_string();
    }
    format!("0x{:0>64}", digits.to_ascii_lowercase())
}

/// JSON-RPC encodes block numbers as minimal hex quantities.
///
/// The `&Option<u64>` signature is dictated by serde's `serialize_with`
/// contract, which always hands over a reference to the field itself; taking
/// `Option<&u64>` would simply not compile here.
#[allow(
    clippy::ref_option,
    reason = "signature is fixed by serde's serialize_with"
)]
fn ser_opt_quantity<S: serde::Serializer>(
    v: &Option<u64>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match v {
        Some(n) => s.serialize_str(&format!("0x{n:x}")),
        None => s.serialize_none(),
    }
}
