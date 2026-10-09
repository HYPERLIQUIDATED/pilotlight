use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::B256;
use bytes::Bytes;
use jsonrpsee_types::{Id, Request, Response, ResponsePayload};

use crate::{BroadcastError, FailureKind};

pub(crate) fn encode_request(
    raw: alloy_primitives::Bytes,
) -> Result<(Bytes, B256), BroadcastError> {
    let hash = *TxEnvelope::decode_2718_exact(&raw)
        .map_err(|_| BroadcastError::InvalidTransaction)?
        .tx_hash();
    let params =
        serde_json::value::to_raw_value(&[raw]).expect("Serializing signed bytes is infallible");
    let request = Request::borrowed("eth_sendRawTransaction", Some(&params), Id::Number(1));
    let body = serde_json::to_vec(&request)
        .expect("Serializing an RPC request is infallible")
        .into();

    Ok((body, hash))
}

pub(crate) fn decode_response(body: &[u8], expected_hash: B256) -> Result<(), FailureKind> {
    let response: Response<'_, B256> =
        serde_json::from_slice(body).map_err(|_| FailureKind::InvalidResponse)?;

    if response.jsonrpc.is_none() || response.id != Id::Number(1) {
        return Err(FailureKind::InvalidResponse);
    }

    match response.payload {
        ResponsePayload::Success(hash) if *hash == expected_hash => Ok(()),
        ResponsePayload::Error(error) => Err(FailureKind::Rpc(i64::from(error.code()))),
        ResponsePayload::Success(_) => Err(FailureKind::InvalidResponse),
    }
}
