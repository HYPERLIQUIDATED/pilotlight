//! TLS setup.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

use crate::error::{Error, Result};

/// Build the shared rustls config for all sequencer connections.
///
/// The crypto provider is passed explicitly rather than read from rustls'
/// process-global slot, so embedding this crate can never fight with whatever
/// the host application installed.
pub(crate) fn client_config() -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            Error::Config(format!(
                "the TLS provider supports none of the required protocol versions: {e}"
            ))
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();

    // h2 alone. This crate has no HTTP/1.1 code path, so advertising it as a
    // fallback would invite a downgrade that cannot be served.
    cfg.alpn_protocols = vec![b"h2".to_vec()];

    // Cache tickets so a reconnect resumes in one round trip instead of two.
    // Reconnects happen off the hot path, but a faster one narrows the window
    // in which an endpoint is unavailable.
    cfg.resumption = rustls::client::Resumption::in_memory_sessions(64);

    Ok(Arc::new(cfg))
}
