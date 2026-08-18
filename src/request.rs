//! Pre-built HTTP request scaffolding.
//!
//! Everything that does not change between submissions — the URI and the
//! `user-agent` header value — is parsed once at construction. Building a
//! request on the hot path is then a handful of refcount bumps.

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};
use http::{HeaderValue, Method, Request, Uri};
use http_body_util::Full;

use crate::config::Config;
use crate::error::{Error, Result};

/// Reusable request skeleton for one sequencer host.
#[derive(Clone)]
pub(crate) struct RequestTemplate {
    /// Absolute `https://host[:port]/` URI, source of the `:scheme`,
    /// `:authority` and `:path` pseudo-headers.
    uri: Uri,
    /// Pre-parsed `user-agent` value, cloned per request.
    user_agent: HeaderValue,
}

impl RequestTemplate {
    /// Parse the per-host constants once.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] if `host` and `port` do not form a valid URI, or if
    /// `user_agent` contains bytes a header value cannot hold.
    pub(crate) fn new(cfg: &Config) -> Result<Self> {
        let authority = if cfg.port == 443 {
            cfg.host.clone()
        } else {
            format!("{}:{}", cfg.host, cfg.port)
        };

        let uri: Uri = format!("https://{authority}/")
            .parse()
            .map_err(|e| Error::Config(format!("cannot build URI for `{authority}`: {e}")))?;

        let user_agent = HeaderValue::from_str(&cfg.user_agent)
            .map_err(|e| Error::Config(format!("user_agent is not a valid header value: {e}")))?;

        Ok(Self { uri, user_agent })
    }

    /// Wrap a JSON-RPC body in a ready-to-send request.
    ///
    /// The absolute URI supplies HTTP/2's `:scheme` and `:authority`
    /// pseudo-headers, so no separate `host` header is sent.
    pub(crate) fn build(&self, body: Bytes) -> Request<Full<Bytes>> {
        let mut req = Request::new(Full::new(body));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = self.uri.clone();

        let headers = req.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(USER_AGENT, self.user_agent.clone());

        req
    }
}
