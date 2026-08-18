//! Client configuration.
//!
//! [`Config`] is internal: [`ClientBuilder`](crate::ClientBuilder) is the only
//! way to set any of it, so every setting has exactly one public name and
//! adding one here is never a breaking change. The prose describing what each
//! setting does lives on the corresponding builder method.

use std::time::Duration;

/// Hostname of the Robinhood mainnet sequencer.
pub const SEQUENCER_HOST: &str = "sequencer.mainnet.chain.robinhood.com";

/// TLS port.
pub const SEQUENCER_PORT: u16 = 443;

/// Resolved settings for one client.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// DNS name, TLS SNI, and HTTP/2 `:authority`.
    pub(crate) host: String,
    /// TLS port.
    pub(crate) port: u16,
    /// Interval between endpoint-set reconciliations; zero resolves once.
    pub(crate) dns_refresh_interval: Duration,
    /// Warm connections per endpoint address.
    pub(crate) conns_per_ip: usize,
    /// Endpoints per submission; zero means all of them.
    pub(crate) fanout: usize,
    /// TCP connect plus TLS handshake budget.
    pub(crate) connect_timeout: Duration,
    /// Budget for one submission across the whole fan-out.
    pub(crate) request_timeout: Duration,
    /// Interval between `rpc_modules` probes; zero disables them.
    pub(crate) probe_interval: Duration,
    /// HTTP/2 PING interval.
    pub(crate) h2_ping_interval: Duration,
    /// Deadline for a PING acknowledgement.
    pub(crate) h2_ping_timeout: Duration,
    /// Delay before the first reconnect attempt.
    pub(crate) reconnect_min_backoff: Duration,
    /// Ceiling for the reconnect backoff.
    pub(crate) reconnect_max_backoff: Duration,
    /// `user-agent` header value.
    pub(crate) user_agent: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: SEQUENCER_HOST.to_string(),
            port: SEQUENCER_PORT,
            dns_refresh_interval: Duration::from_secs(30),
            conns_per_ip: 2,
            fanout: 0,
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(5),
            probe_interval: Duration::from_secs(15),
            h2_ping_interval: Duration::from_secs(10),
            h2_ping_timeout: Duration::from_secs(5),
            reconnect_min_backoff: Duration::from_millis(100),
            reconnect_max_backoff: Duration::from_secs(5),
            user_agent: concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")).to_string(),
        }
    }
}

impl Config {
    /// Reject configurations that cannot produce a working client.
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self.host.is_empty() {
            return Err(crate::Error::Config("host must not be empty".into()));
        }
        if self.conns_per_ip == 0 {
            return Err(crate::Error::Config(
                "conns_per_ip must be at least 1".into(),
            ));
        }
        if self.request_timeout.is_zero() {
            return Err(crate::Error::Config(
                "request_timeout must be non-zero".into(),
            ));
        }
        if self.connect_timeout.is_zero() {
            return Err(crate::Error::Config(
                "connect_timeout must be non-zero".into(),
            ));
        }
        // Resolving is not a validator: a name DNS answers for can still be
        // rejected as a TLS server name, and that failure happens inside the
        // supervisor, where it would only surface as a client that never
        // becomes ready while retrying something that cannot succeed.
        if rustls_pki_types::ServerName::try_from(self.host.clone()).is_err() {
            return Err(crate::Error::Config(format!(
                "`{}` is not a valid TLS server name",
                self.host
            )));
        }
        if self.reconnect_min_backoff > self.reconnect_max_backoff {
            return Err(crate::Error::Config(
                "reconnect_min_backoff must not exceed reconnect_max_backoff".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn the_defaults_are_usable() {
        assert!(Config::default().validate().is_ok());
    }

    /// The ceiling clamps every doubling, so a floor above it pins the delay
    /// at the ceiling from the first attempt and the backoff never grows.
    /// A client configured that way reconnects at a fixed rate, and neither
    /// the logs nor the endpoint statistics say why.
    #[test]
    fn a_backoff_floor_above_its_ceiling_is_rejected() {
        let cfg = Config {
            reconnect_min_backoff: Duration::from_secs(10),
            reconnect_max_backoff: Duration::from_secs(5),
            ..Config::default()
        };
        assert!(matches!(cfg.validate(), Err(Error::Config(_))));

        let equal = Config {
            reconnect_min_backoff: Duration::from_secs(5),
            reconnect_max_backoff: Duration::from_secs(5),
            ..Config::default()
        };
        assert!(
            equal.validate().is_ok(),
            "equal bounds are a fixed delay, not an error"
        );
    }

    /// Resolution is not a validator. These parse as URI authorities and some
    /// of them even resolve, but none can be used as a TLS server name, and
    /// that failure happens inside the supervisor — where it would surface
    /// only as a client that never becomes ready while retrying something that
    /// cannot succeed.
    #[test]
    fn a_host_that_cannot_be_a_tls_server_name_is_rejected() {
        for host in [
            "example..com",
            "-leading.example.com",
            "trailing-.example.com",
            "256.256.256.256",
            "host~tilde",
            "",
        ] {
            let cfg = Config {
                host: host.to_string(),
                ..Config::default()
            };
            assert!(
                matches!(cfg.validate(), Err(Error::Config(_))),
                "`{host}` should not build a client"
            );
        }
    }

    #[test]
    fn ordinary_hosts_and_addresses_are_accepted() {
        for host in [
            SEQUENCER_HOST,
            "localhost",
            "1.2.3.4",
            "under_score.example.com",
        ] {
            let cfg = Config {
                host: host.to_string(),
                ..Config::default()
            };
            assert!(cfg.validate().is_ok(), "`{host}` should build a client");
        }
    }
}
