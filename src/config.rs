use std::{fmt, time::Duration};

use crate::ConnectError;

pub struct Config {
    pub endpoints: Vec<String>,
    pub connections_per_ip: usize,
    pub reset_stream_capacity: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub reconnect_min_delay: Duration,
    pub reconnect_max_delay: Duration,
    pub dns_refresh_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            connections_per_ip: 4,
            reset_stream_capacity: 4096,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            reconnect_min_delay: Duration::from_millis(100),
            reconnect_max_delay: Duration::from_secs(5),
            dns_refresh_interval: Duration::from_secs(30),
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("endpoints", &self.endpoints.len())
            .field("connections_per_ip", &self.connections_per_ip)
            .field("reset_stream_capacity", &self.reset_stream_capacity)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("reconnect_min_delay", &self.reconnect_min_delay)
            .field("reconnect_max_delay", &self.reconnect_max_delay)
            .field("dns_refresh_interval", &self.dns_refresh_interval)
            .finish()
    }
}

impl Config {
    pub(crate) fn validate(&self) -> Result<(), ConnectError> {
        if self.endpoints.is_empty() {
            return Err(ConnectError::InvalidConfig("No endpoints configured"));
        }

        if self.connections_per_ip == 0 {
            return Err(ConnectError::InvalidConfig(
                "Connections per IP must be positive",
            ));
        }

        if self.reset_stream_capacity == 0 {
            return Err(ConnectError::InvalidConfig(
                "Reset stream capacity must be positive",
            ));
        }

        if self.reconnect_min_delay > self.reconnect_max_delay {
            return Err(ConnectError::InvalidConfig(
                "Minimum reconnect delay must not exceed maximum reconnect delay",
            ));
        }

        if [
            self.connect_timeout,
            self.request_timeout,
            self.reconnect_min_delay,
            self.reconnect_max_delay,
            self.dns_refresh_interval,
        ]
        .into_iter()
        .any(|duration| {
            duration.is_zero() || tokio::time::Instant::now().checked_add(duration).is_none()
        }) {
            return Err(ConnectError::InvalidConfig(
                "Timeouts and maintenance intervals must be positive and representable",
            ));
        }

        Ok(())
    }
}
