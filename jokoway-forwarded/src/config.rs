use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;
use jokoway_core::config::JokowayConfig;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Configuration settings for the HTTP Forwarded middleware.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForwardedSettings {
    /// Whether the middleware is enabled. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// List of trusted proxy CIDR ranges (IPv4 and IPv6).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for ForwardedSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_proxies: Vec::new(),
        }
    }
}

/// Pre-parsed CIDR ranges for efficient IP lookup.
pub struct TrustedProxies {
    v4: IpRange<Ipv4Net>,
    v6: IpRange<Ipv6Net>,
}

impl TrustedProxies {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.v4.contains(v4),
            IpAddr::V6(v6) => self.v6.contains(v6),
        }
    }
}

impl ForwardedSettings {
    /// Parse the `trusted_proxies` string list into typed CIDR ranges.
    /// Invalid entries are logged and skipped.
    pub fn build_trusted_proxies(&self) -> TrustedProxies {
        let mut v4 = IpRange::<Ipv4Net>::new();
        let mut v6 = IpRange::<Ipv6Net>::new();

        for cidr in &self.trusted_proxies {
            let trimmed = cidr.trim();
            // Try IPv4 first, then IPv6
            if let Ok(net) = trimmed.parse::<Ipv4Net>() {
                v4.add(net);
            } else if let Ok(net) = trimmed.parse::<Ipv6Net>() {
                v6.add(net);
            } else {
                log::warn!("Invalid trusted_proxies CIDR '{}', skipping.", trimmed);
            }
        }

        v4.simplify();
        v6.simplify();
        TrustedProxies { v4, v6 }
    }
}

pub trait ForwardedConfigExt {
    fn http_forwarded(&self) -> Option<ForwardedSettings>;
}

impl ForwardedConfigExt for JokowayConfig {
    fn http_forwarded(&self) -> Option<ForwardedSettings> {
        self.extra
            .get("http_forwarded")
            .and_then(|v| match serde_yaml::from_value(v.clone()) {
                Ok(s) => Some(s),
                Err(e) => {
                    log::error!("Failed to deserialize http_forwarded settings: {}", e);
                    None
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_trusted_proxies() {
        let settings = ForwardedSettings {
            trusted_proxies: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "::1/128".to_string(),
            ],
            ..Default::default()
        };
        let tp = settings.build_trusted_proxies();
        assert!(tp.contains(&"10.0.0.1".parse().unwrap()));
        assert!(tp.contains(&"172.16.5.1".parse().unwrap()));
        assert!(!tp.contains(&"8.8.8.8".parse().unwrap()));
        assert!(tp.contains(&"::1".parse().unwrap()));
        assert!(!tp.contains(&"::2".parse().unwrap()));
    }

    #[test]
    fn test_empty_trusted_proxies() {
        let settings = ForwardedSettings::default();
        let tp = settings.build_trusted_proxies();
        assert!(tp.is_empty());
        assert!(!tp.contains(&"10.0.0.1".parse().unwrap()));
    }
}
