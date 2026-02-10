use crate::config::models::JokowayConfig;
use crate::prelude::*;
use crate::server::context::AppCtx;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[async_trait::async_trait]
pub trait DnsResolveImpl: Send + Sync {
    async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

struct HickoryDnsResolver {
    resolver: Arc<TokioAsyncResolver>,
}

#[async_trait::async_trait]
impl DnsResolveImpl for HickoryDnsResolver {
    async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        match self.resolver.lookup_ip(host).await {
            Ok(lookup) => Ok(lookup.iter().collect()),
            Err(e) => Err(e.to_string()),
        }
    }
}

impl HickoryDnsResolver {
    fn new(config: &JokowayConfig) -> Self {
        let dns_settings = config.dns.as_ref();
        let mut opts = ResolverOpts::default();
        let resolver_config = if let Some(dns) = dns_settings {
            let mut conf = ResolverConfig::new();
            if let Some(nameservers) = &dns.nameservers {
                for ns in nameservers {
                    let socket = if let Ok(socket) = ns.parse::<SocketAddr>() {
                        socket
                    } else if let Ok(ip) = ns.parse::<IpAddr>() {
                        SocketAddr::new(ip, 53)
                    } else {
                        log::warn!("Invalid nameserver: {}", ns);
                        continue;
                    };
                    conf.add_name_server(NameServerConfig::new(socket, Protocol::Udp));
                    conf.add_name_server(NameServerConfig::new(socket, Protocol::Tcp));
                }
            } else {
                // Fallback to Google if dns settings present but empty nameservers (though usually implies just use defaults, but we'll stick to google for consistency with previous impl)
                conf = ResolverConfig::google();
            }

            if let Some(timeout) = dns.timeout {
                opts.timeout = Duration::from_secs(timeout);
            }
            if let Some(attempts) = dns.attempts {
                opts.attempts = attempts;
            }
            if let Some(strategy) = &dns.strategy {
                opts.ip_strategy = match strategy.as_str() {
                    "ipv4_only" => LookupIpStrategy::Ipv4Only,
                    "ipv6_only" => LookupIpStrategy::Ipv6Only,
                    "ipv4_then_ipv6" => LookupIpStrategy::Ipv4thenIpv6,
                    "ipv6_then_ipv4" => LookupIpStrategy::Ipv6thenIpv4,
                    _ => {
                        log::warn!(
                            "Invalid DNS strategy '{}', defaulting to Ipv4thenIpv6",
                            strategy
                        );
                        LookupIpStrategy::Ipv4thenIpv6
                    }
                };
            }
            if let Some(cache_size) = dns.cache_size {
                opts.cache_size = cache_size;
            }
            opts.use_hosts_file = dns.use_hosts_file;

            conf
        } else {
            // Default config (Google DNS)
            ResolverConfig::google()
        };

        let resolver = TokioAsyncResolver::tokio(resolver_config, opts);
        Self {
            resolver: Arc::new(resolver),
        }
    }
}

pub struct MockDnsResolver {
    pub ips: std::collections::HashMap<String, Vec<IpAddr>>,
}

#[async_trait::async_trait]
impl DnsResolveImpl for MockDnsResolver {
    async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        if let Some(ips) = self.ips.get(host) {
            Ok(ips.clone())
        } else {
            Err(format!("Mock DNS: Host {} not found", host))
        }
    }
}

#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<dyn DnsResolveImpl>,
}

impl DnsResolver {
    pub fn new(config: &JokowayConfig) -> Self {
        Self {
            inner: Arc::new(HickoryDnsResolver::new(config)),
        }
    }

    pub fn new_mock(ips: std::collections::HashMap<String, Vec<IpAddr>>) -> Self {
        Self {
            inner: Arc::new(MockDnsResolver { ips }),
        }
    }

    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        self.inner.lookup_ip(host).await
    }
}

pub struct DnsExtension;

impl JokowayExtension for DnsExtension {
    fn init(
        &self,
        _server: &mut pingora::server::Server,
        app_ctx: &mut AppCtx,
        _http_middlewares: &mut Vec<std::sync::Arc<dyn HttpMiddlewareDyn>>,
        _websocket_middlewares: &mut Vec<
            std::sync::Arc<dyn crate::prelude::WebsocketMiddlewareDyn>,
        >,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(config) = app_ctx.get::<JokowayConfig>() {
            let resolver = DnsResolver::new(&config);
            app_ctx.insert(resolver);
            log::info!("DNS Resolver initialized");
        } else {
            log::warn!("JokowayConfig not found in AppCtx during DnsExtension init");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::DnsSettings;

    #[test]
    fn test_dns_config_parsing() {
        let config = JokowayConfig {
            dns: Some(DnsSettings {
                nameservers: Some(vec!["1.1.1.1".to_string()]),
                timeout: Some(10),
                attempts: Some(3),
                strategy: Some("ipv6_only".to_string()),
                cache_size: Some(100),
                use_hosts_file: false,
            }),
            ..Default::default()
        };

        // We can't easily inspect the internal state of ResolverOpts from the Arc<TokioAsyncResolver>
        // But we can ensure that new() runs without panic and creates a resolver.
        let _resolver = DnsResolver::new(&config);

        // Test invalid strategy fallback
        let config_invalid = JokowayConfig {
            dns: Some(DnsSettings {
                nameservers: None,
                timeout: None,
                attempts: None,
                strategy: Some("invalid_strategy".to_string()),
                cache_size: None,
                use_hosts_file: true,
            }),
            ..Default::default()
        };
        let _resolver_invalid = DnsResolver::new(&config_invalid);
    }
}
