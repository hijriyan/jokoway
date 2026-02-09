use crate::config::models::JokowayConfig;
use crate::error::JokowayError;
use crate::extensions::dns::DnsResolver;
use crate::server::context::AppCtx;
use crate::server::discovery::JokowayUpstreamDiscovery;
use crate::server::proxy::{CachedPeerConfig, merge_peer_options};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use pingora::lb::Backends;
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{LoadBalancer, selection::RoundRobin};
use pingora::server::ShutdownWatch;
use pingora::services::background::{BackgroundService, GenBackgroundService};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub struct LbWrapper {
    pub lb: Arc<LoadBalancer<RoundRobin>>,
    pub cancellation_token: CancellationToken,
}

#[async_trait]
impl BackgroundService for LbWrapper {
    async fn start(&self, shutdown: ShutdownWatch) {
        // Create a local watch channel to control the inner lb.start() lifecycle
        let (tx, rx) = tokio::sync::watch::channel(false);

        // 1. Start Pingora's LB background task (Health Checks) in a separate task
        // We wrap it in a spawn so it doesn't block OUR keep-alive loop if it exits early
        // (which happens when no health checks are configured).
        let lb = self.lb.clone();
        tokio::spawn(async move {
            lb.start(rx).await;
        });

        // 2. Run our keep-alive loop to ensure the service wrapper stays active
        let token = self.cancellation_token.clone();
        let mut global_shutdown = shutdown.clone();

        tokio::select! {
            _ = token.cancelled() => {
                log::debug!("Upstream service cancelled via token");
                let _ = tx.send(true); // Signal inner lb to stop
            }
            _ = global_shutdown.changed() => {
                log::debug!("Upstream service shutting down via signal");
                let _ = tx.send(true); // Signal inner lb to stop
            }
        }
    }
}

pub type LbBackgroundService = GenBackgroundService<LbWrapper>;

fn compile_upstream(
    upstream: &crate::config::models::Upstream,
    dns_resolver: Arc<DnsResolver>,
) -> Result<Arc<LoadBalancer<RoundRobin>>, JokowayError> {
    if upstream.servers.is_empty() {
        return Err(JokowayError::Upstream(
            "Cannot create load balancer with no servers".into(),
        ));
    }

    // Create server config tuples
    let mut server_configs = Vec::with_capacity(upstream.servers.len());
    for server in &upstream.servers {
        let mut merged_options =
            merge_peer_options(upstream.peer_options.as_ref(), server.peer_options.as_ref());

        // Smart SNI Fallback
        if merged_options.sni.is_none() {
            let host_only = server.host.split(':').next().unwrap_or(&server.host);
            if host_only.parse::<std::net::IpAddr>().is_err() {
                merged_options.sni = Some(host_only.to_string());
                log::debug!(
                    "Automatically setting SNI to '{}' for upstream {}",
                    host_only,
                    upstream.name
                );
            }
        }

        // Determine TLS based on config or port 443 (if not specified)
        let is_tls = server.tls.unwrap_or_else(|| {
            let port_part = server.host.split(':').nth(1);
            port_part == Some("443")
        });

        match CachedPeerConfig::new(merged_options, is_tls) {
            Ok(cached_config) => {
                server_configs.push((server.clone(), cached_config));
            }
            Err(e) => {
                return Err(JokowayError::Upstream(format!(
                    "Failed to create cached peer config for {}: {}",
                    server.host, e
                )));
            }
        }
    }

    if server_configs.is_empty() {
        return Err(JokowayError::Upstream(
            "No valid server configs for upstream".into(),
        ));
    }

    // Use Box for discovery as required by Backends
    let discovery: Box<dyn ServiceDiscovery + Send + Sync> =
        Box::new(JokowayUpstreamDiscovery::new(server_configs, dns_resolver));
    let backends = Backends::new(discovery);
    let mut load_balancer = LoadBalancer::from_backends(backends);
    load_balancer.update_frequency = Some(Duration::from_secs(15));
    // Configure health check if specified
    if let Some(hc_config) = &upstream.health_check {
        use crate::server::health::create_health_check;
        use std::time::Duration;

        let health_check = create_health_check(hc_config);
        load_balancer.set_health_check(health_check);
        load_balancer.health_check_frequency = Some(Duration::from_secs(hc_config.interval));

        log::info!(
            "Configured {:?} health check for upstream '{}' (interval: {}s, timeout: {}s)",
            hc_config.check_type,
            upstream.name,
            hc_config.interval,
            hc_config.timeout
        );
    }

    Ok(Arc::new(load_balancer))
}

fn spawn_upstream_background_task(
    name: String,
    lb: Arc<LoadBalancer<RoundRobin>>,
    token: CancellationToken,
) {
    tokio::spawn(async move {
        log::info!("Starting background task for upstream: {}", name);
        // reference: https://docs.rs/pingora-load-balancing/latest/src/pingora_load_balancing/background.rs.html
        const NEVER: Duration = Duration::from_secs(u32::MAX as u64);
        let mut now = Instant::now();
        // run update and health check once
        let mut next_update = now;
        let mut next_health_check = now;
        loop {
            if token.is_cancelled() {
                log::info!("Background task cancelled for upstream: {}", name);
                break;
            }
            if next_update <= now {
                // TODO: log err
                let _ = lb.update().await;
                next_update = now + lb.update_frequency.unwrap_or(NEVER);
            }

            if next_health_check <= now {
                lb.backends().run_health_check(true).await;
                next_health_check = now + lb.health_check_frequency.unwrap_or(NEVER);
            }

            if lb.update_frequency.is_none() && lb.health_check_frequency.is_none() {
                return;
            }
            let to_wake = std::cmp::min(next_update, next_health_check);
            tokio::time::sleep_until(to_wake.into()).await;
            now = Instant::now();
        }
    });
}

pub struct UpstreamManager {
    pub load_balancers: ArcSwap<HashMap<String, Arc<LoadBalancer<RoundRobin>>>>,
    // Track cancellation tokens for background tasks
    cancellation_tokens: Arc<DashMap<String, CancellationToken>>,
}

impl UpstreamManager {
    pub fn new(app_ctx: &AppCtx) -> Result<(Self, Vec<LbBackgroundService>), JokowayError> {
        let config = app_ctx
            .get::<JokowayConfig>()
            .ok_or_else(|| JokowayError::Config("JokowayConfig not found in AppCtx".into()))?;
        let dns_resolver = app_ctx
            .get::<DnsResolver>()
            .ok_or_else(|| JokowayError::Upstream("DnsResolver not found in AppCtx".into()))?;

        let mut load_balancers = HashMap::with_capacity(config.upstreams.len());
        let mut services: Vec<LbBackgroundService> = Vec::with_capacity(config.upstreams.len());
        let cancellation_tokens = Arc::new(DashMap::with_capacity(config.upstreams.len()));

        // Create load balancers for each upstream
        for upstream in &config.upstreams {
            let lb_arc = match compile_upstream(upstream, dns_resolver.clone()) {
                Ok(lb) => lb,
                Err(e) => {
                    log::warn!("Skipping upstream {}: {}", upstream.name, e);
                    continue;
                }
            };

            load_balancers.insert(upstream.name.clone(), lb_arc.clone());

            // Create cancellation token for this upstream
            let token = CancellationToken::new();
            cancellation_tokens.insert(upstream.name.clone(), token.clone());

            let background = GenBackgroundService::new(
                format!("lb_{}", upstream.name),
                Arc::new(LbWrapper {
                    lb: lb_arc,
                    cancellation_token: token,
                }),
            );
            services.push(background);
        }

        Ok((
            UpstreamManager {
                load_balancers: ArcSwap::from_pointee(load_balancers),
                cancellation_tokens,
            },
            services,
        ))
    }

    pub fn get(&self, name: &str) -> Option<Arc<LoadBalancer<RoundRobin>>> {
        self.load_balancers.load().get(name).cloned()
    }

    /// Manually triggers discovery for all load balancers.
    /// Useful for tests or ensuring initial state before serving.
    pub async fn update_backends(&self) {
        let lbs = self.load_balancers.load();
        for lb in lbs.values() {
            let _ = lb.update().await;
        }
    }

    /// List all upstream names
    pub fn list_upstreams(&self) -> Vec<String> {
        self.load_balancers.load().keys().cloned().collect()
    }

    /// Verify if an upstream exists
    pub fn verify_upstream(&self, name: &str) -> bool {
        self.load_balancers.load().contains_key(name)
    }

    /// Add a new upstream dynamically
    pub async fn add_upstream(
        &self,
        upstream: crate::config::models::Upstream,
        dns_resolver: Arc<DnsResolver>,
    ) -> Result<(), JokowayError> {
        // Check if upstream already exists
        if self.verify_upstream(&upstream.name) {
            return Err(JokowayError::Upstream(format!(
                "Upstream {} already exists",
                upstream.name
            )));
        }

        let lb_arc = compile_upstream(&upstream, dns_resolver.clone())?;

        // Update load balancers map
        self.load_balancers.rcu(|old| {
            let mut next = (**old).clone();
            next.insert(upstream.name.clone(), lb_arc.clone());
            next
        });

        // Trigger initial backend discovery
        let _ = lb_arc.update().await;

        // Spawn background task
        let token = CancellationToken::new();
        self.cancellation_tokens
            .insert(upstream.name.clone(), token.clone());

        spawn_upstream_background_task(upstream.name.clone(), lb_arc.clone(), token);

        log::info!("Added upstream: {}", upstream.name);
        Ok(())
    }

    /// Update an existing upstream
    pub async fn update_upstream(
        &self,
        name: &str,
        upstream: crate::config::models::Upstream,
        dns_resolver: Arc<DnsResolver>,
    ) -> Result<(), JokowayError> {
        // Check if upstream exists
        if !self.verify_upstream(name) {
            return Err(JokowayError::Upstream(format!(
                "Upstream {} does not exist",
                name
            )));
        }

        let lb_arc = compile_upstream(&upstream, dns_resolver.clone())?;

        // Update load balancers map
        self.load_balancers.rcu(|old| {
            let mut next = (**old).clone();
            next.insert(name.to_string(), lb_arc.clone());
            next
        });

        // Trigger initial backend discovery
        let _ = lb_arc.update().await;

        // Cancel old background task if exists
        if let Some((_, old_token)) = self.cancellation_tokens.remove(name) {
            old_token.cancel();
            log::debug!("Cancelled old background task for upstream: {}", name);
        }

        // Spawn new background task
        let token = CancellationToken::new();
        self.cancellation_tokens
            .insert(name.to_string(), token.clone());

        spawn_upstream_background_task(name.to_string(), lb_arc.clone(), token);

        log::info!("Updated upstream: {}", name);
        Ok(())
    }

    /// Remove an upstream
    pub fn remove_upstream(&self, name: &str) -> Result<(), JokowayError> {
        // Check if upstream exists
        if !self.verify_upstream(name) {
            log::warn!("Upstream {} does not exist, skipping remove", name);
            return Ok(());
        }

        // Cancel background task if exists
        if let Some((_, token)) = self.cancellation_tokens.remove(name) {
            token.cancel();
            log::info!("Cancelled background task for upstream: {}", name);
        }

        // Remove from load balancers map
        self.load_balancers.rcu(|old| {
            let mut next = (**old).clone();
            next.remove(name);
            next
        });

        log::info!("Removed upstream: {}", name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{PeerOptions, Upstream, UpstreamServer};

    #[tokio::test]
    async fn test_sni_fallback() {
        // We'll simulate the logic inside UpstreamManager::new by extracting the relevant block
        // or just testing the result via creating a config.
        // Creating config is cleaner as it tests integration.

        let config = JokowayConfig {
            upstreams: vec![
                Upstream {
                    name: "domain_upstream".to_string(),
                    peer_options: None,
                    servers: vec![UpstreamServer {
                        host: "example.com:443".to_string(), // Should get SNI
                        weight: None,
                        tls: None,
                        peer_options: None,
                    }],
                    health_check: None,
                },
                Upstream {
                    name: "ip_upstream".to_string(),
                    peer_options: None,
                    servers: vec![UpstreamServer {
                        host: "127.0.0.1:8080".to_string(), // Should NOT get SNI
                        weight: None,
                        tls: None,
                        peer_options: None,
                    }],
                    health_check: None,
                },
                Upstream {
                    name: "explicit_sni".to_string(),
                    peer_options: None,
                    servers: vec![UpstreamServer {
                        host: "example.org:443".to_string(),
                        weight: None,
                        tls: None,
                        peer_options: Some(PeerOptions {
                            sni: Some("custom.example.org".to_string()), // Should preserve custom SNI
                            ..Default::default()
                        }),
                    }],
                    health_check: None,
                },
                Upstream {
                    name: "manual_tls_true".to_string(),
                    peer_options: None,
                    servers: vec![UpstreamServer {
                        host: "127.0.0.1:80".to_string(), // Port 80 but TLS forced
                        weight: None,
                        tls: Some(true),
                        peer_options: None,
                    }],
                    health_check: None,
                },
                Upstream {
                    name: "manual_tls_false".to_string(),
                    peer_options: None,
                    servers: vec![UpstreamServer {
                        host: "127.0.0.1:443".to_string(), // Port 443 but TLS disabled
                        weight: None,
                        tls: Some(false),
                        peer_options: None,
                    }],
                    health_check: None,
                },
            ],
            ..Default::default()
        };

        let app_ctx = AppCtx::new();
        app_ctx.insert(config.clone());
        // Use mock resolver to avoid network dependency and speed up tests
        let mut ips = std::collections::HashMap::new();
        ips.insert(
            "example.com".to_string(),
            vec!["127.0.0.1".parse().unwrap()],
        );
        ips.insert(
            "example.org".to_string(),
            vec!["127.0.0.1".parse().unwrap()],
        );
        let resolver = DnsResolver::new_mock(ips);
        app_ctx.insert(resolver);

        let (manager, _) = UpstreamManager::new(&app_ctx).expect("Failed to create manager");
        manager.update_backends().await;

        // To verify, we would ideally inspect the CachedPeerConfig in the LoadBalancer.
        // However, LoadBalancer internals are private.
        // We might need to rely on the fact that we can call get_backend() if we mock things, but that's hard.
        // Instead, let's verify via the logs (manual) or trust the logic if we could unit test the logic directly.
        // Or we can query the load balancer's backends and check extensions if accessible.

        let lb_domain = manager.get("domain_upstream").unwrap();
        let backends = lb_domain.backends().get_backend();
        let config_domain = backends
            .iter()
            .next()
            .unwrap()
            .ext
            .get::<CachedPeerConfig>()
            .unwrap();
        assert_eq!(config_domain.options.sni.as_deref(), Some("example.com"));
        assert!(config_domain.tls); // 443 port

        let lb_ip = manager.get("ip_upstream").unwrap();
        let backends = lb_ip.backends().get_backend();
        let config_ip = backends
            .iter()
            .next()
            .unwrap()
            .ext
            .get::<CachedPeerConfig>()
            .unwrap();
        assert_eq!(config_ip.options.sni, None);
        assert!(!config_ip.tls); // 8080 port

        let lb_explicit = manager.get("explicit_sni").unwrap();
        let backends = lb_explicit.backends().get_backend();
        let config_explicit = backends
            .iter()
            .next()
            .unwrap()
            .ext
            .get::<CachedPeerConfig>()
            .unwrap();
        assert_eq!(
            config_explicit.options.sni.as_deref(),
            Some("custom.example.org")
        );
        assert!(config_explicit.tls); // 443 port

        let lb_manual_true = manager.get("manual_tls_true").unwrap();
        let backends = lb_manual_true.backends().get_backend();
        let config_manual_true = backends
            .iter()
            .next()
            .unwrap()
            .ext
            .get::<CachedPeerConfig>()
            .unwrap();
        assert!(config_manual_true.tls); // Forced true

        let lb_manual_false = manager.get("manual_tls_false").unwrap();
        let backends = lb_manual_false.backends().get_backend();
        let config_manual_false = backends
            .iter()
            .next()
            .unwrap()
            .ext
            .get::<CachedPeerConfig>()
            .unwrap();
        assert!(!config_manual_false.tls); // Forced false
    }
}
