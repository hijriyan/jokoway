use crate::config::models::{JokowayConfig, LoadBalancingConfig, LoadBalancingStrategy};
use crate::error::JokowayError;
use crate::extensions::dns::DnsResolver;
use crate::prelude::{core::*, *};
use crate::server::context::Context;
use crate::server::discovery::JokowayUpstreamDiscovery;
use crate::server::proxy::{CachedPeerConfig, merge_peer_options};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::selection::{Consistent, FNVHash, Random, RoundRobin};
use pingora::lb::{Backend, Backends, LoadBalancer};
use pingora::server::ShutdownWatch;
use pingora::services::background::{BackgroundService, GenBackgroundService};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub struct RuntimeLoadBalancer {
    config: LoadBalancingConfig,
    inner: RuntimeLoadBalancerInner,
}

enum RuntimeLoadBalancerInner {
    RoundRobin(LoadBalancer<RoundRobin>),
    Random(LoadBalancer<Random>),
    FnvHash(LoadBalancer<FNVHash>),
    Consistent(LoadBalancer<Consistent>),
}

impl RuntimeLoadBalancer {
    fn from_backends(backends: Backends, config: LoadBalancingConfig) -> Self {
        let inner = match config.strategy.clone() {
            LoadBalancingStrategy::RoundRobin => {
                RuntimeLoadBalancerInner::RoundRobin(LoadBalancer::from_backends(backends))
            }
            LoadBalancingStrategy::Random => {
                RuntimeLoadBalancerInner::Random(LoadBalancer::from_backends(backends))
            }
            LoadBalancingStrategy::FnvHash => {
                RuntimeLoadBalancerInner::FnvHash(LoadBalancer::from_backends(backends))
            }
            LoadBalancingStrategy::Consistent => {
                RuntimeLoadBalancerInner::Consistent(LoadBalancer::from_backends(backends))
            }
        };

        Self { config, inner }
    }

    pub fn config(&self) -> &LoadBalancingConfig {
        &self.config
    }

    pub fn requires_selection_key(&self) -> bool {
        matches!(
            self.config.strategy,
            LoadBalancingStrategy::FnvHash | LoadBalancingStrategy::Consistent
        )
    }

    pub fn select(&self, key: &[u8], max_iterations: usize) -> Option<Backend> {
        match &self.inner {
            RuntimeLoadBalancerInner::RoundRobin(lb) => lb.select(key, max_iterations),
            RuntimeLoadBalancerInner::Random(lb) => lb.select(key, max_iterations),
            RuntimeLoadBalancerInner::FnvHash(lb) => lb.select(key, max_iterations),
            RuntimeLoadBalancerInner::Consistent(lb) => lb.select(key, max_iterations),
        }
    }

    pub async fn update(&self) -> Result<(), Box<pingora::Error>> {
        match &self.inner {
            RuntimeLoadBalancerInner::RoundRobin(lb) => lb.update().await,
            RuntimeLoadBalancerInner::Random(lb) => lb.update().await,
            RuntimeLoadBalancerInner::FnvHash(lb) => lb.update().await,
            RuntimeLoadBalancerInner::Consistent(lb) => lb.update().await,
        }
    }

    pub fn update_frequency(&self) -> Option<Duration> {
        match &self.inner {
            RuntimeLoadBalancerInner::RoundRobin(lb) => lb.update_frequency,
            RuntimeLoadBalancerInner::Random(lb) => lb.update_frequency,
            RuntimeLoadBalancerInner::FnvHash(lb) => lb.update_frequency,
            RuntimeLoadBalancerInner::Consistent(lb) => lb.update_frequency,
        }
    }

    pub fn health_check_frequency(&self) -> Option<Duration> {
        match &self.inner {
            RuntimeLoadBalancerInner::RoundRobin(lb) => lb.health_check_frequency,
            RuntimeLoadBalancerInner::Random(lb) => lb.health_check_frequency,
            RuntimeLoadBalancerInner::FnvHash(lb) => lb.health_check_frequency,
            RuntimeLoadBalancerInner::Consistent(lb) => lb.health_check_frequency,
        }
    }

    pub fn set_update_frequency(&mut self, frequency: Option<Duration>) {
        match &mut self.inner {
            RuntimeLoadBalancerInner::RoundRobin(lb) => lb.update_frequency = frequency,
            RuntimeLoadBalancerInner::Random(lb) => lb.update_frequency = frequency,
            RuntimeLoadBalancerInner::FnvHash(lb) => lb.update_frequency = frequency,
            RuntimeLoadBalancerInner::Consistent(lb) => lb.update_frequency = frequency,
        }
    }

    pub fn set_health_check_frequency(&mut self, frequency: Option<Duration>) {
        match &mut self.inner {
            RuntimeLoadBalancerInner::RoundRobin(lb) => lb.health_check_frequency = frequency,
            RuntimeLoadBalancerInner::Random(lb) => lb.health_check_frequency = frequency,
            RuntimeLoadBalancerInner::FnvHash(lb) => lb.health_check_frequency = frequency,
            RuntimeLoadBalancerInner::Consistent(lb) => lb.health_check_frequency = frequency,
        }
    }

    pub fn set_health_check(
        &mut self,
        health_check: Box<dyn pingora::lb::health_check::HealthCheck + Send + Sync + 'static>,
    ) {
        match &mut self.inner {
            RuntimeLoadBalancerInner::RoundRobin(lb) => lb.set_health_check(health_check),
            RuntimeLoadBalancerInner::Random(lb) => lb.set_health_check(health_check),
            RuntimeLoadBalancerInner::FnvHash(lb) => lb.set_health_check(health_check),
            RuntimeLoadBalancerInner::Consistent(lb) => lb.set_health_check(health_check),
        }
    }

    pub async fn run_health_check(&self, parallel: bool) {
        self.backends().run_health_check(parallel).await;
    }

    pub fn backends(&self) -> &Backends {
        match &self.inner {
            RuntimeLoadBalancerInner::RoundRobin(lb) => lb.backends(),
            RuntimeLoadBalancerInner::Random(lb) => lb.backends(),
            RuntimeLoadBalancerInner::FnvHash(lb) => lb.backends(),
            RuntimeLoadBalancerInner::Consistent(lb) => lb.backends(),
        }
    }
}

pub struct LbWrapper {
    pub name: String,
    pub lb: Arc<RuntimeLoadBalancer>,
    pub cancellation_token: CancellationToken,
}

#[async_trait]
impl BackgroundService for LbWrapper {
    async fn start(&self, shutdown: ShutdownWatch) {
        // Create a local watch channel to control the maintenance loop lifecycle.
        let (tx, rx) = tokio::sync::watch::channel(false);

        // Start the local LB maintenance loop in a separate task so this wrapper can
        // keep the Pingora background service alive until shutdown or cancellation.
        let lb = self.lb.clone();
        let name = self.name.clone();
        tokio::spawn(async move {
            run_load_balancer_background_loop(name, lb, rx).await;
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

fn split_host_port(host: &str) -> (&str, Option<u16>) {
    if let Some(rest) = host.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host_part = &rest[..end];
        let after_bracket = &rest[end + 1..];
        let port = after_bracket
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok());
        return (host_part, port);
    }

    if let Some((host_part, port)) = host.rsplit_once(':')
        && !host_part.contains(':')
    {
        return (host_part, port.parse::<u16>().ok());
    }

    (host, None)
}

fn load_balancer_needs_background_task(lb: &RuntimeLoadBalancer) -> bool {
    lb.update_frequency().is_some() || lb.health_check_frequency().is_some()
}

fn compile_upstream(
    upstream: &crate::config::models::Upstream,
    dns_resolver: Arc<DnsResolver>,
) -> Result<Arc<RuntimeLoadBalancer>, JokowayError> {
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

        let (host_only, port) = split_host_port(&server.host);

        // Smart SNI Fallback
        if merged_options.sni.is_none()
            && !host_only.is_empty()
            && host_only.parse::<std::net::IpAddr>().is_err()
        {
            merged_options.sni = Some(host_only.to_string());
            log::debug!(
                "Automatically setting SNI to '{}' for upstream {}",
                host_only,
                upstream.name
            );
        }

        // Determine TLS based on config or port 443 (if not specified)
        let is_tls = server.tls.unwrap_or(port == Some(443));

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
    let mut load_balancer = RuntimeLoadBalancer::from_backends(backends, upstream.lb.clone());

    // Set update frequency from config if specified
    if let Some(freq_secs) = upstream.update_frequency {
        if freq_secs == 0 {
            return Err(JokowayError::Upstream(format!(
                "update_frequency for upstream '{}' must be greater than 0 seconds",
                upstream.name
            )));
        }
        load_balancer.set_update_frequency(Some(Duration::from_secs(freq_secs)));
        log::debug!(
            "Configured update frequency for upstream '{}': {}s",
            upstream.name,
            freq_secs
        );
    }

    // Configure health check if specified
    if let Some(hc_config) = &upstream.health_check {
        use crate::server::health::create_health_check;

        if hc_config.interval == 0 {
            return Err(JokowayError::Upstream(format!(
                "health_check.interval for upstream '{}' must be greater than 0 seconds",
                upstream.name
            )));
        }

        let health_check = create_health_check(hc_config);
        load_balancer.set_health_check(health_check);
        load_balancer.set_health_check_frequency(Some(Duration::from_secs(hc_config.interval)));

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

async fn run_load_balancer_background_loop(
    name: String,
    lb: Arc<RuntimeLoadBalancer>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    log::info!("Starting background task for upstream: {}", name);
    // reference: https://docs.rs/pingora-load-balancing/latest/src/pingora_load_balancing/background.rs.html
    const NEVER: Duration = Duration::from_secs(u32::MAX as u64);
    let mut now = Instant::now();
    // run update and health check once
    let mut next_update = now;
    let mut next_health_check = now;

    loop {
        if *shutdown.borrow() {
            log::info!("Background task cancelled for upstream: {}", name);
            break;
        }

        if next_update <= now {
            if let Err(e) = lb.update().await {
                log::warn!("Failed to update upstream '{}': {}", name, e);
            }
            next_update = now + lb.update_frequency().unwrap_or(NEVER);
        }

        if next_health_check <= now {
            lb.run_health_check(true).await;
            next_health_check = now + lb.health_check_frequency().unwrap_or(NEVER);
        }

        if lb.update_frequency().is_none() && lb.health_check_frequency().is_none() {
            return;
        }

        let to_wake = std::cmp::min(next_update, next_health_check);
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    log::info!("Background task cancelled for upstream: {}", name);
                    break;
                }
            }
            _ = tokio::time::sleep_until(to_wake.into()) => {}
        }
        now = Instant::now();
    }
}

fn spawn_upstream_background_task(
    name: String,
    lb: Arc<RuntimeLoadBalancer>,
    token: CancellationToken,
) {
    tokio::spawn(async move {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let background_name = name.clone();
        let background_lb = lb.clone();
        let handle = tokio::spawn(async move {
            run_load_balancer_background_loop(background_name, background_lb, rx).await;
        });

        token.cancelled().await;
        let _ = tx.send(true);
        let _ = handle.await;
    });
}

pub struct UpstreamManager {
    pub load_balancers: ArcSwap<HashMap<String, Arc<RuntimeLoadBalancer>>>,
    // Track cancellation tokens for background tasks
    cancellation_tokens: Arc<DashMap<String, CancellationToken>>,
    mutation_lock: Mutex<()>,
}

impl UpstreamManager {
    pub fn new(app_ctx: &AppContext) -> Result<(Self, Vec<LbBackgroundService>), JokowayError> {
        let config = app_ctx
            .get::<JokowayConfig>()
            .ok_or_else(|| JokowayError::Config("JokowayConfig not found in Context".into()))?;
        let dns_resolver = app_ctx
            .get::<DnsResolver>()
            .ok_or_else(|| JokowayError::Upstream("DnsResolver not found in Context".into()))?;

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
                    name: upstream.name.clone(),
                    lb: lb_arc,
                    cancellation_token: token,
                }),
            );
            services.push(background);
        }
        let upstream_manager = UpstreamManager {
            load_balancers: ArcSwap::from_pointee(load_balancers),
            cancellation_tokens,
            mutation_lock: Mutex::new(()),
        };
        Ok((upstream_manager, services))
    }

    pub fn get(&self, name: &str) -> Option<Arc<RuntimeLoadBalancer>> {
        self.load_balancers.load().get(name).cloned()
    }

    /// Manually triggers discovery for all load balancers.
    /// Useful for tests or ensuring initial state before serving.
    pub async fn update_backends(&self) {
        let lbs: Vec<_> = self.load_balancers.load().values().cloned().collect();
        for lb in lbs {
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
        let _guard = self.mutation_lock.lock().await;

        // Check if upstream already exists while holding the mutation gate.
        if self.verify_upstream(&upstream.name) {
            return Err(JokowayError::Upstream(format!(
                "Upstream {} already exists",
                upstream.name
            )));
        }

        let lb_arc = compile_upstream(&upstream, dns_resolver)?;

        // Trigger initial backend discovery before exposing this load balancer to requests.
        lb_arc.update().await.map_err(|e| {
            JokowayError::Upstream(format!(
                "Failed initial backend discovery for upstream '{}': {}",
                upstream.name, e
            ))
        })?;

        // Update load balancers map
        self.load_balancers.rcu(|old| {
            let mut next = (**old).clone();
            next.insert(upstream.name.clone(), lb_arc.clone());
            next
        });

        // Spawn background task only if there is periodic work to do.
        if load_balancer_needs_background_task(&lb_arc) {
            let token = CancellationToken::new();
            if let Some(old_token) = self
                .cancellation_tokens
                .insert(upstream.name.clone(), token.clone())
            {
                old_token.cancel();
            }
            spawn_upstream_background_task(upstream.name.clone(), lb_arc, token);
        }

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
        let _guard = self.mutation_lock.lock().await;

        // Check if upstream exists while holding the mutation gate.
        if !self.verify_upstream(name) {
            return Err(JokowayError::Upstream(format!(
                "Upstream {} does not exist",
                name
            )));
        }

        let lb_arc = compile_upstream(&upstream, dns_resolver)?;

        // Trigger initial backend discovery before exposing this load balancer to requests.
        lb_arc.update().await.map_err(|e| {
            JokowayError::Upstream(format!(
                "Failed initial backend discovery for upstream '{}': {}",
                name, e
            ))
        })?;

        // Cancel old background task before publishing the replacement.
        if let Some((_, old_token)) = self.cancellation_tokens.remove(name) {
            old_token.cancel();
            log::debug!("Cancelled old background task for upstream: {}", name);
        }

        // Update load balancers map
        self.load_balancers.rcu(|old| {
            let mut next = (**old).clone();
            next.insert(name.to_string(), lb_arc.clone());
            next
        });

        // Spawn new background task only if there is periodic work to do.
        if load_balancer_needs_background_task(&lb_arc) {
            let token = CancellationToken::new();
            if let Some(old_token) = self
                .cancellation_tokens
                .insert(name.to_string(), token.clone())
            {
                old_token.cancel();
            }
            spawn_upstream_background_task(name.to_string(), lb_arc, token);
        }

        log::info!("Updated upstream: {}", name);
        Ok(())
    }

    /// Remove an upstream
    pub async fn remove_upstream(&self, name: &str) -> Result<(), JokowayError> {
        let _guard = self.mutation_lock.lock().await;

        // Check if upstream exists while holding the mutation gate.
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

pub struct UpstreamManagerService {
    pub manager: Arc<UpstreamManager>,
}

impl UpstreamManagerService {
    pub fn new(manager: Arc<UpstreamManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl BackgroundService for UpstreamManagerService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        log::info!("UpstreamManagerService started");
        let _ = shutdown.changed().await;
        log::info!(
            "UpstreamManagerService shutting down, cancelling all upstream background tasks"
        );
        for entry in self.manager.cancellation_tokens.iter() {
            entry.value().cancel();
        }
    }
}

pub struct UpstreamExtension;

impl JokowayExtension for UpstreamExtension {
    fn order(&self) -> i16 {
        // run after DnsExtension
        i16::MAX - 1
    }

    fn init(
        &self,
        server: &mut pingora::server::Server,
        app_ctx: &mut AppContext,
        _middlewares: &mut Vec<std::sync::Arc<dyn JokowayMiddlewareDyn>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Initialize UpstreamManager
        let (upstream_manager, lb_services) = UpstreamManager::new(app_ctx)?;
        app_ctx.insert(upstream_manager);

        // Add LB background services
        for service in lb_services {
            server.add_service(service);
        }

        // add upstream background service
        let upstream_manager_service = pingora::prelude::background_service(
            "upstream_manager_service",
            UpstreamManagerService::new(app_ctx.get::<UpstreamManager>().unwrap().clone()),
        );
        server.add_service(upstream_manager_service);

        log::info!("UpstreamManager initialized");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{
        LoadBalancingConfig, LoadBalancingKey, LoadBalancingStrategy, PeerOptions, Upstream,
        UpstreamServer,
    };

    #[tokio::test]
    async fn test_sni_fallback() {
        let config = JokowayConfig {
            upstreams: vec![
                Upstream {
                    name: "domain_upstream".to_string(),
                    lb: Default::default(),
                    peer_options: None,
                    servers: vec![UpstreamServer {
                        host: "example.com:443".to_string(), // Should get SNI
                        weight: None,
                        tls: None,
                        peer_options: None,
                    }],
                    health_check: None,
                    update_frequency: None,
                },
                Upstream {
                    name: "ip_upstream".to_string(),
                    lb: Default::default(),
                    peer_options: None,
                    servers: vec![UpstreamServer {
                        host: "127.0.0.1:8080".to_string(), // Should NOT get SNI
                        weight: None,
                        tls: None,
                        peer_options: None,
                    }],
                    health_check: None,
                    update_frequency: None,
                },
                Upstream {
                    name: "explicit_sni".to_string(),
                    lb: Default::default(),
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
                    update_frequency: None,
                },
                Upstream {
                    name: "manual_tls_true".to_string(),
                    lb: Default::default(),
                    peer_options: None,
                    servers: vec![UpstreamServer {
                        host: "127.0.0.1:80".to_string(), // Port 80 but TLS forced
                        weight: None,
                        tls: Some(true),
                        peer_options: None,
                    }],
                    health_check: None,
                    update_frequency: None,
                },
                Upstream {
                    name: "manual_tls_false".to_string(),
                    lb: Default::default(),
                    peer_options: None,
                    servers: vec![UpstreamServer {
                        host: "127.0.0.1:443".to_string(), // Port 443 but TLS disabled
                        weight: None,
                        tls: Some(false),
                        peer_options: None,
                    }],
                    health_check: None,
                    update_frequency: None,
                },
            ],
            ..Default::default()
        };

        let app_ctx = AppContext::new();
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

    #[tokio::test]
    async fn test_dynamic_load_balancing_strategy_update() {
        let config = JokowayConfig {
            upstreams: vec![Upstream {
                name: "dynamic_lb".to_string(),
                lb: LoadBalancingConfig {
                    strategy: LoadBalancingStrategy::RoundRobin,
                    key: None,
                },
                servers: vec![UpstreamServer {
                    host: "127.0.0.1:8080".to_string(),
                    weight: None,
                    tls: None,
                    peer_options: None,
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let app_ctx = AppContext::new();
        app_ctx.insert(config.clone());
        app_ctx.insert(DnsResolver::new_mock(Default::default()));

        let (manager, _) = UpstreamManager::new(&app_ctx).expect("Failed to create manager");
        manager.update_backends().await;

        let lb = manager.get("dynamic_lb").unwrap();
        assert_eq!(lb.config().strategy, LoadBalancingStrategy::RoundRobin);

        manager
            .update_upstream(
                "dynamic_lb",
                Upstream {
                    name: "dynamic_lb".to_string(),
                    lb: LoadBalancingConfig {
                        strategy: LoadBalancingStrategy::Consistent,
                        key: Some(LoadBalancingKey::Header {
                            name: "x-user-id".to_string(),
                        }),
                    },
                    servers: vec![UpstreamServer {
                        host: "127.0.0.1:8081".to_string(),
                        weight: None,
                        tls: None,
                        peer_options: None,
                    }],
                    ..Default::default()
                },
                app_ctx.get::<DnsResolver>().unwrap(),
            )
            .await
            .expect("Failed to update upstream");

        let updated_lb = manager.get("dynamic_lb").unwrap();
        assert_eq!(
            updated_lb.config().strategy,
            LoadBalancingStrategy::Consistent
        );
        assert_eq!(
            updated_lb.config().key,
            Some(LoadBalancingKey::Header {
                name: "x-user-id".to_string()
            })
        );
        assert!(updated_lb.requires_selection_key());
        assert!(updated_lb.select(b"user-1", 256).is_some());
    }
}
