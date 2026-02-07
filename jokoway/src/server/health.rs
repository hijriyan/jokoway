use crate::config::models::{HealthCheckConfig, HealthCheckType};
use crate::server::proxy::CachedPeerConfig;
use async_trait::async_trait;
use dashmap::DashMap;
use pingora::Error;
use pingora::http::RequestHeader;
use pingora::lb::Backend;
use pingora::lb::health_check::{HealthCheck, HttpHealthCheck, TcpHealthCheck};
use pingora::protocols::l4::socket::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Create a health check from configuration
///
/// This function creates either a dynamic HTTP/HTTPS or TCP health check based on the configuration.
pub fn create_health_check(config: &HealthCheckConfig) -> Box<dyn HealthCheck + Send + Sync> {
    match config.check_type {
        HealthCheckType::Http | HealthCheckType::Https => {
            Box::new(JokowayHttpHealthCheck::new(config.clone()))
        }
        HealthCheckType::Tcp => Box::new(JokowayTcpHealthCheck::new(config.clone())),
    }
}

struct JokowayHttpHealthCheck {
    config: HealthCheckConfig,
    checks: DashMap<SocketAddr, Arc<HttpHealthCheck>>,
}

#[async_trait]
impl HealthCheck for JokowayHttpHealthCheck {
    async fn check(&self, backend: &Backend) -> Result<(), Box<Error>> {
        let cached_config = backend.ext.get::<CachedPeerConfig>();

        // DashMap operations can't hold reference across await
        if let Some(c) = self.checks.get(&backend.addr) {
            return c.value().check(backend).await;
        }

        // Create new check if missing
        let new_check = self.create_check(cached_config);
        let check_arc: Arc<HttpHealthCheck> = Arc::from(new_check);

        // Insert and return
        self.checks.insert(backend.addr.clone(), check_arc.clone());
        check_arc.check(backend).await
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.config.healthy_threshold as usize
        } else {
            self.config.unhealthy_threshold as usize
        }
    }
}

impl JokowayHttpHealthCheck {
    fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            checks: DashMap::new(),
        }
    }

    fn create_check(&self, cached_config: Option<&CachedPeerConfig>) -> Box<HttpHealthCheck> {
        let is_https = self.config.check_type == HealthCheckType::Https;
        let host = cached_config
            .and_then(|c| c.options.sni.as_deref())
            .unwrap_or("");

        let mut health_check = HttpHealthCheck::new(host, is_https);

        if let Some(cached) = cached_config {
            cached.apply_to_peer(&mut health_check.peer_template);
            cached.apply_client_cert(&mut health_check.peer_template);
        }

        health_check.peer_template.options.read_timeout =
            Some(Duration::from_secs(self.config.timeout));
        health_check.peer_template.options.connection_timeout =
            Some(Duration::from_secs(self.config.timeout));

        self.configure_request(&mut health_check, host);

        health_check.consecutive_success = self.config.healthy_threshold as usize;
        health_check.consecutive_failure = self.config.unhealthy_threshold as usize;
        health_check.reuse_connection = true;

        self.configure_validator(&mut health_check);

        Box::new(health_check)
    }

    fn configure_request(&self, health_check: &mut HttpHealthCheck, host: &str) {
        let path = self.config.path.as_deref().unwrap_or("/");
        let method = self.config.method.as_deref().unwrap_or("GET");

        if path != "/" || method != "GET" {
            let mut req = RequestHeader::build(method, path.as_bytes(), None).unwrap();
            if !host.is_empty() {
                req.append_header("Host", host).ok();
            }
            if let Some(headers) = &self.config.headers {
                for (key, value) in headers {
                    req.append_header(key.clone(), value.clone()).ok();
                }
            }
            health_check.req = req;
        } else if let Some(headers) = &self.config.headers {
            for (key, value) in headers {
                health_check
                    .req
                    .append_header(key.clone(), value.clone())
                    .ok();
            }
        }
    }

    fn configure_validator(&self, health_check: &mut HttpHealthCheck) {
        if let Some(expected_codes) = &self.config.expected_status {
            let codes = expected_codes.clone();
            health_check.validator = Some(Box::new(move |resp_header| {
                if codes.contains(&resp_header.status.as_u16()) {
                    Ok(())
                } else {
                    Err(Error::explain(
                        pingora::ErrorType::HTTPStatus(resp_header.status.as_u16()),
                        format!("Unexpected status code: {}", resp_header.status),
                    ))
                }
            }));
        }
    }
}

/// Dynamic TCP Health Check
struct JokowayTcpHealthCheck {
    config: HealthCheckConfig,
    checks: DashMap<SocketAddr, Arc<TcpHealthCheck>>,
}

impl JokowayTcpHealthCheck {
    fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            checks: DashMap::new(),
        }
    }

    fn create_check(&self, cached_config: Option<&CachedPeerConfig>) -> Box<TcpHealthCheck> {
        let mut health_check = if let Some(cached) = cached_config {
            if let Some(sni) = &cached.options.sni {
                TcpHealthCheck::new_tls(sni)
            } else {
                TcpHealthCheck::new()
            }
        } else {
            TcpHealthCheck::new()
        };

        if let Some(cached) = cached_config {
            cached.apply_to_peer(&mut health_check.peer_template);
        }

        health_check.consecutive_success = self.config.healthy_threshold as usize;
        health_check.consecutive_failure = self.config.unhealthy_threshold as usize;
        health_check.peer_template.options.connection_timeout =
            Some(Duration::from_secs(self.config.timeout));

        health_check
    }
}

#[async_trait]
impl HealthCheck for JokowayTcpHealthCheck {
    async fn check(&self, backend: &Backend) -> Result<(), Box<Error>> {
        if let Some(c) = self.checks.get(&backend.addr) {
            return c.value().check(backend).await;
        }

        let cached_config = backend.ext.get::<CachedPeerConfig>();
        let new_check = self.create_check(cached_config);
        let check_arc = Arc::from(*new_check);

        self.checks.insert(backend.addr.clone(), check_arc.clone());

        check_arc.check(backend).await
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.config.healthy_threshold as usize
        } else {
            self.config.unhealthy_threshold as usize
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::HealthCheckType;

    fn create_test_http_config() -> HealthCheckConfig {
        HealthCheckConfig {
            check_type: HealthCheckType::Http,
            interval: 10,
            timeout: 5,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            path: Some("/health".to_string()),
            method: Some("GET".to_string()),
            expected_status: Some(vec![200]),
            headers: None,
        }
    }

    fn create_test_tcp_config() -> HealthCheckConfig {
        HealthCheckConfig {
            check_type: HealthCheckType::Tcp,
            interval: 10,
            timeout: 5,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            path: None,
            method: None,
            expected_status: None,
            headers: None,
        }
    }

    #[test]
    fn test_create_health_check_http() {
        let config = create_test_http_config();
        let hc = create_health_check(&config);

        // Verify it returns the correct type by checking health_threshold
        assert_eq!(hc.health_threshold(true), 2);
        assert_eq!(hc.health_threshold(false), 3);
    }

    #[test]
    fn test_create_health_check_tcp() {
        let config = create_test_tcp_config();
        let hc = create_health_check(&config);

        // Verify it returns the correct type by checking health_threshold
        assert_eq!(hc.health_threshold(true), 2);
        assert_eq!(hc.health_threshold(false), 3);
    }

    #[test]
    fn test_jokoway_http_health_check_caching() {
        let config = create_test_http_config();
        let checker = JokowayHttpHealthCheck::new(config);

        // Cache should be empty initially
        assert!(checker.checks.is_empty());

        // Note: We can't easily test the async check without a real server,
        // but we can verify the cache structure is correct
        assert_eq!(checker.checks.len(), 0);
    }

    #[test]
    fn test_jokoway_tcp_health_check_caching() {
        let config = create_test_tcp_config();
        let checker = JokowayTcpHealthCheck::new(config);

        // Cache should be empty initially
        assert!(checker.checks.is_empty());
        assert_eq!(checker.checks.len(), 0);
    }

    #[test]
    fn test_health_threshold_http() {
        let config = create_test_http_config();
        let checker = JokowayHttpHealthCheck::new(config);

        // Test success threshold
        assert_eq!(checker.health_threshold(true), 2);

        // Test failure threshold
        assert_eq!(checker.health_threshold(false), 3);
    }

    #[test]
    fn test_health_threshold_tcp() {
        let config = create_test_tcp_config();
        let checker = JokowayTcpHealthCheck::new(config);

        // Test success threshold
        assert_eq!(checker.health_threshold(true), 2);

        // Test failure threshold
        assert_eq!(checker.health_threshold(false), 3);
    }

    #[test]
    fn test_http_config_values() {
        let config = HealthCheckConfig {
            check_type: HealthCheckType::Http,
            interval: 30,
            timeout: 10,
            healthy_threshold: 5,
            unhealthy_threshold: 7,
            path: Some("/custom".to_string()),
            method: Some("POST".to_string()),
            expected_status: Some(vec![200, 204]),
            headers: None,
        };

        let checker = JokowayHttpHealthCheck::new(config.clone());

        assert_eq!(checker.config.path, Some("/custom".to_string()));
        assert_eq!(checker.config.interval, 30);
        assert_eq!(checker.config.timeout, 10);
        assert_eq!(checker.health_threshold(true), 5);
        assert_eq!(checker.health_threshold(false), 7);
    }

    #[test]
    fn test_tcp_config_values() {
        let config = HealthCheckConfig {
            check_type: HealthCheckType::Tcp,
            interval: 20,
            timeout: 8,
            healthy_threshold: 4,
            unhealthy_threshold: 6,
            path: None,
            method: None,
            expected_status: None,
            headers: None,
        };

        let checker = JokowayTcpHealthCheck::new(config.clone());

        assert_eq!(checker.config.interval, 20);
        assert_eq!(checker.config.timeout, 8);
        assert_eq!(checker.health_threshold(true), 4);
        assert_eq!(checker.health_threshold(false), 6);
    }
}
