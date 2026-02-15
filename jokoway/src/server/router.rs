use crate::config::models::ServiceProtocol;

use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use arc_swap::ArcSwap;
use jokoway_transformer::{RequestTransformer, ResponseTransformer};
use pingora::http::RequestHeader;
use std::collections::HashMap;
use std::sync::Arc;

// Re-export protocol constants from service module
pub use crate::server::service::{ALL_PROTOCOLS, HTTP_PROTOCOLS, HTTPS_PROTOCOLS};

pub struct RouteMatch {
    pub upstream_name: Arc<str>,
    pub req_transformer: Option<Arc<dyn RequestTransformer>>,
    pub res_transformer: Option<Arc<dyn ResponseTransformer>>,
}

/// Router evaluates rules and transformers for request matching.
/// Requires ServiceManager and UpstreamManager for initialization.
pub struct Router {
    service_manager: Arc<ServiceManager>,
    upstream_manager: Arc<UpstreamManager>,
    /// Index of services key by Host header value.
    /// Maps host string to list of service indices.
    host_index: ArcSwap<HashMap<String, Vec<usize>>>,
    /// List of service indices that must always be checked (wildcards, regex hosts, etc.)
    catch_all_indices: ArcSwap<Vec<usize>>,
    /// Protocols this router handles (needed for refresh)
    protocols: Vec<ServiceProtocol>,
}

impl Router {
    pub fn new(
        service_manager: Arc<ServiceManager>,
        upstream_manager: Arc<UpstreamManager>,
        protocols: &[ServiceProtocol],
    ) -> Arc<Self> {
        let (host_index, catch_all_indices) = Self::build_indices(&service_manager, protocols);

        let router = Arc::new(Router {
            service_manager: service_manager.clone(),
            upstream_manager,
            host_index: ArcSwap::from_pointee(host_index),
            catch_all_indices: ArcSwap::from_pointee(catch_all_indices),
            protocols: protocols.to_vec(),
        });

        // Register callback to refresh indices when services change
        let router_weak = Arc::downgrade(&router);
        service_manager.add_services_changed_callback(move || {
            if let Some(r) = router_weak.upgrade() {
                r.refresh_indices();
            }
        });

        router
    }

    /// Build indices based on current services and protocols
    fn build_indices(
        service_manager: &ServiceManager,
        protocols: &[ServiceProtocol],
    ) -> (HashMap<String, Vec<usize>>, Vec<usize>) {
        let service_indices = service_manager.get_indices_for_protocols(protocols);
        let all_services = service_manager.get_all();

        let mut host_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut catch_all_indices = Vec::new();

        for idx in service_indices {
            let service = &all_services[idx];
            let mut service_has_wildcard = false;
            let mut service_hosts = std::collections::HashSet::new();

            // Check if all routes have specific hosts
            for route in &service.routes {
                let (hosts, is_wildcard) = route.matcher.get_required_hosts();

                if is_wildcard {
                    service_has_wildcard = true;
                }
                service_hosts.extend(hosts);
            }

            if service_has_wildcard || service.routes.is_empty() {
                catch_all_indices.push(idx);
            }

            // ALWAYS add to specific host index if specific hosts are available,
            // even if the service is also a wildcard. This ensures O(1) lookup for the specific host leg.
            for host in service_hosts {
                host_index.entry(host).or_default().push(idx);
            }
        }

        (host_index, catch_all_indices)
    }

    /// Refresh service indices based on current services and protocols
    pub fn refresh_indices(&self) {
        let (host_index, catch_all_indices) =
            Self::build_indices(&self.service_manager, &self.protocols);

        self.host_index.store(Arc::new(host_index));
        self.catch_all_indices.store(Arc::new(catch_all_indices));
        log::debug!("Router indices refreshed");
    }

    pub fn match_request(&self, req_header: &RequestHeader) -> Option<RouteMatch> {
        let all_services = self.service_manager.get_all();
        let host_index = self.host_index.load();
        let catch_all_indices = self.catch_all_indices.load();

        // 1. Check indexed services by Host header or URI host
        let uri_host = req_header.uri.host();
        let header_host = req_header.headers.get("Host").and_then(|v| v.to_str().ok());

        // Check URI host first (authoritative)
        if let Some(host) = uri_host
            && let Some(indices) = host_index.get(host)
            && let Some(m) = Self::find_route_in_indices(&all_services, indices, req_header)
        {
            return Some(m);
        }

        // Check Host header if different from URI host
        if let Some(host) = header_host
            && Some(host) != uri_host
            && let Some(indices) = host_index.get(host)
            && let Some(m) = Self::find_route_in_indices(&all_services, indices, req_header)
        {
            return Some(m);
        }

        // 2. Check catch-all services (wildcards, regex, etc.)
        Self::find_route_in_indices(&all_services, &catch_all_indices, req_header)
    }

    #[inline]
    fn find_route_in_indices(
        all_services: &[crate::server::service::RuntimeService],
        indices: &[usize],
        req_header: &RequestHeader,
    ) -> Option<RouteMatch> {
        for &idx in indices {
            let service = &all_services[idx];
            for route in &service.routes {
                if route.matcher.matches(req_header) {
                    return Some(RouteMatch {
                        upstream_name: service.host.clone(),
                        req_transformer: route.req_transformer.clone(),
                        res_transformer: route.res_transformer.clone(),
                    });
                }
            }
        }
        None
    }

    pub fn upstream_manager(&self) -> &Arc<UpstreamManager> {
        &self.upstream_manager
    }

    pub fn service_manager(&self) -> &Arc<ServiceManager> {
        &self.service_manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{JokowayConfig, Route, Service, ServiceProtocol};
    use crate::extensions::dns::DnsResolver;
    use crate::server::context::AppCtx;

    fn create_test_config() -> JokowayConfig {
        JokowayConfig {
            services: vec![
                Service {
                    name: "http_only".to_string(),
                    host: "http_backend".to_string(),
                    protocols: vec![ServiceProtocol::Http],
                    routes: vec![Route {
                        name: "http_route".to_string(),
                        rule: "Host(`example.com`)".to_string(),
                        priority: None,
                        request_transformer: None,
                        response_transformer: None,
                    }],
                },
                Service {
                    name: "https_only".to_string(),
                    host: "https_backend".to_string(),
                    protocols: vec![ServiceProtocol::Https],
                    routes: vec![Route {
                        name: "https_route".to_string(),
                        rule: "Host(`secure.example.com`)".to_string(),
                        priority: None,
                        request_transformer: None,
                        response_transformer: None,
                    }],
                },
                Service {
                    name: "dual_protocol".to_string(),
                    host: "dual_backend".to_string(),
                    protocols: vec![ServiceProtocol::Http, ServiceProtocol::Https],
                    routes: vec![Route {
                        name: "dual_route".to_string(),
                        rule: "Host(`dual.example.com`)".to_string(),
                        priority: None,
                        request_transformer: None,
                        response_transformer: None,
                    }],
                },
                Service {
                    name: "no_protocol".to_string(),
                    host: "default_backend".to_string(),
                    protocols: vec![],
                    routes: vec![Route {
                        name: "default_route".to_string(),
                        rule: "Host(`default.example.com`)".to_string(),
                        priority: None,
                        request_transformer: None,
                        response_transformer: None,
                    }],
                },
            ]
            .into_iter()
            .map(Arc::new)
            .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_protocol_restriction() {
        let config = create_test_config();
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );

        let app_ctx = AppCtx::new();
        app_ctx.insert(config.clone());
        app_ctx.insert(DnsResolver::new(&config));

        let (upstream_manager, _) =
            UpstreamManager::new(&app_ctx).expect("Failed to create UpstreamManager");
        let upstream_manager = Arc::new(upstream_manager);

        // Test HTTP router (should only include HTTP-compatible services)
        let http_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &HTTP_PROTOCOLS,
        );
        assert_eq!(count_unique_services(&http_router), 3);

        // Test HTTPS router (should only include HTTPS-compatible services)
        let https_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &HTTPS_PROTOCOLS,
        );
        assert_eq!(count_unique_services(&https_router), 3);

        // Test with all protocols (should include all services)
        let all_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &ALL_PROTOCOLS,
        );
        assert_eq!(count_unique_services(&all_router), 4);
    }

    fn count_unique_services(router: &Router) -> usize {
        let mut unique_indices = std::collections::HashSet::new();
        for indices in router.host_index.load().values() {
            for &idx in indices {
                unique_indices.insert(idx);
            }
        }
        for &idx in router.catch_all_indices.load().iter() {
            unique_indices.insert(idx);
        }
        unique_indices.len()
    }

    #[test]
    fn test_router_refresh_on_service_changes() {
        let config = create_test_config();
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );

        let app_ctx = AppCtx::new();
        app_ctx.insert(config.clone());
        app_ctx.insert(DnsResolver::new(&config));

        let (upstream_manager, _) =
            UpstreamManager::new(&app_ctx).expect("Failed to create UpstreamManager");
        let upstream_manager = Arc::new(upstream_manager);

        // Create router with HTTP protocols
        let http_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &HTTP_PROTOCOLS,
        );

        // Initial state: 3 HTTP-compatible services
        assert_eq!(count_unique_services(&http_router), 3);

        // Add a new HTTP service
        let new_service = Service {
            name: "new_http_service".to_string(),
            host: "new_backend".to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "new_route".to_string(),
                rule: "Host(`new.example.com`)".to_string(),
                priority: None,
                request_transformer: None,
                response_transformer: None,
            }],
        };

        service_manager
            .add_service(new_service)
            .expect("Failed to add service");

        // Router should automatically refresh and now have 4 services
        assert_eq!(count_unique_services(&http_router), 4);

        // Remove a service
        service_manager
            .remove_service("http_only")
            .expect("Failed to remove service");

        // Router should automatically refresh and now have 3 services
        assert_eq!(count_unique_services(&http_router), 3);
    }

    #[test]
    fn test_router_match_request_scenarios() {
        // 1. Setup Services
        // - Service A: Host("a.com")
        // - Service B: Host("b.com")
        // - Service Hybrid: Host("c.com") || PathPrefix("/c")
        // - Service Wild: PathPrefix("/wild")

        let services = vec![
            Service {
                name: "service_a".to_string(),
                host: "backend_a".to_string(),
                protocols: vec![ServiceProtocol::Http],
                routes: vec![Route {
                    name: "route_a".to_string(),
                    rule: "Host(`a.com`)".to_string(),
                    priority: None,
                    request_transformer: None,
                    response_transformer: None,
                }],
            },
            Service {
                name: "service_b".to_string(),
                host: "backend_b".to_string(),
                protocols: vec![ServiceProtocol::Http],
                routes: vec![Route {
                    name: "route_b".to_string(),
                    rule: "Host(`b.com`)".to_string(),
                    priority: None,
                    request_transformer: None,
                    response_transformer: None,
                }],
            },
            Service {
                name: "service_hybrid".to_string(),
                host: "backend_hybrid".to_string(),
                protocols: vec![ServiceProtocol::Http],
                routes: vec![Route {
                    name: "route_hybrid".to_string(),
                    rule: "Host(`c.com`) || PathPrefix(`/c`)".to_string(),
                    priority: None,
                    request_transformer: None,
                    response_transformer: None,
                }],
            },
            Service {
                name: "service_wild".to_string(),
                host: "backend_wild".to_string(),
                protocols: vec![ServiceProtocol::Http],
                routes: vec![Route {
                    name: "route_wild".to_string(),
                    rule: "PathPrefix(`/wild`)".to_string(),
                    priority: None,
                    request_transformer: None,
                    response_transformer: None,
                }],
            },
            Service {
                name: "service_complex_no_wild".to_string(),
                host: "backend_complex_no_wild".to_string(),
                protocols: vec![ServiceProtocol::Http],
                routes: vec![Route {
                    name: "route_complex_no_wild".to_string(),
                    // Host("c.com") || (Host("a.com") && PathPrefix("/c"))
                    // Both branches have specific hosts, so entire rule is NOT wildcard.
                    rule: "Host(`c.com`) || Host(`a.com`) && PathPrefix(`/c`)".to_string(),
                    priority: None,
                    request_transformer: None,
                    response_transformer: None,
                }],
            },
        ];

        let config = JokowayConfig {
            services: services.into_iter().map(Arc::new).collect(),
            ..Default::default()
        };
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );

        let app_ctx = AppCtx::new();
        app_ctx.insert(config.clone());
        app_ctx.insert(DnsResolver::new(&config));

        let (upstream_manager, _) =
            UpstreamManager::new(&app_ctx).expect("Failed to create UpstreamManager");
        let upstream_manager = Arc::new(upstream_manager);

        let router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &HTTP_PROTOCOLS,
        );

        // 2. Verify Scenarios

        // Scenario A: Specific Host Match (a.com) -> Index Hit
        let mut req_a = RequestHeader::build("GET", b"/", None).unwrap();
        req_a.insert_header("Host", "a.com").unwrap();
        let match_a = router
            .match_request(&req_a)
            .expect("Should match service_a");
        assert_eq!(match_a.upstream_name.as_ref(), "backend_a");

        // Scenario B: Specific Host Match (b.com) -> Index Hit
        let mut req_b = RequestHeader::build("GET", b"/foo", None).unwrap();
        req_b.insert_header("Host", "b.com").unwrap();
        let match_b = router
            .match_request(&req_b)
            .expect("Should match service_b");
        assert_eq!(match_b.upstream_name.as_ref(), "backend_b");

        // Scenario C1: Hybrid Match by Host (c.com) -> Index Hit (or safe fallback)
        let mut req_c1 = RequestHeader::build("GET", b"/anything", None).unwrap();
        req_c1.insert_header("Host", "c.com").unwrap();
        let match_c1 = router
            .match_request(&req_c1)
            .expect("Should match service_hybrid by host");
        assert_eq!(match_c1.upstream_name.as_ref(), "backend_hybrid");

        // Scenario C2: Hybrid Match by Path (/c) with DIFFERENT Host -> Catch-all Hit
        let mut req_c2 = RequestHeader::build("GET", b"/c/foo", None).unwrap();
        req_c2.insert_header("Host", "other.com").unwrap();
        let match_c2 = router
            .match_request(&req_c2)
            .expect("Should match service_hybrid by path (catch-all)");
        assert_eq!(match_c2.upstream_name.as_ref(), "backend_hybrid");

        // Scenario D: Wildcard Match (/wild) -> Catch-all Hit
        let mut req_d = RequestHeader::build("GET", b"/wild/bar", None).unwrap();
        req_d.insert_header("Host", "random.com").unwrap();
        let match_d = router
            .match_request(&req_d)
            .expect("Should match service_wild");
        assert_eq!(match_d.upstream_name.as_ref(), "backend_wild");

        // Scenario E: No Match
        let mut req_e = RequestHeader::build("GET", b"/nomatch", None).unwrap();
        req_e.insert_header("Host", "other.com").unwrap();
        let match_e = router.match_request(&req_e);
        assert!(match_e.is_none());

        // Scenario F: Complex No-Wild Match
        // F1: Match c.com (first branch of OR) -> Index Hit
        let mut req_f1 = RequestHeader::build("GET", b"/anything", None).unwrap();
        req_f1.insert_header("Host", "c.com").unwrap();
        let match_f1 = router
            .match_request(&req_f1)
            .expect("Should match complex rule via c.com");

        assert_eq!(match_f1.upstream_name.as_ref(), "backend_hybrid");

        // F2: Match a.com/c (second branch of OR) -> Index Hit under a.com
        let mut req_f2 = RequestHeader::build("GET", b"/c/foo", None).unwrap();
        req_f2.insert_header("Host", "a.com").unwrap();
        // service_a is index 0. It matches Host("a.com").
        // Rules: service_a matches "/c/foo" (Host matches).
        // So service_a will match first.
        let match_f2 = router
            .match_request(&req_f2)
            .expect("Should match service_a");
        assert_eq!(match_f2.upstream_name.as_ref(), "backend_a");

        // F3: Test catch-all exclusion
        // If we send Host: other.com and Path: /c/foo:
        // - service_complex: `Host(c) || (Host(a) && Path(/c))` -> Mismatch (Host other!=c, other!=a)
        // - service_hybrid: `Host(c) || Path(/c)` -> Match (Path /c matches)
        // So we expect backend_hybrid.
        let mut req_f3 = RequestHeader::build("GET", b"/c/foo", None).unwrap();
        req_f3.insert_header("Host", "other.com").unwrap();
        let match_f3 = router
            .match_request(&req_f3)
            .expect("Should match service_hybrid (catch-all)");
        assert_eq!(match_f3.upstream_name.as_ref(), "backend_hybrid");

        // Verify catch_all indices count
        // service_wild (PathPrefix /wild) -> Wildcard
        // service_hybrid (PathPrefix /c part) -> Wildcard
        // service_a (Host a) -> Specific
        // service_b (Host b) -> Specific
        // service_complex_no_wild -> Specific (Host c, Host a)
        // Total catch-all should be 2.
        assert_eq!(router.catch_all_indices.load().len(), 2);
    }
}
