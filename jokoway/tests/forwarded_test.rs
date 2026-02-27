use jokoway::config::{
    ConfigBuilder,
    models::{Route, Service, ServiceProtocol, Upstream, UpstreamServer},
};
use jokoway::server::app::App;
use jokoway_core::Context;
use jokoway_forwarded::config::ForwardedSettings;
use pingora::server::configuration::Opt;
use reqwest::Client;
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

mod common;
use common::start_http_mock;

#[tokio::test]
async fn test_forwarded_middleware_with_trusted_proxies() {
    let _ = env_logger::try_init();

    // 1. Setup Mock Backend
    let mock_server = start_http_mock().await;

    let mock = Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200));

    mock.mount(&mock_server).await;

    // 2. Configure Jokoway
    let ups_name = "mock-forwarded";
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let (config, server_conf) = ConfigBuilder::new()
        .configure(|cfg, _| {
            cfg.http_listen = format!("127.0.0.1:{}", port);
            cfg.extra.insert(
                "http_forwarded".to_string(),
                serde_yaml::to_value(ForwardedSettings {
                    enabled: true,
                    // Allow our test client (127.0.0.1) as a trusted proxy,
                    // so it accepts our spoofed headers and also append its IP.
                    // If we don't, it might reject.
                    trusted_proxies: vec!["127.0.0.1/32".to_string()],
                })
                .unwrap(),
            );
        })
        .add_upstream(Upstream {
            name: ups_name.to_string(),
            servers: vec![UpstreamServer {
                host: mock_addr.to_string(),
                weight: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        })
        .add_service(Service {
            name: "forwarded-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "forwarded-route".to_string(),
                rule: "PathPrefix(`/test`)".to_string(),
                priority: Some(1),
                ..Default::default()
            }],
        })
        .build();

    let app = App::new(config, server_conf, Opt::default(), vec![]);

    std::thread::spawn(move || if let Err(_e) = app.run() {});

    // 4. Test
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/test", port);

    // Wait for server to be ready
    let mut ready = false;
    for _ in 0..50 {
        if client.get(&url).send().await.is_ok() {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "Server failed to start in time");

    // Clear requests from the ready check
    mock_server.reset().await;
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Send a request with spoofed headers
    let resp = client
        .get(&url)
        .header("x-forwarded-for", "203.0.113.1")
        .header("x-forwarded-host", "spoofed.com")
        .header("x-forwarded-proto", "https")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(resp.status(), 200);

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        1,
        "Expected exactly 1 request to reach backend"
    );

    let backend_req = &requests[0];
    // Jokoway should have read the spoofed headers (because 127.0.0.1 is trusted),
    // and appended the real client IP (127.0.0.1) to x-forwarded-for.
    // It should also forward host and proto.
    let x_for = backend_req
        .headers
        .get("x-forwarded-for")
        .expect("x-forwarded-for missing");
    assert_eq!(
        x_for.to_str().unwrap(),
        "203.0.113.1, 127.0.0.1",
        "Should append real client IP to existing XFF"
    );

    let x_host = backend_req
        .headers
        .get("x-forwarded-host")
        .expect("x-forwarded-host missing");
    assert_eq!(
        x_host.to_str().unwrap(),
        "spoofed.com",
        "Should preserve trusted x-forwarded-host"
    );

    let x_proto = backend_req
        .headers
        .get("x-forwarded-proto")
        .expect("x-forwarded-proto missing");
    assert_eq!(
        x_proto.to_str().unwrap(),
        "https",
        "Should preserve trusted x-forwarded-proto"
    );
}

#[tokio::test]
async fn test_forwarded_middleware_edge_proxy() {
    let _ = env_logger::try_init();

    // 1. Setup Mock Backend
    let mock_server = start_http_mock().await;

    let mock = Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200));

    mock.mount(&mock_server).await;

    // 2. Configure Jokoway
    let ups_name = "mock-forwarded-edge";
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let (config, server_conf) = ConfigBuilder::new()
        .configure(|cfg, _| {
            cfg.http_listen = format!("127.0.0.1:{}", port);
            cfg.extra.insert(
                "http_forwarded".to_string(),
                serde_yaml::to_value(ForwardedSettings {
                    enabled: true,
                    trusted_proxies: vec![], // Empty, open mode for edge proxies
                })
                .unwrap(),
            );
        })
        .add_upstream(Upstream {
            name: ups_name.to_string(),
            servers: vec![UpstreamServer {
                host: mock_addr.to_string(),
                weight: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        })
        .add_service(Service {
            name: "forwarded-service-edge".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "forwarded-route-edge".to_string(),
                rule: "PathPrefix(`/test`)".to_string(),
                priority: Some(1),
                ..Default::default()
            }],
        })
        .build();

    let app = App::new(config, server_conf, Opt::default(), vec![]);

    std::thread::spawn(move || if let Err(_e) = app.run() {});

    // 4. Test
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/test", port);

    // Wait for server to be ready
    let mut ready = false;
    for _ in 0..50 {
        if client.get(&url).send().await.is_ok() {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "Server failed to start in time");

    // Clear requests from the ready check
    mock_server.reset().await;
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Send a request without any spoofed headers
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(resp.status(), 200);

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        1,
        "Expected exactly 1 request to reach backend"
    );

    let backend_req = &requests[0];
    // Jokoway should populate headers based on actual connection
    let x_for = backend_req
        .headers
        .get("x-forwarded-for")
        .expect("x-forwarded-for missing");
    assert_eq!(
        x_for.to_str().unwrap(),
        "127.0.0.1",
        "Should use real client IP when jokoway is the first proxy"
    );

    let x_host = backend_req
        .headers
        .get("x-forwarded-host")
        .expect("x-forwarded-host missing");
    assert_eq!(
        x_host.to_str().unwrap(),
        format!("127.0.0.1:{}", port).as_str(),
        "Should use Host header when no X-Forwarded-Host provided"
    );

    let x_proto = backend_req
        .headers
        .get("x-forwarded-proto")
        .expect("x-forwarded-proto missing");
    assert_eq!(
        x_proto.to_str().unwrap(),
        "http", // Since test client connects via HTTP
        "Should use actual request protocol when no X-Forwarded-Proto provided"
    );
}

// Custom middleware to read ForwardedInfo
struct InfoReaderMiddleware {
    pub extracted_info:
        std::sync::Arc<std::sync::Mutex<Option<jokoway_forwarded::models::ForwardedInfo>>>,
}

#[async_trait::async_trait]
impl jokoway_core::JokowayMiddleware for InfoReaderMiddleware {
    type CTX = ();

    fn name(&self) -> &'static str {
        "InfoReaderMiddleware"
    }

    fn new_ctx(&self) -> Self::CTX {}

    fn order(&self) -> i16 {
        -10 // Run after ForwardedMiddleware (which has order 0)
    }

    async fn request_filter(
        &self,
        _session: &mut pingora::proxy::Session,
        _ctx: &mut Self::CTX,
        _app_ctx: &jokoway_core::AppContext,
        request_ctx: &jokoway_core::RequestContext,
    ) -> Result<bool, Box<pingora::Error>> {
        if let Some(info) = request_ctx.get::<jokoway_forwarded::models::ForwardedInfo>() {
            *self.extracted_info.lock().unwrap() = Some(info.as_ref().clone());
        }
        Ok(false)
    }
}

struct TestReaderExtension {
    reader: std::sync::Arc<InfoReaderMiddleware>,
}

impl jokoway_core::JokowayExtension for TestReaderExtension {
    fn init(
        &self,
        _server: &mut pingora::server::Server,
        _app_ctx: &mut jokoway_core::AppContext,
        middlewares: &mut Vec<std::sync::Arc<dyn jokoway_core::JokowayMiddlewareDyn>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        middlewares.push(self.reader.clone());
        Ok(())
    }
}

#[tokio::test]
async fn test_forwarded_middleware_request_ctx_extraction() {
    let _ = env_logger::try_init();

    // 1. Setup Mock Backend
    let mock_server = start_http_mock().await;

    let mock = Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200));

    mock.mount(&mock_server).await;

    // 2. Configure Jokoway
    let ups_name = "mock-forwarded-ctx";
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let (config, server_conf) = ConfigBuilder::new()
        .configure(|cfg, _| {
            cfg.http_listen = format!("127.0.0.1:{}", port);
            cfg.extra.insert(
                "http_forwarded".to_string(),
                serde_yaml::to_value(ForwardedSettings {
                    enabled: true,
                    trusted_proxies: vec![], // Edge proxy
                })
                .unwrap(),
            );
        })
        .add_upstream(Upstream {
            name: ups_name.to_string(),
            servers: vec![UpstreamServer {
                host: mock_addr.to_string(),
                weight: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        })
        .add_service(Service {
            name: "forwarded-service-ctx".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "forwarded-route-ctx".to_string(),
                rule: "Host(`kuli.dev`) && PathPrefix(`/test`)".to_string(),
                priority: Some(1),
                ..Default::default()
            }],
        })
        .build();

    let extracted_info = std::sync::Arc::new(std::sync::Mutex::new(None));
    let reader_ext = TestReaderExtension {
        reader: std::sync::Arc::new(InfoReaderMiddleware {
            extracted_info: extracted_info.clone(),
        }),
    };

    let app = App::new(
        config,
        server_conf,
        Opt::default(),
        vec![Box::new(reader_ext)],
    );

    std::thread::spawn(move || if let Err(_e) = app.run() {});

    // 4. Test
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/test", port);

    // Wait for server to be ready
    let mut ready = false;
    for _ in 0..50 {
        if client
            .get(&url)
            .header("Host", "kuli.dev")
            .send()
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "Server failed to start in time");

    // Clear requests from the ready check
    mock_server.reset().await;
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // Send a request with spoofed headers
    let resp = client
        .get(&url)
        .header("Host", "kuli.dev")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(resp.status(), 200);

    // 5. Verify that our reader middleware successfully extracted the info
    let info_opt = extracted_info.lock().unwrap().clone();
    assert!(
        info_opt.is_some(),
        "ForwardedInfo should have been extracted by the reader middleware"
    );
    let info = info_opt.unwrap();
    assert_eq!(info.for_nodes, Some("127.0.0.1".to_string()));
    assert_eq!(info.host, Some("kuli.dev".to_string()));
    assert_eq!(info.proto, Some("http".to_string()));
    assert_eq!(info.client_ip, Some("127.0.0.1".to_string()));
}
