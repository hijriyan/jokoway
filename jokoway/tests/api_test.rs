use jokoway::config::models::{
    ApiSettings, BasicAuth, JokowayConfig, RateLimit, Route, Service, ServiceProtocol, Upstream,
    UpstreamServer,
};
use jokoway::extensions::api::{
    AddServiceRequest, AddUpstreamRequest, RemoveServiceRequest, RemoveUpstreamRequest,
    ServiceListResponse, SuccessResponse, UpstreamListResponse,
};
use jokoway::server::app::App;
use pingora::server::configuration::Opt;
use reqwest::Client;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;

mod common;
use common::start_http_mock;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

// Helper to get a random port
async fn get_random_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

// Helper to start the app with specific API settings
async fn start_app_with_api(api_settings: ApiSettings) -> u16 {
    let port = get_random_port().await;
    let mut api_settings = api_settings;

    // Override listen address to use the random port
    api_settings.listen = Some(format!("127.0.0.1:{}", port));

    let config = JokowayConfig {
        http_listen: "127.0.0.1:0".to_string(), // Disable HTTP for this test or use random
        api: Some(api_settings),
        ..Default::default()
    };

    let app = App::new(config, None, Opt::default(), vec![]);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // Wait for server to start
    sleep(Duration::from_millis(500)).await;
    port
}

#[tokio::test]
async fn test_api_basic_auth() {
    let _ = env_logger::try_init();

    let api_settings = ApiSettings {
        basic_auth: Some(BasicAuth {
            username: "admin".to_string(),
            password: "secret".to_string(),
        }),
        ..Default::default()
    };

    let port = start_app_with_api(api_settings).await;
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();

    // 1. Test without auth - should fail
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // 2. Test with incorrect auth - should fail
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .basic_auth("admin", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // 3. Test with correct auth - should succeed
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .basic_auth("admin", Some("secret"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_api_rate_limit() {
    let api_settings = ApiSettings {
        rate_limit: Some(RateLimit {
            requests_per_second: 1,
            burst: 1,
        }),
        ..Default::default()
    };

    let port = start_app_with_api(api_settings).await;
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();

    // 1. First request - should succeed
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 2. Immediate second request - should be rate limited (allow some leeway for slow CI)
    // We send multiple requests to ensure we hit the limit
    let mut limited = false;
    for _ in 0..5 {
        let resp = client
            .get(format!("{}/upstreams/list", base_url))
            .send()
            .await
            .unwrap();
        if resp.status() == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "Should have been rate limited");

    // 3. Wait for 1 second and try again - should succeed
    sleep(Duration::from_secs(2)).await; // Wait slightly more than 1s
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_api_upstreams() {
    let port = start_app_with_api(ApiSettings::default()).await;
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();

    // 1. List upstreams - initially empty
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: UpstreamListResponse = resp.json().await.unwrap();
    assert!(list.upstreams.is_empty());

    // 2. Add upstream
    let upstream = Upstream {
        name: "test-upstream".to_string(),
        servers: vec![UpstreamServer {
            host: "127.0.0.1:8080".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let resp = client
        .post(format!("{}/upstreams/add", base_url))
        .json(&AddUpstreamRequest { upstream })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let success: SuccessResponse = resp.json().await.unwrap();
    assert!(success.success);

    // 3. Verify upstream exists
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    let list: UpstreamListResponse = resp.json().await.unwrap();
    assert_eq!(list.upstreams.len(), 1);
    assert_eq!(list.upstreams[0], "test-upstream");

    // 4. Update upstream
    let updated_upstream = Upstream {
        name: "test-upstream".to_string(),
        servers: vec![UpstreamServer {
            host: "127.0.0.1:9090".to_string(), // Changed port
            ..Default::default()
        }],
        ..Default::default()
    };
    let resp = client
        .post(format!("{}/upstreams/update", base_url))
        .json(&jokoway::extensions::api::UpdateUpstreamRequest {
            name: "test-upstream".to_string(),
            upstream: updated_upstream,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 5. Remove upstream
    let resp = client
        .post(format!("{}/upstreams/remove", base_url))
        .json(&RemoveUpstreamRequest {
            name: "test-upstream".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 6. Verify removal
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    let list: UpstreamListResponse = resp.json().await.unwrap();
    assert!(list.upstreams.is_empty());
}

#[tokio::test]
async fn test_api_services() {
    let port = start_app_with_api(ApiSettings::default()).await;
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();

    // 1. List services - initially empty
    let resp = client
        .get(format!("{}/services/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: ServiceListResponse = resp.json().await.unwrap();
    assert!(list.services.is_empty());

    // 2. Add service
    let service = Service {
        name: "test-service".to_string(),
        host: "example.com".to_string(),
        protocols: vec![ServiceProtocol::Http],
        routes: vec![Route {
            name: "test-route".to_string(),
            rule: "PathPrefix(`/`)".to_string(),
            ..Default::default()
        }],
    };
    let resp = client
        .post(format!("{}/services/add", base_url))
        .json(&AddServiceRequest { service })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let success: SuccessResponse = resp.json().await.unwrap();
    assert!(success.success);

    // 3. Verify service exists
    let resp = client
        .get(format!("{}/services/list", base_url))
        .send()
        .await
        .unwrap();
    let list: ServiceListResponse = resp.json().await.unwrap();
    assert_eq!(list.services.len(), 1);
    assert_eq!(list.services[0].name, "test-service");

    // 4. Update service
    let updated_service = Service {
        name: "test-service".to_string(),
        host: "updated.example.com".to_string(), // Changed host
        protocols: vec![ServiceProtocol::Http],
        routes: vec![Route {
            name: "test-route".to_string(),
            rule: "PathPrefix(`/updated`)".to_string(),
            ..Default::default()
        }],
    };
    let resp = client
        .post(format!("{}/services/update", base_url))
        .json(&jokoway::extensions::api::UpdateServiceRequest {
            name: "test-service".to_string(),
            service: updated_service,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 5. Remove service
    let resp = client
        .post(format!("{}/services/remove", base_url))
        .json(&RemoveServiceRequest {
            name: "test-service".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 6. Verify removal
    let resp = client
        .get(format!("{}/services/list", base_url))
        .send()
        .await
        .unwrap();
    let list: ServiceListResponse = resp.json().await.unwrap();
    assert!(list.services.is_empty());
}

#[tokio::test]
async fn test_proxy_via_api() {
    // 1. Setup Mock Upstream
    let mock_server = start_http_mock().await;
    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200).set_body_string("I am the target"))
        .mount(&mock_server)
        .await;

    let mock_addr = mock_server.uri().replace("http://", "");

    // 2. Setup Jokoway with API
    let api_port = get_random_port().await;
    let proxy_port = get_random_port().await;

    let api_settings = ApiSettings {
        listen: Some(format!("127.0.0.1:{}", api_port)),
        ..Default::default()
    };

    let config = JokowayConfig {
        http_listen: format!("127.0.0.1:{}", proxy_port),
        api: Some(api_settings),
        ..Default::default()
    };

    let app = App::new(config, None, Opt::default(), vec![]);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    sleep(Duration::from_millis(500)).await;

    let api_base = format!("http://127.0.0.1:{}", api_port);
    let proxy_base = format!("http://127.0.0.1:{}", proxy_port);
    let client = Client::new();

    // 3. Add Upstream via API
    let upstream = Upstream {
        name: "dynamic-upstream".to_string(),
        servers: vec![UpstreamServer {
            host: mock_addr,
            ..Default::default()
        }],
        ..Default::default()
    };
    let resp = client
        .post(format!("{}/upstreams/add", api_base))
        .json(&AddUpstreamRequest { upstream })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 4. Add Service via API
    let service = Service {
        name: "dynamic-service".to_string(),
        host: "dynamic-upstream".to_string(), // Matches upstream name
        protocols: vec![ServiceProtocol::Http],
        routes: vec![Route {
            name: "dynamic-route".to_string(),
            rule: "PathPrefix(`/target`)".to_string(),
            ..Default::default()
        }],
    };
    let resp = client
        .post(format!("{}/services/add", api_base))
        .json(&AddServiceRequest { service })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 5. Test Proxy
    // We need to send a request to the proxy with the correct Host header
    let resp = client
        .get(format!("{}/target", proxy_base))
        .header("Host", "dynamic.test")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "I am the target");
}
