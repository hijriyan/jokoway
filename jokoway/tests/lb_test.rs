use common::start_http_mock;
use jokoway::config::models::{
    JokowayConfig, LoadBalancingConfig, LoadBalancingKey, LoadBalancingStrategy, Route, Service,
    ServiceProtocol, Upstream, UpstreamServer,
};
use jokoway::server::app::App;
use pingora::server::configuration::Opt;
use reqwest::Client;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

mod common;

async fn setup_app_and_mocks(
    lb_config: LoadBalancingConfig,
) -> (u16, wiremock::MockServer, wiremock::MockServer) {
    let mock_server_1 = start_http_mock().await;
    Mock::given(method("GET"))
        .and(path("/lb-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("server1"))
        .mount(&mock_server_1)
        .await;

    let mock_server_2 = start_http_mock().await;
    Mock::given(method("GET"))
        .and(path("/lb-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("server2"))
        .mount(&mock_server_2)
        .await;

    let mock_addr_1 = mock_server_1.uri().trim_start_matches("http://").to_string();
    let mock_addr_2 = mock_server_2.uri().trim_start_matches("http://").to_string();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let config = JokowayConfig {
        http_listen: format!("127.0.0.1:{}", port),
        upstreams: vec![Upstream {
            name: "lb-upstream".to_string(),
            lb: lb_config,
            servers: vec![
                UpstreamServer {
                    host: mock_addr_1,
                    weight: Some(1),
                    ..Default::default()
                },
                UpstreamServer {
                    host: mock_addr_2,
                    weight: Some(1),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        services: vec![Arc::new(Service {
            name: "lb-service".to_string(),
            host: "lb-upstream".to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "lb-route".to_string(),
                rule: "PathPrefix(`/`)".to_string(),
                priority: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        })],
        ..Default::default()
    };

    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![]);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // Wait for the app to be ready
    sleep(Duration::from_millis(500)).await;

    (port, mock_server_1, mock_server_2)
}

#[tokio::test]
async fn test_lb_round_robin() {
    let _ = env_logger::try_init();

    let (port, _server1, _server2) = setup_app_and_mocks(LoadBalancingConfig {
        strategy: LoadBalancingStrategy::RoundRobin,
        key: None,
    })
    .await;

    let client = Client::new();
    let url = format!("http://127.0.0.1:{}/lb-test", port);

    let mut responses = Vec::new();
    for _ in 0..4 {
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        responses.push(body);
    }

    // Since it's round-robin with equal weight, it should strictly alternate
    let server1_count = responses.iter().filter(|b| *b == "server1").count();
    let server2_count = responses.iter().filter(|b| *b == "server2").count();

    assert_eq!(server1_count, 2);
    assert_eq!(server2_count, 2);
}

#[tokio::test]
async fn test_lb_random() {
    let _ = env_logger::try_init();

    let (port, _server1, _server2) = setup_app_and_mocks(LoadBalancingConfig {
        strategy: LoadBalancingStrategy::Random,
        key: None,
    })
    .await;

    let client = Client::new();
    let url = format!("http://127.0.0.1:{}/lb-test", port);

    let mut responses = Vec::new();
    for _ in 0..50 {
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        responses.push(body);
    }

    let server1_count = responses.iter().filter(|b| *b == "server1").count();
    let server2_count = responses.iter().filter(|b| *b == "server2").count();

    // With 50 random requests, the chance of all going to one server is astronomically low
    assert!(server1_count > 0, "Server 1 did not receive any requests");
    assert!(server2_count > 0, "Server 2 did not receive any requests");
}

#[tokio::test]
async fn test_lb_fnvhash() {
    let _ = env_logger::try_init();

    let (port, _server1, _server2) = setup_app_and_mocks(LoadBalancingConfig {
        strategy: LoadBalancingStrategy::FnvHash,
        key: Some(LoadBalancingKey::Header {
            name: "x-user-id".to_string(),
        }),
    })
    .await;

    let client = Client::new();
    let url = format!("http://127.0.0.1:{}/lb-test", port);

    // Test 1: Same header should always go to the same server
    let mut identical_responses = Vec::new();
    for _ in 0..10 {
        let resp = client
            .get(&url)
            .header("x-user-id", "same-user-123")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        identical_responses.push(body);
    }

    let first_response = &identical_responses[0];
    assert!(
        identical_responses.iter().all(|r| r == first_response),
        "FnvHash did not route identical keys to the same backend"
    );

    // Test 2: Different headers should distribute across servers
    let mut different_responses = Vec::new();
    for i in 0..50 {
        let resp = client
            .get(&url)
            .header("x-user-id", format!("user-{}", i))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        different_responses.push(body);
    }

    let server1_count = different_responses.iter().filter(|b| *b == "server1").count();
    let server2_count = different_responses.iter().filter(|b| *b == "server2").count();

    assert!(server1_count > 0, "Server 1 did not receive any hashed requests");
    assert!(server2_count > 0, "Server 2 did not receive any hashed requests");
}

#[tokio::test]
async fn test_lb_consistent() {
    let _ = env_logger::try_init();

    let (port, _server1, _server2) = setup_app_and_mocks(LoadBalancingConfig {
        strategy: LoadBalancingStrategy::Consistent,
        key: Some(LoadBalancingKey::Header {
            name: "x-session-id".to_string(),
        }),
    })
    .await;

    let client = Client::new();
    let url = format!("http://127.0.0.1:{}/lb-test", port);

    // Test 1: Same header should always go to the same server
    let mut identical_responses = Vec::new();
    for _ in 0..10 {
        let resp = client
            .get(&url)
            .header("x-session-id", "same-session-456")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        identical_responses.push(body);
    }

    let first_response = &identical_responses[0];
    assert!(
        identical_responses.iter().all(|r| r == first_response),
        "Consistent hashing did not route identical keys to the same backend"
    );

    // Test 2: Different headers should distribute across servers
    let mut different_responses = Vec::new();
    for i in 0..50 {
        let resp = client
            .get(&url)
            .header("x-session-id", format!("session-{}", i))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        different_responses.push(body);
    }

    let server1_count = different_responses.iter().filter(|b| *b == "server1").count();
    let server2_count = different_responses.iter().filter(|b| *b == "server2").count();

    assert!(server1_count > 0, "Server 1 did not receive any consistent hashed requests");
    assert!(server2_count > 0, "Server 2 did not receive any consistent hashed requests");
}
