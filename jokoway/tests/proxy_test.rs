use common::{start_http_mock, start_mtls_mock, start_ws_mock};
use futures_util::{SinkExt, StreamExt};
use jokoway::config::models::{
    JokowayConfig, PeerOptions, Route, Rule, Service, ServiceProtocol, Upstream, UpstreamServer,
};
use jokoway::server::app::App;
use pingora::server::configuration::Opt;
use reqwest::Client;
use std::fs;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

mod common;

#[tokio::test]
async fn test_http_proxy() {
    let _ = env_logger::try_init();

    // 1. Setup Mock
    let mock_server = start_http_mock().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200).set_body_string("world"))
        .mount(&mock_server)
        .await;

    // 2. Configure Jokoway
    let ups_name = "mock-http";
    // wiremock uri creates http://127.0.0.1:xxxxx
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");

    // Pick a random port for Jokoway
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let config = JokowayConfig {
        http_listen: format!("127.0.0.1:{}", port),
        upstreams: vec![Upstream {
            name: ups_name.to_string(),
            servers: vec![UpstreamServer {
                host: mock_addr.to_string(),
                weight: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        }],
        services: vec![Arc::new(Service {
            name: "test-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "test-route".to_string(),
                rules: vec![Rule {
                    rule: "PathPrefix(`/`)".to_string(),
                    priority: Some(1),
                    ..Default::default()
                }],
            }],
            ..Default::default()
        })],
        ..Default::default()
    };

    // 3. Start App in background thread
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![], vec![]);

    std::thread::spawn(move || {
        // App::run blocks forever
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // 4. Wait for readiness and test
    let client = Client::new();
    let url = format!("http://127.0.0.1:{}/hello", port);

    let mut success = false;
    for _ in 0..50 {
        // 5 seconds timeout
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status() == 200 {
                let body = resp.text().await.unwrap();
                assert_eq!(body, "world");
                success = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        success,
        "Failed to connect to proxy or get correct response from {}",
        url
    );
}

#[tokio::test]
async fn test_ws_proxy() {
    let _ = env_logger::try_init();

    // 1. Setup Mock WS
    let (ws_upstream_url, _handle) = start_ws_mock().await;
    let ws_upstream_addr = ws_upstream_url.trim_start_matches("ws://");

    // 2. Configure Jokoway
    let ups_name = "mock-ws";

    // Random port for Jokoway
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let config = JokowayConfig {
        http_listen: format!("127.0.0.1:{}", port),
        upstreams: vec![Upstream {
            name: ups_name.to_string(),
            servers: vec![UpstreamServer {
                host: ws_upstream_addr.to_string(),
                weight: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        }],
        services: vec![Arc::new(Service {
            name: "test-ws-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Ws],
            routes: vec![Route {
                name: "test-ws-route".to_string(),
                rules: vec![Rule {
                    rule: "PathPrefix(`/ws`)".to_string(),
                    priority: Some(1),
                    ..Default::default()
                }],
            }],
            ..Default::default()
        })],
        ..Default::default()
    };

    // 3. Start App
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![], vec![]);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // 4. Test WS connection
    let url = format!("ws://127.0.0.1:{}/ws", port);

    let mut success = false;
    for _ in 0..50 {
        if let Ok((mut socket, _)) = connect_async(&url).await {
            // Send echo message
            socket
                .send(Message::Text("ping".into()))
                .await
                .expect("Failed to send");

            if let Some(msg) = socket.next().await {
                let msg = msg.expect("Failed to read");
                if let Ok(text) = msg.into_text() {
                    assert_eq!(text, "ping");
                    success = true;
                    break;
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(success, "Failed to connect to WS proxy at {}", url);
}

#[tokio::test]
async fn test_https_proxy() {
    let _ = env_logger::try_init();

    // 1. Generate Certs
    let certs = common::generate_test_certs();

    // 2. Setup Mock
    let mock_server = start_http_mock().await;
    Mock::given(method("GET"))
        .and(path("/secure"))
        .respond_with(ResponseTemplate::new(200).set_body_string("secure world"))
        .mount(&mock_server)
        .await;

    // 3. Configure Jokoway
    let ups_name = "mock-secure";
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");

    // Random ports
    let listener_http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port_http = listener_http.local_addr().unwrap().port();
    drop(listener_http);

    let listener_https = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port_https = listener_https.local_addr().unwrap().port();
    drop(listener_https);

    // Write certs to temp files
    let temp_dir = std::env::temp_dir();
    let rand = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let server_cert_path = temp_dir.join(format!("server_cert_{}.pem", rand));
    let server_key_path = temp_dir.join(format!("server_key_{}.pem", rand));

    fs::write(&server_cert_path, &certs.server_cert).unwrap();
    fs::write(&server_key_path, &certs.server_key).unwrap();

    let config = JokowayConfig {
        http_listen: format!("127.0.0.1:{}", port_http),
        https_listen: Some(format!("127.0.0.1:{}", port_https)),
        ssl: Some(jokoway::config::models::SslSettings {
            server_cert: Some(server_cert_path.to_str().unwrap().to_string()),
            server_key: Some(server_key_path.to_str().unwrap().to_string()),
            ..Default::default()
        }),
        upstreams: vec![Upstream {
            name: ups_name.to_string(),
            servers: vec![UpstreamServer {
                host: mock_addr.to_string(),
                weight: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        }],
        services: vec![Arc::new(Service {
            name: "secure-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Https],
            routes: vec![Route {
                name: "secure-route".to_string(),
                rules: vec![Rule {
                    rule: "PathPrefix(`/secure`)".to_string(),
                    priority: Some(1),
                    ..Default::default()
                }],
            }],
            ..Default::default()
        })],
        ..Default::default()
    };

    // 4. Start App
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![], vec![]);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // 5. Build Client with CA trust
    let cert = reqwest::Certificate::from_pem(certs.ca_cert.as_bytes()).unwrap();
    let client = Client::builder()
        .add_root_certificate(cert)
        .build()
        .unwrap();

    let url = format!("https://localhost:{}/secure", port_https);

    let mut success = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status() == 200 {
                let body = resp.text().await.unwrap();
                assert_eq!(body, "secure world");
                success = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(success, "Failed to connect to HTTPS proxy at {}", url);
}

#[tokio::test]
async fn test_mtls_upstream() {
    let _ = env_logger::try_init();

    // 1. Generate Certs
    let certs = common::generate_test_certs();

    // 2. Setup mTLS Mock
    // The mock server requires a client cert signed by our CA
    let (mock_addr, _handle) = start_mtls_mock(&certs).await;

    // 3. Write client certs to temp files (Jokoway needs paths)
    let temp_dir = std::env::temp_dir();
    // Use somewhat unique names to avoid collisions in concurrent tests
    let rand = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let client_cert_path = temp_dir.join(format!("client_cert_{}.pem", rand));
    let client_key_path = temp_dir.join(format!("client_key_{}.pem", rand));
    let ca_cert_path = temp_dir.join(format!("ca_cert_{}.pem", rand));

    fs::write(&client_cert_path, &certs.client_cert).unwrap();
    fs::write(&client_key_path, &certs.client_key).unwrap();
    fs::write(&ca_cert_path, &certs.ca_cert).unwrap();

    // 4. Configure Jokoway
    let ups_name = "mock-mtls";

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let config = JokowayConfig {
        http_listen: format!("127.0.0.1:{}", port),
        upstreams: vec![Upstream {
            name: ups_name.to_string(),
            peer_options: None,
            servers: vec![UpstreamServer {
                host: mock_addr.clone(),
                peer_options: Some(PeerOptions {
                    verify_cert: Some(true),
                    // Trust the mock server's cert (signed by our CA)
                    cacert: Some(ca_cert_path.to_str().unwrap().to_string()),
                    // Present our client cert
                    client_cert: Some(client_cert_path.to_str().unwrap().to_string()),
                    client_key: Some(client_key_path.to_str().unwrap().to_string()),
                    ..Default::default()
                }),
                tls: Some(true),
                ..Default::default()
            }],
            ..Default::default()
        }],
        services: vec![Arc::new(Service {
            name: "mtls-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "mtls-route".to_string(),
                rules: vec![Rule {
                    rule: "PathPrefix(`/mtls`)".to_string(),
                    priority: Some(1),
                    ..Default::default()
                }],
            }],
            ..Default::default()
        })],
        ..Default::default()
    };

    // 5. Start App
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![], vec![]);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // 6. Test Connection
    // We send a normal HTTP request to Jokoway
    // Jokoway forwards it to Upstream using mTLS
    let client = Client::new();
    let url = format!("http://127.0.0.1:{}/mtls", port);

    let mut success = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status() == 200 {
                // Our mock server returns 200 OK
                success = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        success,
        "Failed to connect to mTLS upstream via proxy at {}",
        url
    );
}
