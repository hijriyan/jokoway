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
use wiremock::matchers::{any, method, path};
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
        })],
        ..Default::default()
    };

    // 3. Start App in background thread
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![]);

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
        // 5 seconds timeout
        if let Ok(resp) = client.get(&url).send().await
            && resp.status() == 200
        {
            let body = resp.text().await.unwrap();
            assert_eq!(body, "world");
            success = true;
            break;
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
        })],
        ..Default::default()
    };

    // 3. Start App
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![]);

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
        })],
        ..Default::default()
    };

    // 4. Start App
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![]);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });
    sleep(Duration::from_millis(100)).await;
    // 5. Build Client with CA trust
    let cert = reqwest::Certificate::from_pem(certs.ca_cert.as_bytes()).unwrap();
    let client = Client::builder()
        .add_root_certificate(cert)
        .build()
        .unwrap();

    let url = format!("https://localhost:{}/secure", port_https);

    let mut success = false;
    if let Ok(resp) = client.get(&url).send().await
        && resp.status() == 200
    {
        let body = resp.text().await.unwrap();
        assert_eq!(body, "secure world");
        success = true;
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
        })],
        ..Default::default()
    };

    // 5. Start App
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![]);

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
        if let Ok(resp) = client.get(&url).send().await
            && resp.status() == 200
        {
            // Our mock server returns 200 OK
            success = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        success,
        "Failed to connect to mTLS upstream via proxy at {}",
        url
    );
}

#[tokio::test]
async fn test_health_check() {
    let _ = env_logger::try_init();

    // 1. Setup two mock HTTP servers
    let mock_server1 = start_http_mock().await;
    let mock_server2 = start_http_mock().await;

    // Configure server1
    Mock::given(method("GET"))
        .and(path("/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("server1")
                .append_header("Connection", "close"),
        )
        .mount(&mock_server1)
        .await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("OK")
                .append_header("Connection", "close"),
        )
        .mount(&mock_server1)
        .await;

    // Configure server2
    Mock::given(method("GET"))
        .and(path("/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("server2")
                .append_header("Connection", "close"),
        )
        .mount(&mock_server2)
        .await;

    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("OK")
                .append_header("Connection", "close"),
        )
        .mount(&mock_server2)
        .await;

    // 2. Configure Jokoway
    let ups_name = "mock-health-check";
    let mock_uri1 = mock_server1.uri();
    let mock_addr1 = mock_uri1.trim_start_matches("http://");
    let mock_uri2 = mock_server2.uri();
    let mock_addr2 = mock_uri2.trim_start_matches("http://");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let config = JokowayConfig {
        http_listen: format!("127.0.0.1:{}", port),
        upstreams: vec![Upstream {
            name: ups_name.to_string(),
            servers: vec![
                UpstreamServer {
                    host: mock_addr1.to_string(),
                    weight: Some(1),
                    ..Default::default()
                },
                UpstreamServer {
                    host: mock_addr2.to_string(),
                    weight: Some(1),
                    ..Default::default()
                },
            ],
            health_check: Some(jokoway::config::models::HealthCheckConfig {
                check_type: jokoway::config::models::HealthCheckType::Http,
                interval: 1,
                timeout: 1,
                unhealthy_threshold: 2,
                healthy_threshold: 1,
                path: Some("/health".to_string()),
                method: Some("GET".to_string()),
                expected_status: Some(vec![200]),
                headers: None,
            }),
            update_frequency: Some(5),
            ..Default::default()
        }],
        services: vec![Arc::new(Service {
            name: "test-health-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "test-health-route".to_string(),
                rules: vec![Rule {
                    rule: "PathPrefix(`/`)".to_string(),
                    priority: Some(1),
                    ..Default::default()
                }],
            }],
        })],
        ..Default::default()
    };

    // 3. Start App
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![]);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    let url = format!("http://127.0.0.1:{}/api", port);

    // Create client
    let client = Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();

    sleep(Duration::from_millis(100)).await;

    // 4. Phase 1: 1 request to identify server
    println!("Phase 1: Identifying active server...");
    let resp = client.get(&url).send().await.unwrap();
    let first_server = resp.text().await.unwrap();
    println!("First request handled by: {}", first_server);

    // 5. Phase 2: Identify server and 'Crash' it
    if first_server == "server1" {
        println!("Crashing server1...");
        mock_server1.reset().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server1)
            .await;
    } else {
        println!("Crashing server2...");
        mock_server2.reset().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server2)
            .await;
    }

    // Wait for health checks to fail (3s)
    println!("Waiting for health checks (3s)...");
    sleep(Duration::from_secs(3)).await;

    println!("Running 9 requests...");
    let mut s1_count = 0;
    let mut s2_count = 0;
    let mut failed_count = 0;

    // Use a new client just to be safe regarding connection pooling
    let client2 = Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();

    for i in 1..=9 {
        if let Ok(resp) = client2.get(&url).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap();
                println!("Request {}: {}", i, body);
                if body == "server1" {
                    s1_count += 1;
                } else if body == "server2" {
                    s2_count += 1;
                }
            } else {
                println!("Request {}: Failed with status {}", i, resp.status());
                failed_count += 1;
            }
        } else {
            println!("Request {}: Connection Error", i);
            failed_count += 1;
        }
        // sleep(Duration::from_millis(10)).await;
    }

    // 7. Verify Results
    println!("\nSummary:");
    if first_server == "server1" {
        println!("Initial (Server1): 1 (Crashed)");
    } else {
        println!("Initial (Server2): 1 (Crashed)");
    }
    println!("Subsequent (Server1): {}", s1_count);
    println!("Subsequent (Server2): {}", s2_count);
    println!("Failed: {}", failed_count);

    // Assert that the crashed server got 0 subsequent requests
    if first_server == "server1" {
        assert_eq!(
            s1_count, 0,
            "Server1 (crashed) should have 0 subsequent requests"
        );
        assert_eq!(s2_count, 9, "Server2 should have 9 subsequent requests");
    } else {
        assert_eq!(s1_count, 9, "Server1 should have 9 subsequent requests");
        assert_eq!(
            s2_count, 0,
            "Server2 (crashed) should have 0 subsequent requests"
        );
    }

    // Also verify no failures occurred (health check should have prevented routing to dead server)
    assert_eq!(failed_count, 0, "Should have 0 failed requests");

    // 8. restart crashed server
    println!("\nPhase 2: Restarting crashed server...");
    if first_server == "server1" {
        mock_server1.reset().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("server1")
                    .append_header("Connection", "close"),
            )
            .mount(&mock_server1)
            .await;
    } else {
        mock_server2.reset().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("server2")
                    .append_header("Connection", "close"),
            )
            .mount(&mock_server2)
            .await;
    }

    // Wait for health checks to recover (3s)
    println!("Waiting for health checks (3s)...");
    sleep(Duration::from_secs(3)).await;

    // 9. Run 9 requests
    println!("Running 9 requests...");
    let mut s1_count = 0;
    let mut s2_count = 0;
    let mut failed_count = 0;

    // Use a new client just to be safe regarding connection pooling
    let client3 = Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();

    for i in 1..=9 {
        if let Ok(resp) = client3.get(&url).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap();
                println!("Request {}: {}", i, body);
                if body == "server1" {
                    s1_count += 1;
                } else if body == "server2" {
                    s2_count += 1;
                }
            } else {
                println!("Request {}: Failed with status {}", i, resp.status());
                failed_count += 1;
            }
        } else {
            println!("Request {}: Connection Error", i);
            failed_count += 1;
        }
        // sleep(Duration::from_millis(10)).await;
    }

    // 10. Verify Results
    println!("\nSummary:");
    if first_server == "server1" {
        println!("Initial (Server1)");
        assert!(!mock_server1.received_requests().await.unwrap().is_empty());
    } else {
        println!("Initial (Server2)");
        assert!(!mock_server2.received_requests().await.unwrap().is_empty());
    }
    println!("Subsequent (Server1): {}", s1_count);
    println!("Subsequent (Server2): {}", s2_count);
    println!("Failed: {}", failed_count);

    assert_eq!(s1_count + s2_count, 9, "Should have 9 successful requests");
    // Also verify no failures occurred (health check should have prevented routing to dead server)
    assert_eq!(failed_count, 0, "Should have 0 failed requests");

    println!("\n✓ Health check test passed!");
}

#[tokio::test]
async fn test_proxy_404_no_hang() {
    let _ = env_logger::try_init();

    // 1. Configure Jokoway (no upstreams needed for 404 test)
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let config = JokowayConfig {
        http_listen: format!("127.0.0.1:{}", port),
        ..Default::default()
    };

    // 2. Start App
    let opt = Opt::default();
    let app = App::new(config, None, opt, vec![]);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // 3. Test 404 Response
    let url = format!("http://127.0.0.1:{}/not-found", port);
    let client = Client::builder()
        .timeout(Duration::from_secs(2)) // Short timeout to fail fast if it hangs
        .build()
        .unwrap();

    // Retry loop to allow server startup
    let mut success = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(&url).send().await {
            assert_eq!(resp.status(), 404);
            // Verify Content-Length header is present
            assert!(resp.headers().contains_key("content-length"));
            assert_eq!(resp.headers()["content-length"], "0");
            success = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(success, "Failed to get 404 response or connection hung");
}
