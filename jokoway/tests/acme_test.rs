#![cfg(feature = "acme_tests")]

use jokoway::config::models::{
    JokowayConfig, Route, Service, ServiceProtocol, SslSettings, Upstream, UpstreamServer,
};
use jokoway::prelude::{AcmeChallengeType, AcmeSettings};
use jokoway::server::app::App;
use pingora::prelude::Opt;
use reqwest::Client;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use wiremock::matchers::method;
use wiremock::{Mock, ResponseTemplate};

mod common;

const PEBBLE_ACME_PORT: u16 = 14000;

fn get_pebble_ca_path() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    PathBuf::from(manifest_dir).join("tests/pebble/certs/ca.pem")
}

/// Build a reqwest client that trusts Pebble's CA (for talking to Pebble API)
fn pebble_client() -> Client {
    let ca_path = get_pebble_ca_path();
    Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(&ca_path).unwrap()).unwrap())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Ensure Pebble is reachable, panic with helpful message if not
async fn assert_pebble_reachable() {
    let pebble_dir_url = format!("https://localhost:{}/dir", PEBBLE_ACME_PORT);
    let client = pebble_client();
    if client.get(&pebble_dir_url).send().await.is_err() {
        panic!(
            "Could not connect to Pebble at {}. Ensure 'docker compose up' is running in 'jokoway/tests/pebble'.",
            pebble_dir_url
        );
    }
}

/// Create a Jokoway config for ACME testing
fn create_acme_config(
    http_port: u16,
    https_port: u16,
    protocol: ServiceProtocol,
    challenge: AcmeChallengeType,
    acme_storage_path: &std::path::Path,
    upstream_port: u16,
) -> JokowayConfig {
    let pebble_dir_url = format!("https://localhost:{}/dir", PEBBLE_ACME_PORT);

    let acme_settings = AcmeSettings {
        ca_server: pebble_dir_url,
        email: "test@example.com".to_string(),
        storage: acme_storage_path.to_str().unwrap().to_string(),
        challenge,
        insecure: true,
        renewal_interval: Some(10),
    };

    let mut config = JokowayConfig {
        http_listen: format!("0.0.0.0:{}", http_port),
        https_listen: Some(format!("0.0.0.0:{}", https_port)),
        ssl: Some(SslSettings::default()),
        extra: std::collections::HashMap::new(),
        services: vec![Arc::new(Service {
            name: "test-acme-service".to_string(),
            host: "dummy".to_string(),
            protocols: vec![protocol],
            routes: vec![Route {
                name: "catch-all".to_string(),
                rule: "Host(`test.com`)".to_string(),
                priority: Some(1),
                ..Default::default()
            }],
        })],
        upstreams: vec![Upstream {
            name: "dummy".to_string(),
            servers: vec![UpstreamServer {
                host: format!("127.0.0.1:{}", upstream_port),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let acme_val = serde_yaml::to_value(acme_settings).unwrap();
    config.extra.insert("acme".to_string(), acme_val);
    config
}

/// Wait for ACME certificate to appear in storage file
async fn wait_for_certificate(acme_storage_path: &std::path::Path, domain: &str) {
    for _ in 0..300 {
        if acme_storage_path.exists() {
            let content = fs::read_to_string(acme_storage_path).unwrap();
            if content.contains(domain) && content.contains("BEGIN CERTIFICATE") {
                return;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "Failed to obtain certificate for {} within 30 seconds",
        domain
    );
}

/// Verify that the HTTPS connection uses a valid certificate for the domain
async fn verify_https_connection(port: u16, domain: &str) {
    let client = Client::builder()
        .resolve_to_addrs(domain, &[SocketAddr::from(([127, 0, 0, 1], port))])
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .build()
        .unwrap();

    let url = format!("https://{}:{}/", domain, port);
    let mut success = false;

    // Retry loop for connection
    for _ in 0..20 {
        match client.get(&url).send().await {
            Ok(resp) => {
                // Connection successful (even if 500 error), now verify cert
                let tls_info = resp
                    .extensions()
                    .get::<reqwest::tls::TlsInfo>()
                    .expect("TlsInfo not found in response extensions");

                let der = tls_info
                    .peer_certificate()
                    .expect("No peer certificate found in TlsInfo");

                let cert = boring::x509::X509::from_der(der)
                    .expect("Failed to parse peer certificate from DER");

                let sans: Vec<String> = cert
                    .subject_alt_names()
                    .expect("No SAN extension found in certificate")
                    .iter()
                    .filter_map(|name| name.dnsname().map(|s| s.to_string()))
                    .collect();

                assert!(
                    sans.contains(&domain.to_string()),
                    "Certificate SANs {:?} do not contain expected domain '{}'",
                    sans,
                    domain
                );

                success = true;
                break;
            }
            Err(e) => {
                println!("Failing to connect to {}: {}", url, e);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    assert!(success, "Failed to establish HTTPS connection to {}", url);
}

// -- Tests --
// Each test uses different ports to avoid conflicts (Pingora's Server::run never returns).
// Pebble validates HTTP-01 on httpPort=5002 and TLS-ALPN-01 on tlsPort=5003
// (configured in pebble-config.json), so the matching port must stay the same.

#[tokio::test]
async fn test_acme_pebble_http01() {
    let _ = env_logger::try_init();
    assert_pebble_reachable().await;

    // HTTP=5002 must match Pebble's httpPort, HTTPS=5013 avoids conflict with TLS-ALPN test
    const HTTP_PORT: u16 = 5002;
    const HTTPS_PORT: u16 = 5013;

    let temp_dir =
        std::env::temp_dir().join(format!("jokoway_acme_http01_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let storage_path = temp_dir.join("acme.json");

    // Start mock upstream
    let mock_server = common::start_http_mock().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = create_acme_config(
        HTTP_PORT,
        HTTPS_PORT,
        ServiceProtocol::Https,
        AcmeChallengeType::Http01,
        &storage_path,
        mock_server.address().port(),
    );

    let app = App::new(config, None, Opt::default(), vec![]);
    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // Wait for ACME cert issuance
    wait_for_certificate(&storage_path, "test.com").await;

    // Verify the cert contains the expected domain
    // Verify HTTPS is actually served (and cert is valid)
    verify_https_connection(HTTPS_PORT, "test.com").await;

    fs::remove_dir_all(&temp_dir).unwrap_or(());
}

#[tokio::test]
async fn test_acme_pebble_tls_alpn_01() {
    let _ = env_logger::try_init();
    assert_pebble_reachable().await;

    // HTTPS=5003 must match Pebble's tlsPort, HTTP=5012 avoids conflict with HTTP-01 test
    const HTTP_PORT: u16 = 5012;
    const HTTPS_PORT: u16 = 5003;

    let temp_dir = std::env::temp_dir().join(format!("jokoway_acme_alpn_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();
    let storage_path = temp_dir.join("acme.json");

    // Start mock upstream
    let mock_server = common::start_http_mock().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = create_acme_config(
        HTTP_PORT,
        HTTPS_PORT,
        ServiceProtocol::Https,
        AcmeChallengeType::TlsAlpn01,
        &storage_path,
        mock_server.address().port(),
    );

    let app = App::new(config, None, Opt::default(), vec![]);
    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // Wait for ACME cert issuance
    wait_for_certificate(&storage_path, "test.com").await;

    // Verify HTTPS is actually served (and cert is valid)
    verify_https_connection(HTTPS_PORT, "test.com").await;

    fs::remove_dir_all(&temp_dir).unwrap_or(());
}
