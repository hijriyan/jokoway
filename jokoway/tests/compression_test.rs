use jokoway::config::{
    ConfigBuilder,
    models::{Route, Service, ServiceProtocol, Upstream, UpstreamServer},
};

use jokoway::server::app::App;
use jokoway_compress::{CompressionConfigBuilderExt, CompressionSettings, GzipSettings};
use pingora::server::configuration::Opt;
use reqwest::Client;
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

mod common;
use common::start_http_mock;

#[tokio::test]
async fn test_compression() {
    let _ = env_logger::try_init();

    // 1. Setup Mock
    let mock_server = start_http_mock().await;
    Mock::given(method("GET"))
        .and(path("/compress"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("A".repeat(2048))
                .append_header("content-type", "text/plain"),
        )
        .mount(&mock_server)
        .await;

    // 2. Configure Jokoway with Gzip explicitly enabled using ConfigBuilder
    let ups_name = "mock-compress";
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let (config, server_conf) = ConfigBuilder::new()
        .configure(|cfg, _| {
            cfg.http_listen = format!("127.0.0.1:{}", port);
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
            name: "compress-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "compress-route".to_string(),
                rule: "PathPrefix(`/compress`)".to_string(),
                priority: Some(1),
                ..Default::default()
            }],
        })
        .with_compression(CompressionSettings {
            gzip: Some(GzipSettings::default()),
            #[cfg(feature = "compress-brotli")]
            brotli: Some(jokoway_compress::BrotliSettings::default()),
            #[cfg(feature = "compress-zstd")]
            zstd: Some(jokoway_compress::ZstdSettings::default()),
            ..Default::default()
        })
        .build();

    let app = App::new(config, server_conf, Opt::default(), vec![]);

    std::thread::spawn(move || if let Err(_e) = app.run() {});

    // 4. Test
    // Disable auto-decompression to verify Content-Encoding header
    let client = Client::builder()
        .no_deflate()
        .no_brotli()
        .no_zstd()
        .no_gzip()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/compress", port);

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

    let resp = client
        .get(&url)
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .expect("Failed to send 4.1 request");
    assert_eq!(resp.status(), 200);
    let encoding = resp
        .headers()
        .get("content-encoding")
        .map(|v| v.to_str().unwrap());
    assert_eq!(encoding, Some("gzip"), "Should use gzip when requested");

    let bytes = resp.bytes().await.unwrap();
    println!("Gzip response: {} bytes", bytes.len());

    #[cfg(feature = "compress-brotli")]
    {
        let resp = client
            .get(&url)
            .header("Accept-Encoding", "gzip, br")
            .send()
            .await
            .expect("Failed to send 4.2 request");
        assert_eq!(resp.status(), 200);
        let encoding = resp
            .headers()
            .get("content-encoding")
            .map(|v| v.to_str().unwrap());
        assert_eq!(encoding, Some("br"), "Brotli should be preferred over gzip");

        let bytes = resp.bytes().await.unwrap();
        println!("Brotli response: {} bytes", bytes.len());
    }

    #[cfg(all(feature = "compress-brotli", feature = "compress-zstd"))]
    {
        let resp = client
            .get(&url)
            .header("Accept-Encoding", "gzip, br, zstd")
            .send()
            .await
            .expect("Failed to send 4.3 request");
        assert_eq!(resp.status(), 200);
        let encoding = resp
            .headers()
            .get("content-encoding")
            .map(|v| v.to_str().unwrap());
        assert_eq!(encoding, Some("br"), "Brotli should be preferred over all");

        let bytes = resp.bytes().await.unwrap();
        println!("Brotli (all) response: {} bytes", bytes.len());
    }

    #[cfg(feature = "compress-zstd")]
    {
        let resp = client
            .get(&url)
            .header("Accept-Encoding", "gzip, zstd")
            .send()
            .await
            .expect("Failed to send 4.4 request");
        assert_eq!(resp.status(), 200);
        let encoding = resp
            .headers()
            .get("content-encoding")
            .map(|v| v.to_str().unwrap());
        assert_eq!(encoding, Some("zstd"), "Zstd should be preferred over gzip");

        let bytes = resp.bytes().await.unwrap();
        println!("Zstd response: {} bytes", bytes.len());
    }
    let resp = client
        .get(&url)
        // .header("Accept-Encoding", "gzip")
        .send()
        .await
        .expect("Failed to send 4.5 request");
    assert_eq!(resp.status(), 200);
    let encoding = resp
        .headers()
        .get("content-encoding")
        .map(|v| v.to_str().unwrap());
    assert_eq!(
        encoding, None,
        "Should not use any compression when requested"
    );

    let bytes = resp.bytes().await.unwrap();
    println!("Plain response: {} bytes", bytes.len());
}
