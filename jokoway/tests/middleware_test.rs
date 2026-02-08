use futures_util::{SinkExt, StreamExt};
use jokoway::config::models::{
    JokowayConfig, Route, Rule, Service, ServiceProtocol, Upstream, UpstreamServer,
};
use jokoway::prelude::*;
use jokoway::server::app::App;
use jokoway::server::context::AppCtx;
use pingora::proxy::Session;
use pingora::server::configuration::Opt;
use reqwest::Client;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

mod common;
use common::{start_http_mock, start_ws_mock};

// --- HTTP Middleware ---

struct TestHttpMiddleware;

#[async_trait::async_trait]
impl HttpMiddleware for TestHttpMiddleware {
    type CTX = ();

    fn name(&self) -> &'static str {
        "TestHttpMiddleware"
    }

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppCtx,
    ) -> Result<bool, Box<pingora::Error>> {
        session
            .req_header_mut()
            .insert_header("x-test-middleware", "processed")
            .unwrap();
        Ok(false)
    }
}

// --- WebSocket Middleware ---

struct TestWsMiddleware;

impl WebsocketMiddleware for TestWsMiddleware {
    type CTX = ();

    fn name(&self) -> &'static str {
        "TestWsMiddleware"
    }

    fn new_ctx(&self) -> Self::CTX {}

    fn on_message(
        &self,
        _direction: WebsocketDirection,
        mut frame: WsFrame,
        _ctx: &mut Self::CTX,
    ) -> WebsocketMessageAction {
        if let Some(text) = frame.text() {
            let modified = format!("{}_modified", text);
            frame.set_text(&modified);
        }
        WebsocketMessageAction::Forward(frame)
    }
}

#[tokio::test]
async fn test_http_middleware() {
    let _ = env_logger::try_init();

    // 1. Setup Mock
    let mock_server = start_http_mock().await;
    Mock::given(method("GET"))
        .and(path("/middleware"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ack"))
        .mount(&mock_server)
        .await;

    // 2. Configure Jokoway
    let ups_name = "mock-mid";
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
            name: "mid-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "mid-route".to_string(),
                rules: vec![Rule {
                    rule: "PathPrefix(`/middleware`)".to_string(),
                    priority: Some(1),
                    ..Default::default()
                }],
            }],
            ..Default::default()
        })],
        ..Default::default()
    };

    // 3. Start App with Middleware
    let mut app = App::new(config, None, Opt::default(), vec![], vec![]);
    app.add_middleware(TestHttpMiddleware);

    std::thread::spawn(move || {
        if let Err(e) = app.run() {
            eprintln!("App failed: {:?}", e);
        }
    });

    // 4. Test
    let client = Client::new();
    let url = format!("http://127.0.0.1:{}/middleware", port);

    let mut success = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status() == 200 {
                success = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(success, "Failed to reach proxy");

    // Verify upstream received the header added by middleware
    let requests = mock_server.received_requests().await.unwrap();
    let req = requests
        .iter()
        .find(|r| r.url.path() == "/middleware")
        .expect("Request not found at mock");

    let has_header = req
        .headers
        .get("x-test-middleware")
        .map(|v| v.to_str().unwrap() == "processed")
        .unwrap_or(false);

    assert!(
        has_header,
        "Upstream did not receive header from middleware"
    );
}

#[tokio::test]
async fn test_websocket_middleware() {
    let _ = env_logger::try_init();

    // 1. Setup Mock WS
    let (ws_upstream_url, _handle) = start_ws_mock().await;
    let ws_upstream_addr = ws_upstream_url.trim_start_matches("ws://");

    // 2. Configure Jokoway
    let ups_name = "mock-mid-ws";

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
            name: "mid-ws-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Ws],
            routes: vec![Route {
                name: "mid-ws-route".to_string(),
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

    // 3. Start App with WS Middleware
    let mut app = App::new(config, None, Opt::default(), vec![], vec![]);
    app.add_websocket_middleware(TestWsMiddleware);

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
            socket
                .send(Message::Text("ping".into()))
                .await
                .expect("Failed to send");

            if let Some(msg) = socket.next().await {
                let msg = msg.expect("Failed to read");
                if let Ok(text) = msg.into_text() {
                    // "ping" -> "ping_modified" (Upstream) -> echo -> "ping_modified_modified" (Downstream)
                    assert_eq!(text, "ping_modified_modified");
                    success = true;
                    break;
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        success,
        "Failed to connect to WS proxy or verify middleware logic at {}",
        url
    );
}

#[test]
fn test_manual_downcast() {
    let middleware = TestWsMiddleware;
    let dyn_middleware: Arc<dyn jokoway::prelude::WebsocketMiddlewareDyn> = Arc::new(middleware);

    let mut ctx = dyn_middleware.new_ctx_dyn();
    let frame = WsFrame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: jokoway_core::websocket::WsOpcode::Text,
        payload: bytes::Bytes::from_static(b"hello"),
    };

    dyn_middleware.on_message_dyn(
        WebsocketDirection::UpstreamToDownstream,
        frame,
        ctx.as_mut(),
    );
}

#[tokio::test]
async fn test_manual_http_downcast() {
    let middleware = TestHttpMiddleware;
    let dyn_middleware: Arc<dyn jokoway::prelude::HttpMiddlewareDyn> = Arc::new(middleware);

    let mut ctx = dyn_middleware.new_ctx_dyn();

    let ctx_any: &mut (dyn std::any::Any + Send + Sync) = ctx.as_mut();
    assert!(
        ctx_any.downcast_mut::<()>().is_some(),
        "Manual downcast failed!"
    );
}
