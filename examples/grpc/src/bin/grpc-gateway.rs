use std::sync::Arc;

use async_trait::async_trait;
use jokoway::config::models::{
    JokowayConfig, Route, Service, ServiceProtocol, Upstream, UpstreamServer,
};
use jokoway::prelude::core::*;
use jokoway::server::app::App;
use jokoway::server::context::{AppContext, RequestContext};
use pingora::server::configuration::Opt;
use prost::Message;

// Include the generated protobufs for our middleware to decode/encode
pub mod helloworld {
    tonic::include_proto!("helloworld");
}

#[derive(Clone)]
struct LoggerGrpcMiddleware;

#[async_trait]
impl JokowayMiddleware for LoggerGrpcMiddleware {
    type CTX = ();

    fn name(&self) -> &'static str {
        "LoggerGrpcMiddleware"
    }

    fn new_ctx(&self) -> Self::CTX {}

    fn on_grpc_message(
        &self,
        direction: GrpcDirection,
        mut message: GrpcMessage,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppContext,
        _request_ctx: &RequestContext,
    ) -> GrpcMessageAction {
        match direction {
            GrpcDirection::UpstreamToClient => {
                log::info!("Intercepted Response (Upstream -> Downstream)");
                if let Ok(mut reply) = helloworld::HelloReply::decode(message.payload.clone()) {
                    log::info!("Original reply: {}", reply.message);
                    reply.message = format!("{} (intercepted by gateway)", reply.message);
                    message.payload = reply.encode_to_vec().into();
                } else {
                    log::warn!("Failed to decode GrpcMessage payload as HelloReply");
                }
            }
            GrpcDirection::ClientToUpstream => {
                log::info!("Intercepted Request (Downstream -> Upstream)");
            }
        }
        GrpcMessageAction::Forward(message)
    }
}

struct ExampleExtension;

impl JokowayExtension for ExampleExtension {
    fn init(
        &self,
        _server: &mut pingora::server::Server,
        _app_ctx: &mut AppContext,
        middlewares: &mut Vec<std::sync::Arc<dyn JokowayMiddlewareDyn>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        middlewares.push(Arc::new(LoggerGrpcMiddleware));
        log::info!("Registered LoggerGrpcMiddleware");
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let port = 8080;
    let ups_name = "grpc-backend";
    let upstream_host =
        std::env::var("GRPC_UPSTREAM_HOST").unwrap_or_else(|_| "localhost:50051".to_string());

    let config = JokowayConfig {
        http_listen: format!("0.0.0.0:{}", port),
        http_server_options: Some(jokoway::config::models::HttpServerOptionsConfig {
            h2c: true,
            ..Default::default()
        }),
        upstreams: vec![Upstream {
            name: ups_name.to_string(),
            servers: vec![UpstreamServer {
                host: upstream_host,
                weight: Some(1),
                ..Default::default()
            }],
            ..Default::default()
        }],
        services: vec![Arc::new(Service {
            name: "grpc-service".to_string(),
            host: ups_name.to_string(),
            protocols: vec![ServiceProtocol::Grpc],
            routes: vec![Route {
                name: "helloworld-route".to_string(),
                rule: "PathPrefix(`/`)".to_string(),
                priority: Some(1),
                ..Default::default()
            }],
        })],
        ..Default::default()
    };

    let opt = Opt::default();

    log::info!("Starting grpc-gateway on port {}...", port);

    let app = App::new(config, None, opt, vec![Box::new(ExampleExtension)]);
    app.run()
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}
