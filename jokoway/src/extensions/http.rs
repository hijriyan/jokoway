use crate::config::models::JokowayConfig;
use crate::prelude::{core::*, *};
use crate::server::context::Context;
use crate::server::proxy::JokowayProxy;
use crate::server::router::{HTTP_PROTOCOLS, Router};
use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use pingora::proxy::ProxyServiceBuilder;
use std::sync::Arc;

pub struct HttpExtension;

use crate::error::JokowayError;
use pingora::server::Server;

impl JokowayExtension for HttpExtension {
    fn order(&self) -> i16 {
        -100
    }

    fn init(
        &self,
        server: &mut Server,
        app_ctx: &mut AppContext,
        middlewares: &mut Vec<std::sync::Arc<dyn JokowayMiddlewareDyn>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = app_ctx.get::<JokowayConfig>().ok_or_else(|| {
            JokowayError::Config("JokowayConfig not found in Context".to_string())
        })?;

        let upstream_manager = app_ctx.get::<UpstreamManager>().ok_or_else(|| {
            JokowayError::Config("UpstreamManager not found in Context".to_string())
        })?;
        let service_manager = app_ctx.get::<ServiceManager>().ok_or_else(|| {
            JokowayError::Config("ServiceManager not found in Context".to_string())
        })?;

        let router = Router::new(
            service_manager,
            upstream_manager.clone(),
            &HTTP_PROTOCOLS,
            // &config,
        );

        let proxy = JokowayProxy::new(
            router,
            Arc::new(app_ctx.clone()),
            middlewares.clone(),
            false,
        )?;

        let mut builder = ProxyServiceBuilder::new(&server.configuration, proxy)
            .name("Jokoway HTTP Proxy Service");

        if let Some(opts) = &config.http_server_options {
            let mut server_options = pingora::apps::HttpServerOptions::default();
            server_options.keepalive_request_limit = opts.keepalive_request_limit;
            server_options.h2c = opts.h2c;
            server_options.allow_connect_method_proxying = opts.allow_connect_method_proxying;
            builder = builder.server_options(server_options);
        }

        let mut http_service = builder.build();
        http_service.add_tcp(&config.http_listen);
        server.add_service(http_service);
        log::info!("HTTP proxy listening on {}", config.http_listen);
        Ok(())
    }
}
