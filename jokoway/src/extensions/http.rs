use crate::config::models::JokowayConfig;
use crate::prelude::*;
use crate::server::context::AppCtx;
use crate::server::proxy::JokowayProxy;
use crate::server::router::{HTTP_PROTOCOLS, Router};
use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use pingora::proxy::http_proxy_service;
use std::sync::Arc;

pub struct HttpExtension;

use crate::error::JokowayError;
use pingora::server::Server;

impl JokowayExtension for HttpExtension {
    fn init(
        &self,
        server: &mut Server,
        app_ctx: &mut AppCtx,
        http_middlewares: &mut Vec<std::sync::Arc<dyn HttpMiddlewareDyn>>,
        websocket_middlewares: &mut Vec<std::sync::Arc<dyn crate::prelude::WebsocketMiddlewareDyn>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = app_ctx
            .get::<JokowayConfig>()
            .ok_or_else(|| JokowayError::Config("JokowayConfig not found in AppCtx".to_string()))?;

        let upstream_manager = app_ctx.get::<UpstreamManager>().ok_or_else(|| {
            JokowayError::Config("UpstreamManager not found in AppCtx".to_string())
        })?;
        let service_manager = app_ctx.get::<ServiceManager>().ok_or_else(|| {
            JokowayError::Config("ServiceManager not found in AppCtx".to_string())
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
            http_middlewares.clone(),
            websocket_middlewares.clone(),
            false,
        )?;

        let mut http_service = http_proxy_service(&server.configuration, proxy);
        http_service.add_tcp(&config.http_listen);
        server.add_service(http_service);
        log::info!("HTTP proxy listening on {}", config.http_listen);
        Ok(())
    }
}
