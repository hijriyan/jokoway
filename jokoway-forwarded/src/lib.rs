pub mod config;
pub mod middleware;
pub mod models;
pub mod parser;

use crate::config::ForwardedConfigExt;
use async_trait::async_trait;
use jokoway_core::{AppContext, Context, JokowayExtension, JokowayMiddlewareDyn};
use middleware::ForwardedMiddleware;
use pingora::server::Server;
use std::sync::Arc;

/// This extension is responsible for setting up the `ForwardedMiddleware`, which parses
/// client IP and protocol information from legacy `X-Forwarded-*` headers.
/// It reads configuration from [`JokowayConfig`] to determine if the middleware should be
/// enabled and to load any configured trusted proxies.
///
/// If enabled, it adds the middleware to the request pipeline so that parsed values
/// can be securely determined and used by other parts of the application.
pub struct ForwardedExtension;

#[async_trait]
impl JokowayExtension for ForwardedExtension {
    fn order(&self) -> i16 {
        0
    }

    fn init(
        &self,
        _server: &mut Server,
        app_ctx: &mut AppContext,
        middlewares: &mut Vec<Arc<dyn JokowayMiddlewareDyn>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config_arc = app_ctx
            .get::<jokoway_core::config::models::JokowayConfig>()
            .ok_or("JokowayConfig not found in AppContext")?;

        let settings = config_arc.http_forwarded().unwrap_or_default();

        if settings.enabled {
            let trusted_proxies = settings.build_trusted_proxies();
            if !trusted_proxies.is_empty() {
                log::info!(
                    "ForwardedExtension: {} trusted proxy CIDR(s) configured.",
                    settings.trusted_proxies.len()
                );
            }
            let middleware = ForwardedMiddleware {
                settings,
                trusted_proxies,
            };
            middlewares.push(Arc::new(middleware));
            log::info!("ForwardedExtension initialized and middleware added.");
        } else {
            log::info!("ForwardedExtension is disabled by configuration.");
        }

        Ok(())
    }
}
