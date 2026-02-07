use crate::config::models::{JokowayConfig, ServerConf};
#[cfg(feature = "acme-extension")]
use crate::extensions::acme::{AcmeExtension, AcmeFilter};
use crate::extensions::dns::{DnsExtension, DnsResolver};
use crate::extensions::http::HttpExtension;
use crate::extensions::https::HttpsExtension;
use crate::server::context::AppCtx;
use crate::server::extension::{JokowayExtension, JokowayFilter, WebsocketExtension};
use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use pingora::server::Server;
use std::sync::Arc;

use pingora::server::configuration::Opt;

pub struct App {
    pub config: JokowayConfig,
    pub server_conf: Option<ServerConf>,
    pub opt: Opt,
    pub extensions: Vec<Box<dyn JokowayExtension>>,
    pub filters: Vec<Arc<dyn JokowayFilter>>,
    pub websocket_extensions: Vec<Arc<dyn WebsocketExtension>>,
    pub app_ctx: AppCtx,
}

impl App {
    pub fn new(
        config: JokowayConfig,
        server_conf: Option<ServerConf>,
        opt: Opt,
        custom_extensions: Vec<Box<dyn JokowayExtension>>,
        custom_websocket_extensions: Vec<Arc<dyn WebsocketExtension>>,
    ) -> Self {
        let mut app = Self {
            config,
            server_conf,
            opt,
            extensions: custom_extensions,
            filters: Vec::new(),
            websocket_extensions: custom_websocket_extensions,
            app_ctx: AppCtx::new(),
        };

        // Register ACME extension if configured
        // Must be added before HttpsExtension so HttpsExtension can find AcmeManager in AppCtx
        #[cfg(feature = "acme-extension")]
        if let Some(acme_settings) = &app.config.acme {
            let acme_ext = AcmeExtension::new(acme_settings, Arc::new(app.config.clone()));
            let acme_filter = AcmeFilter {
                acme_manager: acme_ext.acme_manager.clone(),
            };
            app.add_extension(acme_ext.clone());
            app.add_filter(acme_filter);
        }

        app.add_extension(DnsExtension);
        app.add_extension(HttpExtension);
        app.add_extension(HttpsExtension);

        #[cfg(feature = "compress-extension")]
        {
            if app.config.compress == Some(true) {
                use crate::extensions::compress::{CompressExtension, CompressFilter};
                app.add_extension(CompressExtension);
                app.add_filter(CompressFilter);
            }
        }

        // Register API extension if configured
        #[cfg(feature = "api-extension")]
        {
            if let Some(api_settings) = &app.config.api
                && api_settings.listen.is_some()
            {
                app.add_extension(crate::extensions::api::ApiExtension::new(
                    api_settings.clone(),
                ));
            }
        }

        app
    }

    pub fn add_extension<E: JokowayExtension + 'static>(&mut self, extension: E) {
        self.extensions.push(Box::new(extension));
    }

    pub fn add_filter<F: JokowayFilter + 'static>(&mut self, filter: F) {
        self.filters.push(Arc::new(filter));
    }

    pub fn add_websocket_extension<E: WebsocketExtension + 'static>(&mut self, extension: E) {
        self.websocket_extensions.push(Arc::new(extension));
    }

    pub fn app_ctx(&self) -> &AppCtx {
        &self.app_ctx
    }

    pub fn run(self) -> Result<(), crate::error::JokowayError> {
        let mut server =
            Server::new_with_opt_and_conf(Some(self.opt), self.server_conf.unwrap_or_default());
        server.bootstrap();
        let mut app_ctx = self.app_ctx;

        let config_arc = Arc::new(self.config.clone());

        // Share resources via AppCtx for extensions to use
        app_ctx.insert(self.config.clone());

        // Initialize DNS Resolver early
        let dns_resolver = DnsResolver::new(&self.config);
        app_ctx.insert(dns_resolver);

        // Initialize UpstreamManager
        let (upstream_manager, lb_services) = UpstreamManager::new(&app_ctx)?;

        // Initialize ServiceManager
        let service_manager = ServiceManager::new(config_arc.clone())?;

        // Add LB background services
        for service in lb_services {
            server.add_service(service);
        }

        // Share global filters and websocket extensions
        app_ctx.insert(self.filters);
        app_ctx.insert(self.websocket_extensions);

        // Share core managers for dependency injection within extensions
        app_ctx.insert(upstream_manager);
        app_ctx.insert(service_manager);

        for ext in &self.extensions {
            ext.jokoway_init(&mut server, &mut app_ctx)?;
        }

        server.run_forever();
    }
}
