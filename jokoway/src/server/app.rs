use crate::config::models::{JokowayConfig, ServerConf};
use crate::extensions::dns::{DnsExtension, DnsResolver};
use crate::extensions::http::HttpExtension;
use crate::extensions::https::HttpsExtension;
use crate::prelude::*;
use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
#[cfg(feature = "acme-extension")]
use jokoway_acme::{AcmeConfigExt, AcmeExtension};
use jokoway_core::AppCtx;
use pingora::server::Server;
use std::sync::Arc;

use pingora::server::configuration::Opt;

pub struct App {
    pub config: JokowayConfig,
    pub server_conf: Option<ServerConf>,
    pub opt: Opt,
    pub extensions: Vec<Box<dyn JokowayExtension>>,
    pub app_ctx: AppCtx,
}

impl App {
    pub fn new(
        config: JokowayConfig,
        server_conf: Option<ServerConf>,
        opt: Opt,
        custom_extensions: Vec<Box<dyn JokowayExtension>>,
    ) -> Self {
        let mut app = Self {
            config,
            server_conf,
            opt,
            extensions: custom_extensions,
            app_ctx: AppCtx::new(),
        };

        // Register ACME extension if configured
        // Must be added before HttpsExtension so HttpsExtension can find AcmeManager in AppCtx
        #[cfg(feature = "acme-extension")]
        if let Some(acme_settings) = app.config.acme() {
            let acme_ext = AcmeExtension::new(&acme_settings);
            app.add_extension(acme_ext);
        }

        app.add_extension(DnsExtension);
        app.add_extension(HttpExtension);
        app.add_extension(HttpsExtension);

        #[cfg(feature = "compress-extension")]
        {
            if app.config.compress == Some(true) {
                use jokoway_compress::CompressExtension;
                app.add_extension(CompressExtension);
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

    pub fn app_ctx(&self) -> &AppCtx {
        &self.app_ctx
    }

    pub fn build(mut self) -> Result<Server, crate::error::JokowayError> {
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

        // Share core managers for dependency injection within extensions
        app_ctx.insert(upstream_manager);
        app_ctx.insert(service_manager);

        // Stable sort - maintains insertion order for same values
        self.extensions
            .sort_by_key(|e| std::cmp::Reverse(e.order()));

        let mut middlewares: Vec<Arc<dyn HttpMiddlewareDyn>> = Vec::new();
        let mut websocket_middlewares: Vec<
            Arc<dyn jokoway_core::websocket::WebsocketMiddlewareDyn>,
        > = Vec::new();

        for i in 0..self.extensions.len() {
            self.extensions[i].init(
                &mut server,
                &mut app_ctx,
                &mut middlewares,
                &mut websocket_middlewares,
            )?;

            middlewares.sort_by_key(|b| std::cmp::Reverse(b.order()));

            websocket_middlewares.sort_by_key(|b| std::cmp::Reverse(b.order()));
        }

        Ok(server)
    }

    pub fn run(self) -> Result<(), crate::error::JokowayError> {
        let server = self.build()?;
        server.run_forever();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::HttpMiddleware;
    use async_trait::async_trait;

    struct EarlyMiddleware;
    #[async_trait]
    impl HttpMiddleware for EarlyMiddleware {
        type CTX = ();
        fn name(&self) -> &'static str {
            "EarlyMiddleware"
        }
        fn new_ctx(&self) -> Self::CTX {}
        fn order(&self) -> i16 {
            10
        }
    }

    struct DefaultMiddleware;
    #[async_trait]
    impl HttpMiddleware for DefaultMiddleware {
        type CTX = ();
        fn name(&self) -> &'static str {
            "DefaultMiddleware"
        }
        fn new_ctx(&self) -> Self::CTX {}
        // Uses default order of 0
    }

    struct LateMiddleware;
    #[async_trait]
    impl HttpMiddleware for LateMiddleware {
        type CTX = ();
        fn name(&self) -> &'static str {
            "LateMiddleware"
        }
        fn new_ctx(&self) -> Self::CTX {}
        fn order(&self) -> i16 {
            -10
        }
    }

    #[test]
    fn test_middleware_ordering() {
        let mut middlewares: Vec<Arc<dyn HttpMiddlewareDyn>> = vec![
            Arc::new(LateMiddleware),
            Arc::new(EarlyMiddleware),
            Arc::new(DefaultMiddleware),
        ];

        // Sort by order (descending - highest order runs first)
        middlewares.sort_by_key(|m| -m.order());

        // Verify they are sorted correctly (highest order first)
        assert_eq!(middlewares.len(), 3);
        assert_eq!(middlewares[0].order(), 10); // EarlyMiddleware
        assert_eq!(middlewares[1].order(), 0); // DefaultMiddleware
        assert_eq!(middlewares[2].order(), -10); // LateMiddleware
    }

    #[test]
    fn test_middleware_ordering_same_order() {
        // Add multiple middlewares with the same order
        let mut middlewares: Vec<Arc<dyn HttpMiddlewareDyn>> =
            vec![Arc::new(DefaultMiddleware), Arc::new(DefaultMiddleware)];

        // Sort by order
        middlewares.sort_by_key(|b| std::cmp::Reverse(b.order()));

        // Both should have order 0
        assert_eq!(middlewares.len(), 2);
        assert_eq!(middlewares[0].order(), 0);
        assert_eq!(middlewares[1].order(), 0);
    }

    #[test]
    fn test_middleware_insertion_order_preserved() {
        // Test that middlewares with same order maintain insertion order
        struct FirstMiddleware;
        #[async_trait]
        impl HttpMiddleware for FirstMiddleware {
            type CTX = String;
            fn name(&self) -> &'static str {
                "FirstMiddleware"
            }
            fn new_ctx(&self) -> Self::CTX {
                "first".to_string()
            }
            fn order(&self) -> i16 {
                0
            }
        }

        struct SecondMiddleware;
        #[async_trait]
        impl HttpMiddleware for SecondMiddleware {
            type CTX = String;
            fn name(&self) -> &'static str {
                "SecondMiddleware"
            }
            fn new_ctx(&self) -> Self::CTX {
                "second".to_string()
            }
            fn order(&self) -> i16 {
                0
            }
        }

        struct ThirdMiddleware;
        #[async_trait]
        impl HttpMiddleware for ThirdMiddleware {
            type CTX = String;
            fn name(&self) -> &'static str {
                "ThirdMiddleware"
            }
            fn new_ctx(&self) -> Self::CTX {
                "third".to_string()
            }
            fn order(&self) -> i16 {
                0
            }
        }

        // Add in specific order
        let mut middlewares: Vec<Arc<dyn HttpMiddlewareDyn>> = vec![
            Arc::new(FirstMiddleware),
            Arc::new(SecondMiddleware),
            Arc::new(ThirdMiddleware),
        ];

        // Stable sort should preserve insertion order for same values
        middlewares.sort_by_key(|b| std::cmp::Reverse(b.order()));

        // Verify insertion order is preserved
        assert_eq!(middlewares.len(), 3);

        // All have same order
        assert_eq!(middlewares[0].order(), 0);
        assert_eq!(middlewares[1].order(), 0);
        assert_eq!(middlewares[2].order(), 0);

        // But contexts show insertion order is preserved
        let ctx0 = middlewares[0].new_ctx_dyn();
        let ctx1 = middlewares[1].new_ctx_dyn();
        let ctx2 = middlewares[2].new_ctx_dyn();

        assert_eq!(ctx0.downcast_ref::<String>().unwrap(), "first");
        assert_eq!(ctx1.downcast_ref::<String>().unwrap(), "second");
        assert_eq!(ctx2.downcast_ref::<String>().unwrap(), "third");
    }

    #[test]
    fn test_extension_ordering() {
        use crate::prelude::JokowayExtension;

        struct OrderedExtension {
            order: i16,
        }

        impl JokowayExtension for OrderedExtension {
            fn order(&self) -> i16 {
                self.order
            }
        }

        let mut extensions: Vec<Box<dyn JokowayExtension>> = vec![
            Box::new(OrderedExtension { order: 10 }),
            Box::new(OrderedExtension { order: 0 }),
            Box::new(OrderedExtension { order: -10 }),
        ];

        // This sort logic must match App::build
        extensions.sort_by_key(|e| std::cmp::Reverse(e.order()));

        // Verify higher order comes first
        assert_eq!(extensions[0].order(), 10);
        assert_eq!(extensions[1].order(), 0);
        assert_eq!(extensions[2].order(), -10);
    }

    #[test]
    fn test_extension_returns_middleware() {
        use crate::prelude::JokowayExtension;
        use crate::server::app::App;
        use pingora::server::configuration::Opt;

        struct MwExtension;
        #[async_trait]
        impl JokowayExtension for MwExtension {
            fn init(
                &self,
                _server: &mut pingora::server::Server,
                _app_ctx: &mut AppCtx,
                http_middlewares: &mut Vec<std::sync::Arc<dyn HttpMiddlewareDyn>>,
                _websocket_middlewares: &mut Vec<
                    std::sync::Arc<dyn crate::prelude::WebsocketMiddlewareDyn>,
                >,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let mw = DefaultMiddleware;
                http_middlewares.push(Arc::new(mw));
                Ok(())
            }
        }

        struct VerifierExtension;

        impl JokowayExtension for VerifierExtension {
            fn order(&self) -> i16 {
                -10 // Run after MwExtension (default 0)
            }

            fn init(
                &self,
                _server: &mut pingora::server::Server,
                _app_ctx: &mut AppCtx,
                http_middlewares: &mut Vec<std::sync::Arc<dyn HttpMiddlewareDyn>>,
                _websocket_middlewares: &mut Vec<
                    std::sync::Arc<dyn crate::prelude::WebsocketMiddlewareDyn>,
                >,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                // Verify that the middleware from MwExtension is present
                assert!(
                    http_middlewares
                        .iter()
                        .any(|m| m.name() == "DefaultMiddleware")
                );
                Ok(())
            }
        }

        let app = App::new(
            JokowayConfig::default(),
            None,
            Opt::default(),
            vec![Box::new(MwExtension), Box::new(VerifierExtension)],
        );

        let _server = app.build().unwrap();
    }
}
