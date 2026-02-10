//! Core traits and types for Jokoway API Gateway
//!
//! This crate provides the fundamental traits that extension developers
//! need to implement to create middlewares and extensions for Jokoway.

pub mod error;
pub mod websocket;

use arc_swap::ArcSwap;
use bytes::Bytes;
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingora::server::Server;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

/// Core application context shared across extensions and middlewares
#[derive(Clone)]
pub struct AppCtx {
    data: Arc<ArcSwap<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>>,
}

impl AppCtx {
    pub fn new() -> Self {
        Self {
            data: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }

    pub fn insert<T: Any + Send + Sync>(&self, value: T) {
        let value = Arc::new(value) as Arc<dyn Any + Send + Sync>;
        self.data.rcu(move |old| {
            let mut next = (**old).clone();
            next.insert(TypeId::of::<T>(), value.clone());
            next
        });
    }

    pub fn get<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let data = self.data.load();
        let value = data.get(&TypeId::of::<T>()).cloned()?;
        Arc::downcast::<T>(value).ok()
    }

    pub fn remove<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let mut removed: Option<Arc<dyn Any + Send + Sync>> = None;
        self.data.rcu(|old| {
            let mut next = (**old).clone();
            removed = next.remove(&TypeId::of::<T>());
            next
        });
        removed.and_then(|value| Arc::downcast::<T>(value).ok())
    }
}

impl Default for AppCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// Middleware trait for processing requests and responses.
///
/// Middlewares can inspect and modify requests before they reach the upstream,
/// and responses before they are sent to the client.
#[async_trait::async_trait]
pub trait HttpMiddleware: Send + Sync {
    /// Per-middleware context type
    type CTX: Send + Sync + 'static;

    /// The name of the middleware
    fn name(&self) -> &'static str;

    /// Create a new context instance for this middleware
    fn new_ctx(&self) -> Self::CTX;

    /// The order the middleware will run
    ///
    /// The higher the value, the earlier it runs relative to other middlewares.
    /// If the order of the middleware is not important, leave it to the default 0.
    fn order(&self) -> i16 {
        0
    }

    /// Called when the request is received, before routing.
    ///
    /// Returns Ok(true) if the request was handled and the proxy should stop processing.
    /// Returns Ok(false) to continue to the next filter/routing.
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppCtx,
    ) -> Result<bool, Box<Error>> {
        Ok(false)
    }

    /// Called after the upstream response is received, before sending to client.
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppCtx,
    ) -> Result<(), Box<Error>> {
        Ok(())
    }

    /// Called for each chunk of the response body.
    ///
    /// Returns Ok(Some(duration)) if the body handling took some time that should be recorded.
    /// Returns Ok(None) to continue processing.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>, Box<Error>> {
        Ok(None)
    }

    /// Called for each chunk of the request body.
    ///
    /// This allows middlewares to inspect, modify, or buffer request body data
    /// before it is sent to the upstream server.
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        Ok(())
    }
}

/// Dynamic dispatch version of HttpMiddleware for trait objects
#[async_trait::async_trait]
pub trait HttpMiddlewareDyn: Send + Sync {
    /// The name of the middleware
    fn name(&self) -> &'static str;

    /// The order the middleware will run
    fn order(&self) -> i16 {
        0
    }

    fn new_ctx_dyn(&self) -> Box<dyn Any + Send + Sync>;

    async fn request_filter_dyn(
        &self,
        session: &mut Session,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppCtx,
    ) -> Result<bool, Box<Error>>;

    async fn upstream_response_filter_dyn(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppCtx,
    ) -> Result<(), Box<Error>>;

    fn response_body_filter_dyn(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut (dyn Any + Send + Sync),
    ) -> Result<Option<std::time::Duration>, Box<Error>>;

    async fn request_body_filter_dyn(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut (dyn Any + Send + Sync),
    ) -> Result<(), Box<Error>>;
}

/// Blanket implementation for all HttpMiddleware types
#[async_trait::async_trait]
impl<T: HttpMiddleware> HttpMiddlewareDyn for T {
    fn name(&self) -> &'static str {
        HttpMiddleware::name(self)
    }

    fn order(&self) -> i16 {
        HttpMiddleware::order(self)
    }

    fn new_ctx_dyn(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(self.new_ctx())
    }

    async fn request_filter_dyn(
        &self,
        session: &mut Session,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppCtx,
    ) -> Result<bool, Box<Error>> {
        let ctx = ctx.downcast_mut::<T::CTX>().ok_or_else(|| {
            Error::explain(pingora::ErrorType::InternalError, "Invalid context type")
        })?;
        self.request_filter(session, ctx, app_ctx).await
    }

    async fn upstream_response_filter_dyn(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppCtx,
    ) -> Result<(), Box<Error>> {
        let ctx = ctx.downcast_mut::<T::CTX>().ok_or_else(|| {
            Error::explain(pingora::ErrorType::InternalError, "Invalid context type")
        })?;
        self.upstream_response_filter(session, upstream_response, ctx, app_ctx)
            .await
    }

    fn response_body_filter_dyn(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut (dyn Any + Send + Sync),
    ) -> Result<Option<std::time::Duration>, Box<Error>> {
        let ctx = ctx.downcast_mut::<T::CTX>().ok_or_else(|| {
            Error::explain(pingora::ErrorType::InternalError, "Invalid context type")
        })?;
        self.response_body_filter(session, body, end_of_stream, ctx)
    }

    async fn request_body_filter_dyn(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut (dyn Any + Send + Sync),
    ) -> Result<(), Box<Error>> {
        let ctx = ctx.downcast_mut::<T::CTX>().ok_or_else(|| {
            Error::explain(pingora::ErrorType::InternalError, "Invalid context type")
        })?;
        self.request_body_filter(session, body, end_of_stream, ctx)
            .await
    }
}

/// Extension trait for adding custom functionality to Jokoway
///
/// Extensions can add background services, modify server configuration, etc.
pub trait JokowayExtension: Send + Sync {
    /// The order the extension will run
    ///
    /// The higher the value, the earlier it runs relative to other extensions.
    /// If the order of the extension is not important, leave it to the default 0.
    fn order(&self) -> i16 {
        0
    }

    /// Called during server bootstrap to add background services etc.
    ///
    /// Note: This uses `dyn Any` for app_ctx to avoid circular dependencies.
    /// Extensions should downcast to the concrete AppCtx type.
    fn init(
        &self,
        _server: &mut Server,
        _app_ctx: &mut AppCtx,
        _http_middlewares: &mut Vec<Arc<dyn HttpMiddlewareDyn>>,
        _websocket_middlewares: &mut Vec<Arc<dyn crate::websocket::WebsocketMiddlewareDyn>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
