//! Core traits and types for Jokoway API Gateway
//!
//! This crate provides the fundamental traits that extension developers
//! need to implement to create middlewares and extensions for Jokoway.

pub mod config;
pub mod error;
pub mod prelude;
pub mod tls;
pub mod websocket;

use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingora::server::Server;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

/// Shared interface for type-safe, heterogeneous key-value storage.
///
/// Both [`AppContext`] and [`RequestContext`] implement this trait,
/// allowing generic helper functions to work with either context type.
pub trait Context: Send + Sync {
    /// Insert a value of any type into the context.
    fn insert<T: Any + Send + Sync>(&self, value: T);

    /// Retrieve a value by its type from the context.
    fn get<T: Any + Send + Sync>(&self) -> Option<Arc<T>>;

    /// Remove and return a value by its type from the context.
    fn remove<T: Any + Send + Sync>(&self) -> Option<Arc<T>>;
}

/// Global application context, shared across all requests.
///
/// Uses [`ArcSwap`] internally for lock-free concurrent reads,
/// making it ideal for configuration or state that is written rarely
/// (e.g., at startup) but read on every request from many threads.
#[derive(Clone)]
pub struct AppContext {
    data: Arc<ArcSwap<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>>,
}

impl AppContext {
    pub fn new() -> Self {
        Self {
            data: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }
}

impl Default for AppContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Context for AppContext {
    fn insert<T: Any + Send + Sync>(&self, value: T) {
        let value = Arc::new(value) as Arc<dyn Any + Send + Sync>;
        self.data.rcu(move |old| {
            let mut next = (**old).clone();
            next.insert(TypeId::of::<T>(), value.clone());
            next
        });
    }

    fn get<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let data = self.data.load();
        let value = data.get(&TypeId::of::<T>()).cloned()?;
        Arc::downcast::<T>(value).ok()
    }

    fn remove<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let mut removed: Option<Arc<dyn Any + Send + Sync>> = None;
        self.data.rcu(|old| {
            let mut next = (**old).clone();
            removed = next.remove(&TypeId::of::<T>());
            next
        });
        removed.and_then(|value| Arc::downcast::<T>(value).ok())
    }
}

/// Per-request context for sharing state between middlewares within a single request lifecycle.
///
/// Uses [`DashMap`] internally for fast, zero-clone inserts and removes.
/// Created fresh for every HTTP session and dropped when the request completes.
#[derive(Clone)]
pub struct RequestContext {
    data: Arc<DashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            data: Arc::new(DashMap::new()),
        }
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Context for RequestContext {
    fn insert<T: Any + Send + Sync>(&self, value: T) {
        let value = Arc::new(value) as Arc<dyn Any + Send + Sync>;
        self.data.insert(TypeId::of::<T>(), value);
    }

    fn get<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let value = self.data.get(&TypeId::of::<T>())?.clone();
        Arc::downcast::<T>(value).ok()
    }

    fn remove<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let (_, value) = self.data.remove(&TypeId::of::<T>())?;
        Arc::downcast::<T>(value).ok()
    }
}

/// Middleware trait for processing requests and responses.
///
/// Middlewares can inspect and modify requests before they reach the upstream,
/// and responses before they are sent to the client.
#[async_trait::async_trait]
pub trait JokowayMiddleware: Send + Sync {
    /// Per-middleware context type, instantiated once per request lifecycle
    /// to hold state across different filtering phases.
    type CTX: Send + Sync + 'static;

    /// The name of the middleware, used for identification and debugging.
    fn name(&self) -> &'static str;

    /// Create a new context instance for this middleware.
    /// This is called early and the context is passed to all subsequent filter hooks for a given request.
    fn new_ctx(&self) -> Self::CTX;

    /// The execution order of the middleware.
    ///
    /// The higher the value, the earlier it runs relative to other middlewares in the chain.
    /// Default is 0. Middlewares with the same order value are executed in the order they were registered.
    fn order(&self) -> i16 {
        0
    }

    /// Invoked after receiving the client's request headers, but before routing or connecting to the upstream.
    ///
    /// This hook is ideal for authentication, request block-listing, rate limiting, and
    /// modifying request headers before the router processes them.
    ///
    /// Return `Ok(true)` if the middleware has fully handled the request (e.g., sent an early response)
    /// and further proxy processing should be aborted.
    /// Return `Ok(false)` to continue to the next middleware and eventual routing.
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppContext,
        _request_ctx: &RequestContext,
    ) -> Result<bool, Box<Error>> {
        Ok(false)
    }

    /// Invoked after receiving the HTTP response headers from the upstream server,
    /// but before they are forwarded to the downstream client.
    ///
    /// Useful for modifying response headers (e.g., injecting security headers, CORS),
    /// inspecting the status code, or logging the upstream response details.
    ///
    /// *Note: This is currently bypassed for upgraded WebSocket connections (101 Switching Protocols).*
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppContext,
        _request_ctx: &RequestContext,
    ) -> Result<(), Box<Error>> {
        Ok(())
    }

    /// Invoked for each chunk of the response body streamed from the upstream to the client.
    ///
    /// Allows inspecting or mutating response body chunks before they reach the client.
    /// If there is no more body to process, `_end_of_stream` will be true.
    ///
    /// Return `Ok(Some(duration))` if you want to record the time spent processing this chunk
    /// in the metrics/logs, or `Ok(None)` otherwise.
    ///
    /// *Note: This hook is not invoked for WebSocket traffic. Use `on_websocket_message` instead.*
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppContext,
        _request_ctx: &RequestContext,
    ) -> Result<Option<std::time::Duration>, Box<Error>> {
        Ok(None)
    }

    /// Invoked for each chunk of the request body streamed from the client to the upstream.
    ///
    /// Allows inspecting, buffering, or mutating request body chunks (e.g., parsing JSON validation)
    /// before they reach the upstream server. If there is no more body, `_end_of_stream` will be true.
    ///
    /// *Note: This hook is not invoked for WebSocket traffic. Use `on_websocket_message` instead.*
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppContext,
        _request_ctx: &RequestContext,
    ) -> Result<(), Box<Error>> {
        Ok(())
    }

    /// Invoked whenever a discrete, fully-parsed WebSocket frame is intercepted.
    ///
    /// This hook operates on both directions of the WebSocket connection, distinguished by the `_direction` parameter.
    /// Middlewares can inspect the payload, modify the message, drop the frame silently, or
    /// close the connection altogether using the returned `WebsocketMessageAction`.
    fn on_websocket_message(
        &self,
        _direction: crate::websocket::WebsocketDirection,
        frame: crate::websocket::WsFrame,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppContext,
        _request_ctx: &RequestContext,
    ) -> crate::websocket::WebsocketMessageAction {
        crate::websocket::WebsocketMessageAction::Forward(frame)
    }

    /// Invoked when an error occurs while parsing raw stream bytes into WebSocket frames.
    ///
    /// This provides a facility for dealing with malformed or invalid WebSocket data.
    /// The middleware can decide to pass the raw unparsed bytes through unmodified, drop the invalid
    /// data, or force close the WebSocket connection.
    fn on_websocket_error(
        &self,
        _direction: crate::websocket::WebsocketDirection,
        _error: crate::websocket::WebsocketError,
        _ctx: &mut Self::CTX,
        _app_ctx: &AppContext,
        _request_ctx: &RequestContext,
    ) -> crate::websocket::WebsocketErrorAction {
        crate::websocket::WebsocketErrorAction::PassThrough
    }
}

/// Dynamic dispatch version of JokowayMiddleware for trait objects
#[async_trait::async_trait]
pub trait JokowayMiddlewareDyn: Send + Sync {
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
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> Result<bool, Box<Error>>;

    async fn upstream_response_filter_dyn(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> Result<(), Box<Error>>;

    fn response_body_filter_dyn(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> Result<Option<std::time::Duration>, Box<Error>>;

    async fn request_body_filter_dyn(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> Result<(), Box<Error>>;

    fn on_websocket_message_dyn(
        &self,
        direction: crate::websocket::WebsocketDirection,
        frame: crate::websocket::WsFrame,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> crate::websocket::WebsocketMessageAction;

    fn on_websocket_error_dyn(
        &self,
        direction: crate::websocket::WebsocketDirection,
        error: crate::websocket::WebsocketError,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> crate::websocket::WebsocketErrorAction;
}

/// Blanket implementation for all JokowayMiddleware types
#[async_trait::async_trait]
impl<T: JokowayMiddleware> JokowayMiddlewareDyn for T {
    fn name(&self) -> &'static str {
        JokowayMiddleware::name(self)
    }

    fn order(&self) -> i16 {
        JokowayMiddleware::order(self)
    }

    fn new_ctx_dyn(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(self.new_ctx())
    }

    async fn request_filter_dyn(
        &self,
        session: &mut Session,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> Result<bool, Box<Error>> {
        let ctx = ctx.downcast_mut::<T::CTX>().ok_or_else(|| {
            Error::explain(pingora::ErrorType::InternalError, "Invalid context type")
        })?;
        self.request_filter(session, ctx, app_ctx, request_ctx)
            .await
    }

    async fn upstream_response_filter_dyn(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> Result<(), Box<Error>> {
        let ctx = ctx.downcast_mut::<T::CTX>().ok_or_else(|| {
            Error::explain(pingora::ErrorType::InternalError, "Invalid context type")
        })?;
        self.upstream_response_filter(session, upstream_response, ctx, app_ctx, request_ctx)
            .await
    }

    fn response_body_filter_dyn(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> Result<Option<std::time::Duration>, Box<Error>> {
        let ctx = ctx.downcast_mut::<T::CTX>().ok_or_else(|| {
            Error::explain(pingora::ErrorType::InternalError, "Invalid context type")
        })?;
        self.response_body_filter(session, body, end_of_stream, ctx, app_ctx, request_ctx)
    }

    async fn request_body_filter_dyn(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> Result<(), Box<Error>> {
        let ctx = ctx.downcast_mut::<T::CTX>().ok_or_else(|| {
            Error::explain(pingora::ErrorType::InternalError, "Invalid context type")
        })?;
        self.request_body_filter(session, body, end_of_stream, ctx, app_ctx, request_ctx)
            .await
    }

    fn on_websocket_message_dyn(
        &self,
        direction: crate::websocket::WebsocketDirection,
        frame: crate::websocket::WsFrame,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> crate::websocket::WebsocketMessageAction {
        let ctx = ctx
            .downcast_mut::<T::CTX>()
            .expect("Invalid context type for JokowayMiddleware");
        self.on_websocket_message(direction, frame, ctx, app_ctx, request_ctx)
    }

    fn on_websocket_error_dyn(
        &self,
        direction: crate::websocket::WebsocketDirection,
        error: crate::websocket::WebsocketError,
        ctx: &mut (dyn Any + Send + Sync),
        app_ctx: &AppContext,
        request_ctx: &RequestContext,
    ) -> crate::websocket::WebsocketErrorAction {
        let ctx = ctx
            .downcast_mut::<T::CTX>()
            .expect("Invalid context type for JokowayMiddleware");
        self.on_websocket_error(direction, error, ctx, app_ctx, request_ctx)
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
    /// Extensions should downcast to the concrete Context type.
    fn init(
        &self,
        _server: &mut Server,
        _app_ctx: &mut AppContext,
        _middlewares: &mut Vec<Arc<dyn JokowayMiddlewareDyn>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
