use jokoway_transformer::ResponseTransformer;

use bytes::BytesMut;
use flate2::Decompress;
pub use jokoway_core::AppCtx;
use std::any::Any;
use std::sync::Arc;

pub struct RouteContext {
    pub upstream_name: Option<Arc<str>>,
    pub response_transformer: Option<Arc<dyn ResponseTransformer>>,
    pub is_upgrade: bool,
    pub ws_client_buf: BytesMut,
    pub ws_upstream_buf: BytesMut,
    pub rewrite_host: Option<String>,

    pub ws_client_decompressor: Option<Decompress>,
    pub ws_upstream_decompressor: Option<Decompress>,

    pub middleware_ctx: Vec<Box<dyn Any + Send + Sync>>,
    pub websocket_middleware_ctx: Vec<Box<dyn Any + Send + Sync>>,
}

impl RouteContext {
    /// Create a new RouteContext with optimized buffer sizes
    pub fn new() -> Self {
        Self {
            upstream_name: None,
            response_transformer: None,
            is_upgrade: false,
            // Pre-allocate reasonable buffer sizes for WebSocket frames
            ws_client_buf: BytesMut::with_capacity(4096),
            ws_upstream_buf: BytesMut::with_capacity(4096),
            rewrite_host: None,

            ws_client_decompressor: None,
            ws_upstream_decompressor: None,

            middleware_ctx: Vec::new(),
            websocket_middleware_ctx: Vec::new(),
        }
    }

    /// Clear websocket buffers for reuse
    pub fn clear_ws_buffers(&mut self) {
        self.ws_client_buf.clear();
        self.ws_upstream_buf.clear();
    }
}

impl Default for RouteContext {
    fn default() -> Self {
        Self::new()
    }
}

// AppCtx has been moved to jokoway-core

#[cfg(test)]
mod tests {
    use super::AppCtx;

    #[test]
    fn app_ctx_insert_get_remove() {
        let ctx = AppCtx::new();

        assert!(ctx.get::<usize>().is_none());
        ctx.insert(12usize);
        assert_eq!(*ctx.get::<usize>().unwrap(), 12);

        ctx.insert(24usize);
        assert_eq!(*ctx.get::<usize>().unwrap(), 24);

        let removed = ctx.remove::<usize>().unwrap();
        assert_eq!(*removed, 24);
        assert!(ctx.get::<usize>().is_none());
    }

    #[test]
    fn app_ctx_handles_multiple_types() {
        let ctx = AppCtx::new();

        ctx.insert(10usize);
        ctx.insert("jokoway".to_string());

        assert_eq!(*ctx.get::<usize>().unwrap(), 10);
        assert_eq!(&*ctx.get::<String>().unwrap(), "jokoway");
    }

    #[test]
    fn app_ctx_remove_missing_returns_none() {
        let ctx = AppCtx::new();
        assert!(ctx.remove::<u64>().is_none());
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CustomData {
        id: u32,
        label: String,
    }

    #[test]
    fn app_ctx_store_custom_struct() {
        let ctx = AppCtx::new();
        let data = CustomData {
            id: 7,
            label: "alpha".to_string(),
        };

        ctx.insert(data);

        let stored = ctx.get::<CustomData>().unwrap();
        assert_eq!(stored.id, 7);
    }
}
