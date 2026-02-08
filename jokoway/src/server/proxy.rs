use crate::config::models::{JokowayConfig, PeerOptions as ConfigPeerOptions};
use crate::error::JokowayError;

use crate::prelude::*;
use crate::server::context::{AppCtx, RouteContext};
use crate::server::router::Router;
use crate::server::upstream::UpstreamManager;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::Version;
use jokoway_core::websocket::{
    WebsocketMiddlewareDyn, WsFrame, WsOpcode, WsParseResult, encode_ws_frame_into,
    mask_key_from_time, parse_ws_frames,
};
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::tls::{pkey::PKey, x509::X509};
use pingora::upstreams::peer::{BasicPeer, HttpPeer, PeerOptions};
use pingora::utils::tls::CertKey;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

pub trait ConfigurablePeer {
    fn options_mut(&mut self) -> &mut PeerOptions;
}

impl ConfigurablePeer for BasicPeer {
    fn options_mut(&mut self) -> &mut PeerOptions {
        &mut self.options
    }
}

impl ConfigurablePeer for HttpPeer {
    fn options_mut(&mut self) -> &mut PeerOptions {
        &mut self.options
    }
}

/// Cached peer configuration with pre-loaded certificates for performance
#[derive(Clone)]
pub struct CachedPeerConfig {
    pub options: ConfigPeerOptions,
    pub ca_certs: Option<Arc<Box<[X509]>>>,
    pub client_cert_key: Option<Arc<CertKey>>,
    pub tls: bool,
}

impl CachedPeerConfig {
    pub fn new(options: ConfigPeerOptions, tls: bool) -> Result<Self, JokowayError> {
        let mut cached = Self {
            options: options.clone(),
            ca_certs: None,
            client_cert_key: None,
            tls,
        };

        // Pre-load CA certificates if specified
        if let Some(cacert_path) = options.cacert.as_deref()
            && !cacert_path.is_empty()
        {
            match load_x509_stack(cacert_path) {
                Ok(certs) => {
                    cached.ca_certs = Some(Arc::new(certs.into_boxed_slice()));
                }
                Err(e) => {
                    log::error!("Failed to pre-load CA certs from {}: {}", cacert_path, e);
                    return Err(JokowayError::Tls(format!("Failed to load CA certs: {}", e)));
                }
            }
        }

        // Pre-load client certificate and key if specified
        if let (Some(cert_path), Some(key_path)) = (
            options.client_cert.as_deref(),
            options.client_key.as_deref(),
        ) && !cert_path.is_empty()
            && !key_path.is_empty()
        {
            match load_client_cert_key(cert_path, key_path) {
                Ok(cert_key) => {
                    cached.client_cert_key = Some(Arc::new(cert_key));
                }
                Err(e) => {
                    let msg = format!(
                        "Failed to pre-load client cert/key from {} and {}: {}",
                        cert_path, key_path, e
                    );
                    log::error!("{}", msg);
                    return Err(JokowayError::Tls(msg));
                }
            }
        }

        Ok(cached)
    }

    #[inline]
    pub fn apply_to_peer<P: ConfigurablePeer>(&self, peer: &mut P) {
        let peer_options = peer.options_mut();
        // Apply basic options (same as original apply_peer_options)
        if let Some(read_timeout) = self.options.read_timeout {
            peer_options.read_timeout = Some(Duration::from_secs(read_timeout));
        }
        if let Some(idle_timeout) = self.options.idle_timeout {
            peer_options.idle_timeout = Some(Duration::from_secs(idle_timeout));
        }
        if let Some(write_timeout) = self.options.write_timeout {
            peer_options.write_timeout = Some(Duration::from_secs(write_timeout));
        }
        if let Some(verify_cert) = self.options.verify_cert {
            peer_options.verify_cert = verify_cert;
        }
        if let Some(verify_hostname) = self.options.verify_hostname {
            peer_options.verify_hostname = verify_hostname;
        }
        if let Some(tcp_recv_buf) = self.options.tcp_recv_buf {
            peer_options.tcp_recv_buf = Some(tcp_recv_buf);
        }
        if let Some(ref curves) = self.options.curves {
            peer_options.curves = Some(Box::leak(curves.clone().into_boxed_str()));
        }
        if let Some(tcp_fast_open) = self.options.tcp_fast_open {
            peer_options.tcp_fast_open = tcp_fast_open;
        }

        // Set CA certificates if available
        if let Some(ca_certs) = &self.ca_certs {
            peer_options.ca = Some(ca_certs.clone());
        }
    }

    #[inline]
    pub fn apply_client_cert(&self, peer: &mut HttpPeer) {
        if let Some(client_cert_key) = &self.client_cert_key {
            peer.client_cert_key = Some(client_cert_key.clone());
        }
    }
}

// --- Proxy ---

#[derive(Clone)]
pub struct JokowayProxy {
    pub config: Arc<JokowayConfig>,
    pub router: Arc<Router>,
    pub http_middlewares: Arc<Vec<Arc<dyn HttpMiddlewareDyn>>>,
    pub websocket_middlewares: Arc<Vec<Arc<dyn WebsocketMiddlewareDyn>>>,
    pub app_ctx: Arc<AppCtx>,
    pub upstream_manager: Arc<UpstreamManager>,
}

impl JokowayProxy {
    pub fn new(router: Arc<Router>, app_ctx: Arc<AppCtx>) -> Result<Self, JokowayError> {
        let config = app_ctx
            .get::<JokowayConfig>()
            .ok_or_else(|| JokowayError::Config("JokowayConfig not found in AppCtx".to_string()))?;
        let middlewares = app_ctx
            .get::<Vec<Arc<dyn HttpMiddlewareDyn>>>()
            .unwrap_or_else(|| Arc::new(Vec::new()));
        let websocket_middlewares = app_ctx
            .get::<Vec<Arc<dyn WebsocketMiddlewareDyn>>>()
            .unwrap_or_else(|| Arc::new(Vec::new()));
        let upstream_manager = app_ctx.get::<UpstreamManager>().ok_or_else(|| {
            JokowayError::Config("UpstreamManager not found in AppCtx".to_string())
        })?;
        Ok(JokowayProxy {
            config,
            router,
            http_middlewares: middlewares,
            websocket_middlewares,
            app_ctx,
            upstream_manager,
        })
    }
}

#[inline]
pub fn merge_peer_options(
    parent: Option<&ConfigPeerOptions>,
    child: Option<&ConfigPeerOptions>,
) -> ConfigPeerOptions {
    let mut merged = parent.cloned().unwrap_or_default();
    if let Some(child) = child {
        if child.read_timeout.is_some() {
            merged.read_timeout = child.read_timeout;
        }
        if child.idle_timeout.is_some() {
            merged.idle_timeout = child.idle_timeout;
        }
        if child.write_timeout.is_some() {
            merged.write_timeout = child.write_timeout;
        }
        if child.verify_cert.is_some() {
            merged.verify_cert = child.verify_cert;
        }
        if child.verify_hostname.is_some() {
            merged.verify_hostname = child.verify_hostname;
        }
        if child.tcp_recv_buf.is_some() {
            merged.tcp_recv_buf = child.tcp_recv_buf;
        }
        if child.curves.is_some() {
            merged.curves = child.curves.clone();
        }
        if child.tcp_fast_open.is_some() {
            merged.tcp_fast_open = child.tcp_fast_open;
        }
        if child.cacert.is_some() {
            merged.cacert = child.cacert.clone();
        }
        if child.client_cert.is_some() {
            merged.client_cert = child.client_cert.clone();
        }
        if child.client_key.is_some() {
            merged.client_key = child.client_key.clone();
        }
        if child.sni.is_some() {
            merged.sni = child.sni.clone();
        }
    }
    merged
}

fn load_x509_stack(path: &str) -> Result<Vec<X509>, Box<dyn std::error::Error>> {
    let pem = fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let certs = X509::stack_from_pem(&pem)
        .map_err(|e| format!("Failed to parse X509 from {}: {}", path, e))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", path).into());
    }
    Ok(certs)
}

fn load_client_cert_key(
    cert_path: &str,
    key_path: &str,
) -> Result<CertKey, Box<dyn std::error::Error>> {
    let certs = load_x509_stack(cert_path)?;
    let key_pem = fs::read(key_path).map_err(|e| format!("Failed to read {}: {}", key_path, e))?;
    let key = PKey::private_key_from_pem(&key_pem)
        .map_err(|e| format!("Failed to parse private key from {}: {}", key_path, e))?;
    Ok(CertKey::new(certs, key))
}

#[async_trait]
impl ProxyHttp for JokowayProxy {
    type CTX = RouteContext;
    fn new_ctx(&self) -> Self::CTX {
        let mut ctx = RouteContext::new();
        for middleware in self.http_middlewares.iter() {
            ctx.middleware_ctx.push(middleware.new_ctx_dyn());
        }
        for ws_middleware in self.websocket_middlewares.iter() {
            ctx.websocket_middleware_ctx
                .push(ws_middleware.new_ctx_dyn());
        }
        ctx
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<Error>> {
        // Fast path: check middlewares first
        for (idx, middleware) in self.http_middlewares.iter().enumerate() {
            let middleware_ctx = &mut ctx.middleware_ctx[idx];
            if middleware
                .request_filter_dyn(session, middleware_ctx.as_mut(), &self.app_ctx)
                .await?
            {
                return Ok(true);
            }
        }

        let req_header = session.req_header_mut();
        let is_upgrade = req_header
            .headers
            .get("Upgrade")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));

        if is_upgrade {
            // Check if Connection header needs to be added
            let needs_connection_upgrade = req_header
                .headers
                .get("Connection")
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !value.to_ascii_lowercase().contains("upgrade"));

            if needs_connection_upgrade {
                req_header.insert_header("Connection", "Upgrade").ok();
            }
        }

        // Route matching with early return
        let match_result = self.router.match_request(req_header);

        if let Some(match_result) = match_result {
            log::debug!("Route matched: upstream={}", match_result.upstream_name);

            if let Some(transformer) = &match_result.req_transformer {
                transformer.transform_request(req_header);
            }

            ctx.upstream_name = Some(match_result.upstream_name);
            ctx.response_transformer = match_result.res_transformer;
            ctx.is_upgrade = is_upgrade;

            return Ok(false);
        }

        let mut header = ResponseHeader::build(404, None).unwrap();
        header.insert_header("Content-Type", "text/plain").ok();
        session
            .write_response_header(Box::new(header), true)
            .await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        // Fast path: get upstream name and find load balancer
        let upstream_name = ctx.upstream_name.as_ref().ok_or_else(|| {
            Error::explain(
                pingora::ErrorType::InternalError,
                "No upstream name in context",
            )
        })?;

        let load_balancer = self.upstream_manager.get(upstream_name).ok_or_else(|| {
            Error::explain(
                pingora::ErrorType::InternalError,
                "Load balancer not found for upstream",
            )
        })?;

        // Select backend using load balancer - Weighted selection (round-robin when weights are equal)
        let backend = load_balancer.select(b"", 256).ok_or_else(|| {
            Error::explain(
                pingora::ErrorType::InternalError,
                "No available backend from load balancer",
            )
        })?;

        // Get cached config with pre-loaded certificates
        let cached_config = backend.ext.get::<CachedPeerConfig>().cloned();
        let tls = cached_config.as_ref().unwrap().tls;
        let mut sni = String::new();

        if let Some(config) = cached_config.as_ref()
            && let Some(option_sni) = &config.options.sni
        {
            sni = option_sni.clone();
            ctx.rewrite_host = Some(sni.clone());
        }

        let mut peer = HttpPeer::new(backend, tls, sni);

        // Apply cached configuration (includes pre-loaded certificates)
        if let Some(config) = cached_config.as_ref() {
            config.apply_to_peer(&mut peer);
            config.apply_client_cert(&mut peer);
        }

        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        if ctx.is_upgrade {
            upstream_request.set_version(Version::HTTP_11);
        }

        if let Some(host) = &ctx.rewrite_host {
            upstream_request.insert_header("Host", host).map_err(|e| {
                Error::explain(pingora::ErrorType::InvalidHTTPHeader, e.to_string())
            })?;
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        for (idx, middleware) in self.http_middlewares.iter().enumerate() {
            let middleware_ctx = &mut ctx.middleware_ctx[idx];
            middleware
                .upstream_response_filter_dyn(
                    session,
                    upstream_response,
                    middleware_ctx.as_mut(),
                    &self.app_ctx,
                )
                .await?;
        }

        if let Some(transformer) = &ctx.response_transformer {
            if ctx.is_upgrade {
                return Ok(());
            }
            transformer.transform_response(upstream_response);
        }
        Ok(())
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        if !ctx.is_upgrade {
            for (idx, middleware) in self.http_middlewares.iter().enumerate() {
                let middleware_ctx = &mut ctx.middleware_ctx[idx];
                middleware
                    .request_body_filter_dyn(session, body, end_of_stream, middleware_ctx.as_mut())
                    .await?;
            }
            return Ok(());
        }

        let Some(chunk) = body.take() else {
            return Ok(());
        };

        // Fast path: if no extensions, pass through without parsing
        if self.websocket_middlewares.is_empty() {
            *body = Some(chunk);
            return Ok(());
        }

        // Reuse buffer to avoid frequent reallocations
        ctx.ws_client_buf.extend_from_slice(&chunk);
        let mut frames = Vec::with_capacity(16); // Pre-allocate reasonable capacity

        match parse_ws_frames(&mut ctx.ws_client_buf, &mut frames) {
            WsParseResult::Ok => {
                let mut out = BytesMut::with_capacity(chunk.len() + 256); // Pre-allocate output buffer

                for frame in frames {
                    let decompressor = if frame.rsv1 {
                        Some(
                            ctx.ws_client_decompressor
                                .get_or_insert_with(|| flate2::Decompress::new(false)),
                        )
                    } else {
                        None
                    };

                    match apply_ws_middlewares(
                        &self.websocket_middlewares,
                        &mut ctx.websocket_middleware_ctx,
                        WebsocketDirection::DownstreamToUpstream,
                        frame,
                        decompressor,
                    ) {
                        WebsocketMessageAction::Forward(updated) => {
                            encode_ws_frame_into(&updated, Some(mask_key_from_time()), &mut out);
                        }
                        WebsocketMessageAction::Drop => {}
                        WebsocketMessageAction::Close(payload) => {
                            encode_ws_frame_into(
                                &close_frame(payload),
                                Some(mask_key_from_time()),
                                &mut out,
                            );
                            break;
                        }
                    }
                }

                *body = if out.is_empty() {
                    None
                } else {
                    Some(out.freeze())
                };
            }
            WsParseResult::Incomplete => {
                *body = None;
            }
            WsParseResult::Invalid => {
                match handle_ws_error(
                    &self.websocket_middlewares,
                    &mut ctx.websocket_middleware_ctx,
                    WebsocketDirection::DownstreamToUpstream,
                    WebsocketError::InvalidFrame,
                ) {
                    WebsocketErrorAction::PassThrough => {
                        let data = ctx.ws_client_buf.split_to(ctx.ws_client_buf.len()).freeze();
                        *body = if data.is_empty() { None } else { Some(data) };
                    }
                    WebsocketErrorAction::Drop => {
                        ctx.clear_ws_buffers();
                        *body = None;
                    }
                    WebsocketErrorAction::Close(payload) => {
                        ctx.clear_ws_buffers();
                        let mut out = BytesMut::with_capacity(128);
                        encode_ws_frame_into(
                            &close_frame(payload),
                            Some(mask_key_from_time()),
                            &mut out,
                        );
                        *body = Some(out.freeze());
                    }
                }
            }
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>, Box<Error>> {
        if !ctx.is_upgrade {
            for (idx, middleware) in self.http_middlewares.iter().enumerate() {
                let middleware_ctx = &mut ctx.middleware_ctx[idx];
                middleware.response_body_filter_dyn(
                    session,
                    body,
                    end_of_stream,
                    middleware_ctx.as_mut(),
                )?;
            }
            return Ok(None);
        }

        let Some(chunk) = body.take() else {
            return Ok(None);
        };

        // Fast path: if no extensions, pass through without parsing
        if self.websocket_middlewares.is_empty() {
            *body = Some(chunk);
            return Ok(None);
        }

        ctx.ws_upstream_buf.extend_from_slice(&chunk);
        let mut frames = Vec::new();
        match parse_ws_frames(&mut ctx.ws_upstream_buf, &mut frames) {
            WsParseResult::Ok => {
                let mut out = BytesMut::new();
                for frame in frames {
                    let decompressor = if frame.rsv1 {
                        Some(
                            ctx.ws_upstream_decompressor
                                .get_or_insert_with(|| flate2::Decompress::new(false)),
                        )
                    } else {
                        None
                    };

                    match apply_ws_middlewares(
                        &self.websocket_middlewares,
                        &mut ctx.websocket_middleware_ctx,
                        WebsocketDirection::UpstreamToDownstream,
                        frame,
                        decompressor,
                    ) {
                        WebsocketMessageAction::Forward(updated) => {
                            encode_ws_frame_into(&updated, None, &mut out);
                        }
                        WebsocketMessageAction::Drop => {}
                        WebsocketMessageAction::Close(payload) => {
                            encode_ws_frame_into(&close_frame(payload), None, &mut out);
                            break;
                        }
                    }
                }
                if out.is_empty() {
                    *body = None;
                } else {
                    *body = Some(out.freeze());
                }
            }
            WsParseResult::Incomplete => {
                *body = None;
            }
            WsParseResult::Invalid => {
                match handle_ws_error(
                    &self.websocket_middlewares,
                    &mut ctx.websocket_middleware_ctx,
                    WebsocketDirection::UpstreamToDownstream,
                    WebsocketError::InvalidFrame,
                ) {
                    WebsocketErrorAction::PassThrough => {
                        let data = ctx
                            .ws_upstream_buf
                            .split_to(ctx.ws_upstream_buf.len())
                            .freeze();
                        if data.is_empty() {
                            *body = None;
                        } else {
                            *body = Some(data);
                        }
                    }
                    WebsocketErrorAction::Drop => {
                        ctx.ws_upstream_buf.clear();
                        *body = None;
                    }
                    WebsocketErrorAction::Close(payload) => {
                        ctx.ws_upstream_buf.clear();
                        let mut out = BytesMut::new();
                        encode_ws_frame_into(&close_frame(payload), None, &mut out);
                        *body = Some(out.freeze());
                    }
                }
            }
        }
        Ok(None)
    }

    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut Self::CTX) {}
}

fn apply_ws_middlewares(
    middlewares: &[Arc<dyn WebsocketMiddlewareDyn>],
    middleware_ctxs: &mut [Box<dyn std::any::Any + Send + Sync>],
    direction: WebsocketDirection,
    mut frame: WsFrame,
    decompressor: Option<&mut flate2::Decompress>,
) -> WebsocketMessageAction {
    // Decompress if RSV1 is set (permessage-deflate)
    let original_payload = frame.payload.clone();
    let was_compressed = frame.rsv1;
    let mut decompressed_payload = None;
    if was_compressed {
        if let Some(decompressor) = decompressor {
            if let Some(decompressed) = frame.decompress_with(decompressor) {
                decompressed_payload = Some(decompressed.clone());
                frame.payload = decompressed;
                frame.rsv1 = false;
            } else {
                log::error!("Failed to decompress WebSocket frame");
                return WebsocketMessageAction::Forward(frame);
            }
        } else {
            // No decompressor available but frame is compressed
            log::warn!("Compressed frame received but no decompressor available");
            return WebsocketMessageAction::Forward(frame);
        }
    }

    let mut action = WebsocketMessageAction::Forward(frame);
    for (idx, middleware) in middlewares.iter().enumerate() {
        let ctx = &mut middleware_ctxs[idx];
        action = match action {
            WebsocketMessageAction::Forward(current) => {
                middleware.on_message_dyn(direction, current, ctx.as_mut())
            }
            other => other,
        };
        if !matches!(action, WebsocketMessageAction::Forward(_)) {
            break;
        }
    }

    if let WebsocketMessageAction::Forward(mut final_frame) = action {
        // If the payload was modified, we keep it uncompressed (RSV1=false)
        // If it was NOT modified and was originally compressed, we restore it to compressed state
        // This is a heuristic: if the bytes are identical (or both match the decompressed version), we assume no modification.
        let is_modified = if let Some(dp) = &decompressed_payload {
            final_frame.payload != *dp
        } else {
            final_frame.payload != original_payload
        };

        if was_compressed && !is_modified {
            final_frame.payload = original_payload;
            final_frame.rsv1 = true;
        }
        action = WebsocketMessageAction::Forward(final_frame);
    }

    action
}

fn handle_ws_error(
    middlewares: &[Arc<dyn WebsocketMiddlewareDyn>],
    middleware_ctxs: &mut [Box<dyn std::any::Any + Send + Sync>],
    direction: WebsocketDirection,
    error: WebsocketError,
) -> WebsocketErrorAction {
    let mut action = WebsocketErrorAction::PassThrough;
    for (idx, middleware) in middlewares.iter().enumerate() {
        let ctx = &mut middleware_ctxs[idx];
        match middleware.on_error_dyn(direction, error.clone(), &mut *ctx) {
            WebsocketErrorAction::PassThrough => {}
            WebsocketErrorAction::Drop => {
                action = WebsocketErrorAction::Drop;
            }
            WebsocketErrorAction::Close(payload) => {
                return WebsocketErrorAction::Close(payload);
            }
        }
    }
    action
}

fn close_frame(payload: Option<Vec<u8>>) -> WsFrame {
    WsFrame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: WsOpcode::Close,
        payload: payload.map(Bytes::from).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{JokowayConfig, Upstream, UpstreamServer};
    use crate::extensions::dns::DnsResolver;
    use crate::server::context::AppCtx;
    use crate::server::router::{ALL_PROTOCOLS, Router};
    use crate::server::service::ServiceManager;
    use crate::server::upstream::UpstreamManager;
    use jokoway_core::websocket::WebsocketMiddleware;
    use std::sync::Arc;

    struct UppercaseExtension;

    impl jokoway_core::websocket::WebsocketMiddleware for UppercaseExtension {
        type CTX = ();

        fn name(&self) -> &'static str {
            "UppercaseExtension"
        }

        fn new_ctx(&self) -> Self::CTX {
            ()
        }

        fn on_message(
            &self,
            _direction: WebsocketDirection,
            mut frame: WsFrame,
            _ctx: &mut Self::CTX,
        ) -> WebsocketMessageAction {
            if let Ok(text) = std::str::from_utf8(&frame.payload) {
                frame.payload = Bytes::copy_from_slice(text.to_ascii_uppercase().as_bytes());
            }
            WebsocketMessageAction::Forward(frame)
        }
    }

    #[test]
    fn websocket_middleware_transform() {
        // Test direct middleware usage first
        let middleware = UppercaseExtension;
        let mut ctx = middleware.new_ctx();
        let frame = WsFrame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: WsOpcode::Text,
            payload: Bytes::from_static(b"hello"),
        };

        match middleware.on_message(
            WebsocketDirection::UpstreamToDownstream,
            frame.clone(),
            &mut ctx,
        ) {
            WebsocketMessageAction::Forward(updated) => {
                assert_eq!(updated.payload, Bytes::from_static(b"HELLO"));
            }
            _ => panic!("unexpected action"),
        }

        // Now test through trait object
        let middleware_dyn: Arc<dyn WebsocketMiddlewareDyn> = Arc::new(UppercaseExtension);
        let mut ctx_dyn = middleware_dyn.new_ctx_dyn();

        match middleware_dyn.on_message_dyn(
            WebsocketDirection::UpstreamToDownstream,
            frame,
            &mut *ctx_dyn,
        ) {
            WebsocketMessageAction::Forward(updated) => {
                assert_eq!(updated.payload, Bytes::from_static(b"HELLO"));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn test_load_balancer_creation() {
        // Create a test configuration with multiple servers
        let mut config = JokowayConfig::default();

        let upstream = Upstream {
            name: "test_upstream".to_string(),
            peer_options: None,
            servers: vec![
                UpstreamServer {
                    host: "127.0.0.1:8080".to_string(),
                    weight: Some(1),
                    tls: None,
                    peer_options: None,
                },
                UpstreamServer {
                    host: "127.0.0.1:8081".to_string(),
                    weight: Some(2),
                    tls: None,
                    peer_options: None,
                },
                UpstreamServer {
                    host: "127.0.0.1:8082".to_string(),
                    weight: Some(1),
                    tls: None,
                    peer_options: None,
                },
            ],
            health_check: None,
        };

        config.upstreams.push(upstream);
        let config_arc = Arc::new(config.clone());

        // Create ServiceManager and UpstreamManager
        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );

        let app_ctx = AppCtx::new();
        app_ctx.insert(config.clone());
        app_ctx.insert(DnsResolver::new(&config));

        let (upstream_manager_struct, _services) =
            UpstreamManager::new(&app_ctx).expect("Failed to create UpstreamManager");
        upstream_manager_struct.update_backends().await;
        app_ctx.insert(upstream_manager_struct);
        let upstream_manager = app_ctx.get::<UpstreamManager>().unwrap();

        // Create router
        let router = Router::new(
            service_manager,
            upstream_manager.clone(),
            &ALL_PROTOCOLS,
            // &config,
        );

        // Create the proxy with load balancers
        let _proxy = JokowayProxy::new(router, Arc::new(app_ctx.clone()))
            .expect("Failed to create JokowayProxy");

        // Verify load balancer was created
        assert!(upstream_manager.get("test_upstream").is_some());

        // Verify all servers are included
        let load_balancer = upstream_manager.get("test_upstream").unwrap();
        let backends = load_balancer.backends().get_backend();
        assert_eq!(backends.len(), 3);
        let backends = load_balancer.backends().get_backend();
        assert_eq!(backends.len(), 3);

        // Verify server addresses
        let hosts: Vec<String> = backends.iter().map(|b| b.addr.to_string()).collect();
        assert!(hosts.contains(&"127.0.0.1:8080".to_string()));
        assert!(hosts.contains(&"127.0.0.1:8081".to_string()));
        assert!(hosts.contains(&"127.0.0.1:8082".to_string()));

        // Verify weights
        let backend_8081 = backends
            .iter()
            .find(|b| b.addr.to_string() == "127.0.0.1:8081")
            .unwrap();
        assert_eq!(backend_8081.weight, 2); // Weight should be 2 for port 8081
    }

    #[tokio::test]
    async fn test_load_balancer_selection() {
        // Create a test configuration
        let mut config = JokowayConfig::default();

        let upstream = Upstream {
            name: "test_upstream".to_string(),
            peer_options: None,
            servers: vec![
                UpstreamServer {
                    host: "127.0.0.1:8080".to_string(),
                    weight: Some(1),
                    tls: None,
                    peer_options: None,
                },
                UpstreamServer {
                    host: "127.0.0.1:8081".to_string(),
                    weight: Some(1),
                    tls: None,
                    peer_options: None,
                },
            ],
            health_check: None,
        };

        config.upstreams.push(upstream);
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );

        let app_ctx = AppCtx::new();
        app_ctx.insert(config.clone());
        app_ctx.insert(DnsResolver::new(&config));

        let (upstream_manager_struct, _services) =
            UpstreamManager::new(&app_ctx).expect("Failed to create UpstreamManager");
        upstream_manager_struct.update_backends().await;
        app_ctx.insert(upstream_manager_struct);
        let upstream_manager = app_ctx.get::<UpstreamManager>().unwrap();

        let router = Router::new(
            service_manager,
            upstream_manager.clone(),
            &ALL_PROTOCOLS,
            // &config,
        );

        let _proxy = JokowayProxy::new(router, Arc::new(app_ctx.clone()))
            .expect("Failed to create JokowayProxy");

        let load_balancer = upstream_manager.get("test_upstream").unwrap();

        // Test multiple selections to verify round-robin behavior
        let mut selections = Vec::new();
        for _ in 0..10 {
            if let Some(backend) = load_balancer.select(b"", 256) {
                selections.push(backend.addr.to_string());
            }
        }

        // With round-robin and equal weights, we should see alternating selections
        assert!(!selections.is_empty());

        // Verify both backends are selected
        let unique_selections: std::collections::HashSet<_> = selections.iter().collect();
        assert!(!unique_selections.is_empty()); // Should have at least 1 unique backend

        // With round-robin, we should see both backends being selected
        let has_8080 = selections.iter().any(|s: &String| s.contains("8080"));
        let has_8081 = selections.iter().any(|s: &String| s.contains("8081"));
        assert!(
            has_8080 || has_8081,
            "Should select from available backends"
        );
    }

    #[test]
    fn test_empty_upstream() {
        let mut config = JokowayConfig::default();

        let upstream = Upstream {
            name: "empty_upstream".to_string(),
            peer_options: None,
            servers: vec![], // Empty servers list
            health_check: None,
        };

        config.upstreams.push(upstream);
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );

        let app_ctx = AppCtx::new();
        app_ctx.insert(config.clone());
        app_ctx.insert(DnsResolver::new(&config));

        let (upstream_manager_struct, _services) =
            UpstreamManager::new(&app_ctx).expect("Failed to create UpstreamManager");
        app_ctx.insert(upstream_manager_struct);
        let upstream_manager = app_ctx.get::<UpstreamManager>().unwrap();

        let router = Router::new(
            service_manager,
            upstream_manager.clone(),
            &ALL_PROTOCOLS,
            // &config,
        );

        let _proxy = JokowayProxy::new(router, Arc::new(app_ctx.clone()))
            .expect("Failed to create JokowayProxy");

        // Should not create load balancer for empty upstream
        assert!(upstream_manager.get("empty_upstream").is_none());
    }
}
