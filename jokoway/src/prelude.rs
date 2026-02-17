//! Prelude for the `jokoway` crate.
//!
//! This module re-exports the most commonly used types, traits, and macros
//! to make it easier to get started with `jokoway`.

pub use crate::error::JokowayError;
pub use crate::server::context::{AppCtx, RouteContext};
pub use crate::server::proxy::JokowayProxy;
#[cfg(feature = "acme-extension")]
pub use jokoway_acme::{AcmeChallengeType, AcmeSettings};
pub use jokoway_core::config::*;
pub use jokoway_core::tls::{TlsCallback, TlsCallbackHandler};
pub use jokoway_core::websocket::{
    WebsocketDirection, WebsocketError, WebsocketErrorAction, WebsocketMessageAction,
    WebsocketMiddleware, WebsocketMiddlewareDyn, WsFrame,
};
pub use jokoway_core::{HttpMiddleware, HttpMiddlewareDyn, JokowayExtension};
