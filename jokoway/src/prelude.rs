//! Prelude for the `jokoway` crate.
//!
//! This module re-exports the most commonly used types, traits, and macros
//! to make it easier to get started with `jokoway`.

pub use crate::error::JokowayError;
pub use crate::server::context::{AppContext, Context, ProxyContext, RequestContext};
pub use crate::server::proxy::JokowayProxy;

pub mod core {
    pub use jokoway_core::prelude::*;
}

#[cfg(feature = "acme")]
pub mod acme {
    pub use jokoway_acme::prelude::*;
}

#[cfg(feature = "compress")]
pub mod compress {
    pub use jokoway_compress::prelude::*;
}

#[cfg(feature = "forwarded")]
pub mod forwarded {
    pub use jokoway_forwarded::prelude::*;
}

pub mod rules {
    pub use jokoway_rules::prelude::*;
}

pub mod transformer {
    pub use jokoway_transformer::prelude::*;
}
