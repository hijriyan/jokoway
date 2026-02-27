use http::header::HeaderName;
use std::sync::Arc;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForwardedInfo {
    pub for_nodes: Option<Arc<str>>,
    pub host: Option<Arc<str>>,
    pub proto: Option<Arc<str>>,
    pub client_ip: Option<Arc<str>>,
}

impl ForwardedInfo {
    pub fn new() -> Self {
        Self::default()
    }
}

pub const XFF: HeaderName = HeaderName::from_static("x-forwarded-for");
pub const XFH: HeaderName = HeaderName::from_static("x-forwarded-host");
pub const XFP: HeaderName = HeaderName::from_static("x-forwarded-proto");
