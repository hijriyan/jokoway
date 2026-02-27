#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForwardedInfo {
    pub for_nodes: Option<String>,
    pub host: Option<String>,
    pub proto: Option<String>,
    pub client_ip: Option<String>,
}

impl ForwardedInfo {
    pub fn new() -> Self {
        Self::default()
    }
}
