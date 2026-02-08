pub use pingora::server::configuration::ServerConf;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "api-extension")]
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize)]
pub struct RootConfig {
    pub jokoway: JokowayConfig,
    pub pingora: Option<ServerConf>,
}

#[cfg(feature = "acme-extension")]
pub use jokoway_acme::{AcmeChallengeType, AcmeSettings};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct JokowayConfig {
    pub http_listen: String,
    pub https_listen: Option<String>,
    pub api: Option<ApiSettings>,
    pub ssl: Option<SslSettings>,
    #[cfg(feature = "acme-extension")]
    pub acme: Option<AcmeSettings>,

    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub services: Vec<Arc<Service>>,
    #[serde(default)]
    pub dns: Option<DnsSettings>,
    #[serde(default)]
    pub compress: Option<bool>,

    // Allow for extra configuration that might not be strictly defined
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ApiSettings {
    pub listen: Option<String>,
    pub basic_auth: Option<BasicAuth>,
    pub rate_limit: Option<RateLimit>,
    pub openapi: Option<OpenApiSettings>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RateLimit {
    pub requests_per_second: u32,
    pub burst: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsSettings {
    pub nameservers: Option<Vec<String>>,
    pub timeout: Option<u64>,
    pub attempts: Option<usize>,
    pub strategy: Option<String>,
    pub cache_size: Option<usize>,
    #[serde(default = "default_true")]
    pub use_hosts_file: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
pub struct PeerOptions {
    pub read_timeout: Option<u64>,
    pub idle_timeout: Option<u64>,
    pub write_timeout: Option<u64>,
    pub verify_cert: Option<bool>,
    pub verify_hostname: Option<bool>,
    pub tcp_recv_buf: Option<usize>,
    pub curves: Option<String>,
    pub tcp_fast_open: Option<bool>,
    pub cacert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub sni: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SslSettings {
    pub cacert: Option<String>,
    pub server_cert: Option<String>,
    pub server_key: Option<String>,
    pub sans: Option<Vec<String>>,
    pub ssl_min_version: Option<String>,
    pub ssl_max_version: Option<String>,
    pub cipher_suites: Option<CipherSuites>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CipherSuites {
    pub tls12: Option<Vec<String>>,
    pub tls13: Option<Vec<String>>,
}

fn default_openapi_title() -> String {
    "Jokoway API".to_string()
}

fn default_openapi_description() -> String {
    "Jokoway Management API".to_string()
}

fn default_openapi_root_path() -> String {
    "/docs".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
pub struct OpenApiSettings {
    #[serde(default = "default_openapi_title")]
    pub title: String,
    #[serde(default = "default_openapi_description")]
    pub description: String,
    #[serde(default = "default_openapi_root_path")]
    pub root_path: String,
}

impl Default for OpenApiSettings {
    fn default() -> Self {
        Self {
            title: default_openapi_title(),
            description: default_openapi_description(),
            root_path: default_openapi_root_path(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
pub struct Upstream {
    pub name: String,
    pub peer_options: Option<PeerOptions>,
    #[serde(default)]
    pub servers: Vec<UpstreamServer>,
    pub health_check: Option<HealthCheckConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
pub struct UpstreamServer {
    pub host: String,
    pub weight: Option<u32>,
    pub tls: Option<bool>,
    pub peer_options: Option<PeerOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
pub enum ServiceProtocol {
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "https")]
    Https,
    #[serde(rename = "ws")]
    Ws,
    #[serde(rename = "wss")]
    Wss,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
pub struct Service {
    pub name: String,
    pub host: String,
    pub protocols: Vec<ServiceProtocol>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
pub struct Route {
    pub name: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
pub struct Rule {
    pub rule: String,
    pub priority: Option<i32>,
    pub request_transformer: Option<String>,
    pub response_transformer: Option<String>,
}

// Health Check Configuration

fn default_health_check_interval() -> u64 {
    10
}

fn default_health_check_timeout() -> u64 {
    3
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    2
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckType {
    Http,
    Https,
    Tcp,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "api-extension", derive(ToSchema))]
pub struct HealthCheckConfig {
    #[serde(rename = "type")]
    pub check_type: HealthCheckType,

    #[serde(default = "default_health_check_interval")]
    pub interval: u64, // seconds

    #[serde(default = "default_health_check_timeout")]
    pub timeout: u64, // seconds

    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,

    // HTTP/HTTPS specific
    pub path: Option<String>,
    pub method: Option<String>, // GET, HEAD, POST
    pub expected_status: Option<Vec<u16>>,
    pub headers: Option<HashMap<String, String>>,
}
