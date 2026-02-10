use crate::config::models::{ApiSettings, Service, ServiceProtocol, Upstream};
use crate::extensions::dns::DnsResolver;
use crate::prelude::*;
use crate::server::context::AppCtx;
use crate::server::service::{RuntimeService, ServiceManager};
use crate::server::upstream::UpstreamManager;
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};

use pingora::server::ShutdownWatch;
use pingora::services::background::{BackgroundService, GenBackgroundService};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

// API Models

// Upstream requests
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddUpstreamRequest {
    pub upstream: Upstream,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUpstreamRequest {
    pub name: String,
    pub upstream: Upstream,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RemoveUpstreamRequest {
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyUpstreamRequest {
    pub name: String,
}

// Service requests
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddServiceRequest {
    pub service: Service,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateServiceRequest {
    pub name: String,
    pub service: Service,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RemoveServiceRequest {
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyServiceRequest {
    pub name: String,
}

// Common responses
#[derive(Debug, Serialize, ToSchema)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamListResponse {
    pub upstreams: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceListResponse {
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceInfo {
    pub name: String,
    pub host: String,
    pub protocols: Vec<ServiceProtocol>,
    pub routes: Vec<crate::config::models::Route>,
}

impl From<RuntimeService> for ServiceInfo {
    fn from(svc: RuntimeService) -> Self {
        ServiceInfo {
            name: svc.name,
            host: svc.host.to_string(),
            protocols: svc.protocols,
            routes: svc.config.routes.clone(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyResponse {
    pub exists: bool,
}

// API Extension

pub struct ApiExtension {
    settings: ApiSettings,
}

impl ApiExtension {
    pub fn new(settings: ApiSettings) -> Self {
        Self { settings }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_upstreams,
        verify_upstream,
        add_upstream,
        update_upstream,
        remove_upstream,
        list_services,
        verify_service,
        add_service,
        update_service,
        remove_service
    ),
    components(
        schemas(
            AddUpstreamRequest, UpdateUpstreamRequest, RemoveUpstreamRequest, VerifyUpstreamRequest,
            AddServiceRequest, UpdateServiceRequest, RemoveServiceRequest, VerifyServiceRequest,
            SuccessResponse, ErrorResponse, UpstreamListResponse, ServiceListResponse, ServiceInfo, VerifyResponse,
            // Config models
            crate::config::models::Upstream,
            crate::config::models::UpstreamServer,
            crate::config::models::PeerOptions,
            crate::config::models::HealthCheckConfig,
            crate::config::models::HealthCheckType,
            crate::config::models::Service,
            crate::config::models::ServiceProtocol,
            crate::config::models::Route,
            crate::config::models::Rule
        )
    ),
    tags(
        (name = "upstreams", description = "Upstream management endpoints"),
        (name = "services", description = "Service management endpoints")
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "basic_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Basic)
                        .description(Some("Basic Auth"))
                        .build(),
                ),
            )
        }
    }
}

#[derive(Clone)]
struct ApiState {
    app_ctx: Arc<AppCtx>,
}

struct ApiService {
    settings: ApiSettings,
    app_ctx: Arc<AppCtx>,
}

#[async_trait]
impl BackgroundService for ApiService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let state = ApiState {
            app_ctx: self.app_ctx.clone(),
        };

        let mut protected_routes = Router::new()
            .route("/upstreams/list", get(list_upstreams))
            .route("/upstreams/verify", post(verify_upstream))
            .route("/upstreams/add", post(add_upstream))
            .route("/upstreams/update", post(update_upstream))
            .route("/upstreams/remove", post(remove_upstream))
            .route("/services/list", get(list_services))
            .route("/services/verify", post(verify_service))
            .route("/services/add", post(add_service))
            .route("/services/update", post(update_service))
            .route("/services/remove", post(remove_service))
            .with_state(state);

        // Apply basic auth if configured
        if let Some(ref auth) = self.settings.basic_auth {
            let username = auth.username.clone();
            let password = auth.password.clone();
            protected_routes = protected_routes.layer(middleware::from_fn(move |req, next| {
                basic_auth_middleware(req, next, username.clone(), password.clone())
            }));
            log::info!("API basic authentication enabled");
        }

        // Apply rate limiting if configured
        if let Some(ref rate_limit) = self.settings.rate_limit {
            let governor_conf = Arc::new(
                GovernorConfigBuilder::default()
                    .per_second(rate_limit.requests_per_second as u64)
                    .burst_size(rate_limit.burst)
                    .finish()
                    .unwrap(),
            );
            protected_routes = protected_routes.layer(GovernorLayer::new(governor_conf));
            log::info!(
                "API rate limiting enabled: {} req/s, burst {}",
                rate_limit.requests_per_second,
                rate_limit.burst
            );
        }

        // Configure OpenAPI
        let mut openapi = ApiDoc::openapi();
        let mut swagger_path = "/docs".to_string();
        let mut openapi_path = "/docs/openapi.json".to_string();

        if let Some(openapi_settings) = &self.settings.openapi {
            openapi.info.title = openapi_settings.title.clone();
            openapi.info.description = Some(openapi_settings.description.clone());

            swagger_path = openapi_settings.root_path.clone();
            // Clean up path for openapi.json relative to root
            let clean_root = openapi_settings.root_path.trim_end_matches('/');
            openapi_path = format!("{}/openapi.json", clean_root);
        }

        let app = Router::new()
            .merge(protected_routes)
            .merge(SwaggerUi::new(swagger_path).url(openapi_path, openapi))
            .layer(middleware::from_fn(no_cache_middleware));

        let listen_addr = self.settings.listen.as_ref().unwrap();
        match TcpListener::bind(listen_addr).await {
            Ok(listener) => {
                log::info!("API server listening on {}", listen_addr);
                let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                    let _ = shutdown.changed().await;
                });

                if let Err(e) = server.await {
                    log::error!("API server error: {}", e);
                }
            }
            Err(e) => {
                log::error!("Failed to bind API server to {}: {}", listen_addr, e);
            }
        }
    }
}

impl JokowayExtension for ApiExtension {
    fn init(
        &self,
        server: &mut pingora::server::Server,
        app_ctx: &mut jokoway_core::AppCtx,
        _http_middlewares: &mut Vec<std::sync::Arc<dyn HttpMiddlewareDyn>>,
        _websocket_middlewares: &mut Vec<
            std::sync::Arc<dyn jokoway_core::websocket::WebsocketMiddlewareDyn>,
        >,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let service = GenBackgroundService::new(
            "api_server".to_string(),
            Arc::new(ApiService {
                settings: self.settings.clone(),
                app_ctx: Arc::new(app_ctx.clone()),
            }),
        );
        server.add_service(service);

        log::info!(
            "API Extension initialized on {}",
            self.settings
                .listen
                .as_ref()
                .unwrap_or(&"unknown".to_string())
        );
        Ok(())
    }
}

// Middleware functions
async fn basic_auth_middleware(
    req: Request<axum::body::Body>,
    next: Next,
    username: String,
    password: String,
) -> Response {
    use axum::http::header::AUTHORIZATION;

    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if let Some(auth) = auth_header
        && let Some(encoded) = auth.strip_prefix("Basic ")
    {
        use base64::Engine;
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded)
            && let Ok(credentials) = String::from_utf8(decoded)
        {
            let parts: Vec<&str> = credentials.splitn(2, ':').collect();
            if parts.len() == 2 && parts[0] == username && parts[1] == password {
                return next.run(req).await;
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Basic realm=\"API\"")],
        "Unauthorized",
    )
        .into_response()
}

async fn no_cache_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    use axum::http::HeaderValue;
    use axum::http::header::{CACHE_CONTROL, EXPIRES, PRAGMA};

    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(EXPIRES, HeaderValue::from_static("0"));

    response
}

// Upstream handlers
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use x509_parser::pem::Pem;

fn validate_pem(content: &str) -> bool {
    // Basic check: looks like a PEM
    if !content.contains("-----BEGIN") {
        return false;
    }
    // Try parsing
    matches!(
        Pem::read(std::io::Cursor::new(content.as_bytes())),
        Ok((_, _))
    )
}

fn get_upstream_temp_dir(upstream_name: &str) -> PathBuf {
    let mut temp_dir = std::env::temp_dir();
    temp_dir.push("jokoway");
    temp_dir.push("upstreams");
    temp_dir.push(upstream_name);
    temp_dir
}

async fn cleanup_upstream_files(upstream_name: &str) {
    let dir = get_upstream_temp_dir(upstream_name);
    if dir.exists() {
        if let Err(e) = fs::remove_dir_all(&dir).await {
            log::warn!(
                "Failed to cleanup temp files for upstream {}: {}",
                upstream_name,
                e
            );
        } else {
            log::debug!("Cleaned up temp files for upstream {}", upstream_name);
        }
    }
}

async fn save_cert_to_file(
    upstream_name: &str,
    filename: &str,
    content: &str,
) -> Result<String, String> {
    let dir = get_upstream_temp_dir(upstream_name);
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .await
            .map_err(|e| format!("Failed to create temp dir: {}", e))?;
    }

    let file_path = dir.join(filename);
    let mut file = fs::File::create(&file_path)
        .await
        .map_err(|e| format!("Failed to create file: {}", e))?;
    file.write_all(content.as_bytes())
        .await
        .map_err(|e| format!("Failed to write to file: {}", e))?;
    file.flush()
        .await
        .map_err(|e| format!("Failed to flush file: {}", e))?;

    Ok(file_path.to_string_lossy().into_owned())
}

async fn process_peer_options(
    upstream_name: &str,
    options: &mut crate::config::models::PeerOptions,
    prefix: &str,
) -> Result<(), String> {
    if let Some(cert) = &options.cacert
        && validate_pem(cert)
    {
        let path =
            save_cert_to_file(upstream_name, &format!("{}_cacert.pem", prefix), cert).await?;
        options.cacert = Some(path);
    }
    if let Some(cert) = &options.client_cert
        && validate_pem(cert)
    {
        let path =
            save_cert_to_file(upstream_name, &format!("{}_client.crt", prefix), cert).await?;
        options.client_cert = Some(path);
    }
    if let Some(key) = &options.client_key
        && validate_pem(key)
    {
        let path = save_cert_to_file(upstream_name, &format!("{}_client.key", prefix), key).await?;
        options.client_key = Some(path);
    }
    Ok(())
}

async fn process_upstream_certs(
    upstream: &mut crate::config::models::Upstream,
) -> Result<(), String> {
    // Process top-level peer options
    if let Some(options) = &mut upstream.peer_options {
        process_peer_options(&upstream.name, options, "root").await?;
    }

    // Process server-level peer options
    for (i, server) in upstream.servers.iter_mut().enumerate() {
        if let Some(options) = &mut server.peer_options {
            process_peer_options(&upstream.name, options, &format!("server_{}", i)).await?;
        }
    }

    Ok(())
}

#[utoipa::path(
    get,
    path = "/upstreams/list",
    tag = "upstreams",
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "List all upstreams", body = UpstreamListResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn list_upstreams(
    State(state): State<ApiState>,
) -> Result<Json<UpstreamListResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    let upstreams = upstream_manager.list_upstreams();
    Ok(Json(UpstreamListResponse { upstreams }))
}

#[utoipa::path(
    post,
    path = "/upstreams/verify",
    tag = "upstreams",
    request_body = VerifyUpstreamRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Verify upstream existence", body = VerifyResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn verify_upstream(
    State(state): State<ApiState>,
    Json(req): Json<VerifyUpstreamRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    let exists = upstream_manager.verify_upstream(&req.name);
    Ok(Json(VerifyResponse { exists }))
}

#[utoipa::path(
    post,
    path = "/upstreams/add",
    tag = "upstreams",
    request_body = AddUpstreamRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Add new upstream", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn add_upstream(
    State(state): State<ApiState>,
    Json(mut req): Json<AddUpstreamRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    let dns_resolver = state
        .app_ctx
        .get::<DnsResolver>()
        .ok_or_else(|| ApiError::Internal("DnsResolver not found".into()))?;

    // Process certificates
    process_upstream_certs(&mut req.upstream)
        .await
        .map_err(ApiError::BadRequest)?;

    let upstream_name = req.upstream.name.clone();

    upstream_manager
        .add_upstream(req.upstream, dns_resolver)
        .await
        .map_err(|e| {
            let name_for_cleanup = upstream_name.clone();
            tokio::spawn(async move {
                cleanup_upstream_files(&name_for_cleanup).await;
            });
            ApiError::BadRequest(e.to_string())
        })?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Upstream added successfully".into(),
    }))
}

#[utoipa::path(
    post,
    path = "/upstreams/update",
    tag = "upstreams",
    request_body = UpdateUpstreamRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Update existing upstream", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn update_upstream(
    State(state): State<ApiState>,
    Json(mut req): Json<UpdateUpstreamRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    let dns_resolver = state
        .app_ctx
        .get::<DnsResolver>()
        .ok_or_else(|| ApiError::Internal("DnsResolver not found".into()))?;

    // Cleanup old files before processing new ones to ensure clean state
    cleanup_upstream_files(&req.name).await;

    // Process certificates
    if let Err(e) = process_upstream_certs(&mut req.upstream).await {
        // Cleanup on validation failure
        cleanup_upstream_files(&req.name).await;
        return Err(ApiError::BadRequest(e));
    }

    upstream_manager
        .update_upstream(&req.name, req.upstream, dns_resolver)
        .await
        .map_err(|e| {
            let name_for_cleanup = req.name.clone();
            tokio::spawn(async move {
                cleanup_upstream_files(&name_for_cleanup).await;
            });
            ApiError::BadRequest(e.to_string())
        })?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Upstream updated successfully".into(),
    }))
}

#[utoipa::path(
    post,
    path = "/upstreams/remove",
    tag = "upstreams",
    request_body = RemoveUpstreamRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Remove upstream", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn remove_upstream(
    State(state): State<ApiState>,
    Json(req): Json<RemoveUpstreamRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    upstream_manager
        .remove_upstream(&req.name)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Cleanup files after successful removal from manager
    cleanup_upstream_files(&req.name).await;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Upstream removed successfully".into(),
    }))
}

// Service handlers
#[utoipa::path(
    get,
    path = "/services/list",
    tag = "services",
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "List all services", body = ServiceListResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn list_services(
    State(state): State<ApiState>,
) -> Result<Json<ServiceListResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    let services = service_manager
        .list_services()
        .into_iter()
        .map(ServiceInfo::from)
        .collect();

    Ok(Json(ServiceListResponse { services }))
}

#[utoipa::path(
    post,
    path = "/services/verify",
    tag = "services",
    request_body = VerifyServiceRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Verify service existence", body = VerifyResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn verify_service(
    State(state): State<ApiState>,
    Json(req): Json<VerifyServiceRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    let exists = service_manager.verify_service(&req.name);
    Ok(Json(VerifyResponse { exists }))
}

#[utoipa::path(
    post,
    path = "/services/add",
    tag = "services",
    request_body = AddServiceRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Add new service", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn add_service(
    State(state): State<ApiState>,
    Json(req): Json<AddServiceRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    service_manager
        .add_service(req.service)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Service added successfully".into(),
    }))
}

#[utoipa::path(
    post,
    path = "/services/update",
    tag = "services",
    request_body = UpdateServiceRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Update existing service", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn update_service(
    State(state): State<ApiState>,
    Json(req): Json<UpdateServiceRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    service_manager
        .update_service(&req.name, req.service)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Service updated successfully".into(),
    }))
}

#[utoipa::path(
    post,
    path = "/services/remove",
    tag = "services",
    request_body = RemoveServiceRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Remove service", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn remove_service(
    State(state): State<ApiState>,
    Json(req): Json<RemoveServiceRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    service_manager
        .remove_service(&req.name)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Service removed successfully".into(),
    }))
}

// Error handling
#[derive(Debug)]
enum ApiError {
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(ErrorResponse {
            success: false,
            error: error_message,
        });

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{PeerOptions, Upstream, UpstreamServer};

    #[tokio::test]
    async fn test_validate_pem() {
        // Generate a real cert for valid case
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let valid_pem = cert.cert.pem();

        let invalid_pem = "Just some text";

        assert!(validate_pem(&valid_pem));
        assert!(!validate_pem(invalid_pem));
    }

    #[tokio::test]
    async fn test_file_handling_flow() {
        let upstream_name = "test_upstream_xyz";
        let fake_cert = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----";
        // Note: save_cert_to_file doesn't validate, only validate_pem does.
        // So we can use fake_cert here for file I/O test.

        // 1. Clean start
        cleanup_upstream_files(upstream_name).await;

        // 2. Save file
        let res = save_cert_to_file(upstream_name, "test.crt", fake_cert).await;
        assert!(res.is_ok());
        let path = res.unwrap();
        assert!(PathBuf::from(&path).exists());

        // 3. Verify content
        // For verify, strict async usage isn't forced since std::fs works for test verifies,
        // but let's stick to std::fs for read to ensure bytes are on disk.
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, fake_cert);

        // 4. Cleanup
        cleanup_upstream_files(upstream_name).await;
        assert!(!PathBuf::from(&path).exists());
    }

    #[tokio::test]
    async fn test_process_upstream_certs() {
        let upstream_name = "test_integration_upstream";
        cleanup_upstream_files(upstream_name).await;

        // Generate a real cert to pass validate_pem
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let valid_pem = cert.cert.pem();

        let mut upstream = Upstream {
            name: upstream_name.to_string(),
            peer_options: Some(PeerOptions {
                cacert: Some(valid_pem.clone()),
                ..Default::default()
            }),
            servers: vec![UpstreamServer {
                host: "127.0.0.1".to_string(),
                weight: None,
                tls: None,
                peer_options: Some(PeerOptions {
                    client_key: Some(valid_pem.clone()), // Use cert as key just for PEM validation pass
                    ..Default::default()
                }),
            }],
            health_check: None,
            update_frequency: None,
        };

        // Run processing
        let res = process_upstream_certs(&mut upstream).await;
        if let Err(ref e) = res {
            println!("Process failed: {}", e);
        }
        assert!(res.is_ok());

        // Verify top-level
        let cacert_path = upstream
            .peer_options
            .as_ref()
            .unwrap()
            .cacert
            .as_ref()
            .unwrap();
        assert!(cacert_path.contains("root_cacert.pem"));
        assert!(PathBuf::from(cacert_path).exists());

        // Verify server-level
        let key_path = upstream.servers[0]
            .peer_options
            .as_ref()
            .unwrap()
            .client_key
            .as_ref()
            .unwrap();
        assert!(key_path.contains("server_0_client.key"));
        assert!(PathBuf::from(key_path).exists());

        // Cleanup
        cleanup_upstream_files(upstream_name).await;
    }
}
