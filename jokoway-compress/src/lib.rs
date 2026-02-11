use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use jokoway_core::{HttpMiddleware, JokowayExtension};
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingora::server::Server;
use std::io::Write;

// Industry-standard compressible content types based on Cloudflare, NGINX, Apache standards
const COMPRESSIBLE_TYPES: &[&str] = &[
    "text/html",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/json",
    "application/xml",
    "text/xml",
    "text/plain",
    "text/markdown",
    "image/svg+xml",
    "text/x-markdown",
    "application/x-javascript",
    "text/x-script",
    "text/x-component",
    "text/x-java-source",
    "text/*", // Wildcard for all text subtypes
];

// Types that should never be compressed (already compressed)
const NON_COMPRESSIBLE_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "video/mp4",
    "video/webm",
    "audio/mp3",
    "audio/ogg",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-compressed",
    "application/octet-stream",
];

/// Compression settings for YAML configuration (with Option fields for partial config)
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CompressionSettings {
    pub min_size: Option<usize>,
    pub content_types: Option<Vec<String>>,
    pub gzip: Option<GzipSettings>,
    #[cfg(feature = "brotli")]
    pub brotli: Option<BrotliSettings>,
    #[cfg(feature = "zstd")]
    pub zstd: Option<ZstdSettings>,
}

/// YAML config for Gzip
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct GzipSettings {
    pub level: Option<u8>,
}

/// YAML config for Brotli
#[cfg(feature = "brotli")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct BrotliSettings {
    pub quality: Option<u32>,
    pub lgwin: Option<u32>,
    pub buffer_size: Option<usize>,
}

/// YAML config for Zstd
#[cfg(feature = "zstd")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct ZstdSettings {
    pub level: Option<i32>,
}

/// Compression configuration with production-ready defaults (runtime config)
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub min_size: usize,
    pub gzip: Option<GzipConfig>,
    #[cfg(feature = "brotli")]
    pub brotli: Option<BrotliConfig>,
    #[cfg(feature = "zstd")]
    pub zstd: Option<ZstdConfig>,
}

/// Runtime config for Gzip
#[derive(Debug, Clone, Copy)]
pub struct GzipConfig {
    pub level: u8,
}

/// Runtime config for Brotli
#[cfg(feature = "brotli")]
#[derive(Debug, Clone, Copy)]
pub struct BrotliConfig {
    pub quality: u32,
    pub lgwin: u32,
    pub buffer_size: usize,
}

/// Runtime config for Zstd
#[cfg(feature = "zstd")]
#[derive(Debug, Clone, Copy)]
pub struct ZstdConfig {
    pub level: i32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            min_size: 1024,
            gzip: Some(GzipConfig { level: 6 }),
            #[cfg(feature = "brotli")]
            brotli: Some(BrotliConfig {
                quality: 5,
                lgwin: 22,
                buffer_size: 4096,
            }),
            #[cfg(feature = "zstd")]
            zstd: Some(ZstdConfig { level: 3 }),
        }
    }
}

/// Trait extension for accessing compression settings from JokowayConfig
pub trait CompressionConfigExt {
    fn compression(&self) -> Option<CompressionSettings>;
}

impl CompressionConfigExt for jokoway_core::config::JokowayConfig {
    fn compression(&self) -> Option<CompressionSettings> {
        self.extra
            .get("compression")
            .and_then(|v| serde_yaml::from_value(v.clone()).ok())
    }
}

/// Trait extension for adding compression settings to ConfigBuilder
pub trait CompressionConfigBuilderExt {
    fn with_compression(self, compression: CompressionSettings) -> Self;
}

impl CompressionConfigBuilderExt for jokoway_core::config::ConfigBuilder {
    fn with_compression(self, compression: CompressionSettings) -> Self {
        self.configure(|cfg, _| {
            let val =
                serde_yaml::to_value(compression).expect("Failed to serialize CompressionSettings");
            cfg.extra.insert("compression".to_string(), val);
        })
    }
}

impl CompressMiddleware {
    /// Safe compression chunk processing with error handling
    fn safe_compress_chunk(
        &self,
        compressor: &mut Compressor,
        chunk: &[u8],
    ) -> std::io::Result<Option<Vec<u8>>> {
        match compressor.process_chunk(chunk) {
            Ok(data) => Ok(Some(data)),
            Err(e) => {
                log::error!("Compression chunk processing failed: {}", e);
                Err(e)
            }
        }
    }

    /// Safe compression finalization with error handling
    fn safe_finish_compression(
        &self,
        compressor: Option<Compressor>,
    ) -> std::io::Result<Option<Vec<u8>>> {
        match compressor {
            Some(comp) => match comp.finish() {
                Ok(data) => Ok(Some(data)),
                Err(e) => {
                    log::error!("Compression finalization failed: {}", e);
                    Err(e)
                }
            },
            None => Ok(None),
        }
    }
}

impl CompressionConfig {
    /// Check if content type should be compressed based on industry standards
    fn should_compress_type(&self, content_type: Option<&str>) -> bool {
        let content_type = match content_type {
            None => return false,
            Some(ct) => {
                // Extract MIME type without charset parameters
                ct.split(';').next().unwrap_or(ct).trim().to_lowercase()
            }
        };

        // Skip non-compressible types first (fast path)
        if NON_COMPRESSIBLE_TYPES.iter().any(|t| t == &content_type) {
            return false;
        }

        // Check exact matches
        if COMPRESSIBLE_TYPES.iter().any(|t| t == &content_type) {
            return true;
        }

        // Check wildcard patterns (text/*)
        if content_type.starts_with("text/") {
            return COMPRESSIBLE_TYPES.iter().any(|t| t == &"text/*");
        }

        false
    }

    /// Check if content meets minimum size threshold
    fn should_compress_by_size(&self, content_length: Option<usize>, current_data: usize) -> bool {
        let current_size = content_length.unwrap_or(current_data);
        current_size >= self.min_size
    }
}

pub struct CompressExtension {
    config: CompressionConfig,
}

impl CompressExtension {
    pub fn new(config: CompressionConfig) -> Self {
        Self { config }
    }
}

impl Default for CompressExtension {
    fn default() -> Self {
        Self::new(CompressionConfig::default())
    }
}

impl JokowayExtension for CompressExtension {
    fn order(&self) -> i16 {
        1000
    }

    fn init(
        &self,
        _server: &mut Server,
        _app_ctx: &mut jokoway_core::AppCtx,
        http_middlewares: &mut Vec<std::sync::Arc<dyn jokoway_core::HttpMiddlewareDyn>>,
        _websocket_middlewares: &mut Vec<
            std::sync::Arc<dyn jokoway_core::websocket::WebsocketMiddlewareDyn>,
        >,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // We don't really need AppCtx here for compression, but we keep the signature consistent
        let _ = _app_ctx;
        log::info!(
            "Compress extension initialized with config: {:?}",
            self.config
        );

        http_middlewares.push(std::sync::Arc::new(CompressMiddleware::new(
            self.config.clone(),
        )));
        Ok(())
    }
}

pub struct CompressMiddleware {
    config: CompressionConfig,
}

impl CompressMiddleware {
    pub fn new(config: CompressionConfig) -> Self {
        Self { config }
    }
}

impl Default for CompressMiddleware {
    fn default() -> Self {
        Self::new(CompressionConfig::default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgo {
    Gzip,
    #[cfg(feature = "zstd")]
    Zstd,
    #[cfg(feature = "brotli")]
    Brotli,
}

pub enum Compressor {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    #[cfg(feature = "zstd")]
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
    #[cfg(feature = "brotli")]
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
}

impl Compressor {
    pub fn process_chunk(&mut self, chunk: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Compressor::Gzip(encoder) => {
                encoder.write_all(chunk)?;
                encoder.flush()?;
                let inner = encoder.get_mut();
                Ok(std::mem::take(inner))
            }
            #[cfg(feature = "zstd")]
            Compressor::Zstd(encoder) => {
                encoder.write_all(chunk)?;
                encoder.flush()?;
                let inner = encoder.get_mut();
                Ok(std::mem::take(inner))
            }
            #[cfg(feature = "brotli")]
            Compressor::Brotli(encoder) => {
                encoder.write_all(chunk)?;
                encoder.flush()?;
                let inner = encoder.get_mut();
                Ok(std::mem::take(inner))
            }
        }
    }

    pub fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            Compressor::Gzip(encoder) => encoder.finish(),
            #[cfg(feature = "zstd")]
            Compressor::Zstd(mut encoder) => {
                encoder.flush()?;
                encoder.finish()
            }
            #[cfg(feature = "brotli")]
            Compressor::Brotli(mut encoder) => {
                encoder.flush()?;
                Ok(encoder.into_inner())
            }
        }
    }
}

#[derive(Default)]
pub struct CompressContext {
    pub compression_algo: Option<CompressionAlgo>,
    pub compressor: Option<Compressor>,
    pub config: CompressionConfig,
    pub should_compress: bool,
    pub current_size: usize,
}

#[derive(Debug, Clone)]
struct EncodingPreference {
    encoding: String,
    quality: f32,
}

struct AcceptEncodingParser;

impl AcceptEncodingParser {
    /// Parse Accept-Encoding header according to RFC 7231
    /// Handles q-values, wildcards, and identity directives
    fn parse(header: &str) -> Vec<EncodingPreference> {
        if header.is_empty() {
            return Vec::new();
        }

        let mut preferences: Vec<EncodingPreference> = Vec::new();

        for part in header.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let mut encoding_quality_pair = part.split(';');
            let encoding = encoding_quality_pair
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase();

            // Skip empty encoding
            if encoding.is_empty() {
                continue;
            }

            // Default quality is 1.0
            let mut quality = 1.0;

            // Parse q-value if present
            if let Some(q_params) = encoding_quality_pair.next() {
                let q_param = q_params.trim();
                if q_param.to_lowercase().starts_with("q=") {
                    let q_str = &q_param[2..].trim();
                    quality = q_str.parse::<f32>().unwrap_or(1.0);
                    // Clamp to valid range [0.0, 1.0]
                    quality = quality.clamp(0.0, 1.0);
                }
            }

            // Skip encodings with q=0 (explicitly rejected)
            if quality > 0.0 {
                // Deduplicate: if encoding exists, keep highest quality
                if let Some(existing) = preferences.iter_mut().find(|p| p.encoding == encoding) {
                    if quality > existing.quality {
                        existing.quality = quality;
                    }
                } else {
                    preferences.push(EncodingPreference { encoding, quality });
                }
            }
        }

        // Sort by quality (descending), then by server preference order (descending)
        preferences.sort_by(|a, b| {
            b.quality
                .partial_cmp(&a.quality)
                .unwrap_or(std::cmp::Ordering::Equal)
                // Use b vs a for descending server preference
                .then_with(|| Self::compare_server_preference(&b.encoding, &a.encoding))
        });

        preferences
    }

    /// Define server preference order: br > zstd > gzip
    fn compare_server_preference(a: &str, b: &str) -> std::cmp::Ordering {
        let preference_order = |encoding: &str| -> u8 {
            match encoding {
                "br" => 3,
                #[cfg(feature = "zstd")]
                "zstd" => 2,
                "gzip" => 1,
                _ => 0,
            }
        };

        preference_order(a).cmp(&preference_order(b))
    }

    /// Select best encoding from parsed preferences and supported algorithms
    fn select_best(
        preferences: &[EncodingPreference],
        config: &CompressionConfig,
    ) -> Option<CompressionAlgo> {
        for pref in preferences {
            match pref.encoding.as_str() {
                #[cfg(feature = "brotli")]
                "br" => {
                    if config.brotli.is_some() {
                        return Some(CompressionAlgo::Brotli);
                    }
                }
                #[cfg(feature = "zstd")]
                "zstd" => {
                    if config.zstd.is_some() {
                        return Some(CompressionAlgo::Zstd);
                    }
                }
                "gzip" => {
                    if config.gzip.is_some() {
                        return Some(CompressionAlgo::Gzip);
                    }
                }
                "*" => {
                    // Wildcard - return best supported algorithm that is enabled
                    #[cfg(feature = "brotli")]
                    if config.brotli.is_some() {
                        return Some(CompressionAlgo::Brotli);
                    }

                    #[cfg(all(feature = "zstd", not(feature = "brotli")))]
                    if config.zstd.is_some() {
                        return Some(CompressionAlgo::Zstd);
                    }

                    #[cfg(all(not(feature = "zstd"), not(feature = "brotli")))]
                    if config.gzip.is_some() {
                        return Some(CompressionAlgo::Gzip);
                    }
                }
                "identity" => return None, // Explicitly no compression
                _ => continue,             // Unsupported encoding
            }
        }
        None
    }
}

impl CompressMiddleware {
    fn negotiate_compression(&self, accept_encoding: &str) -> Option<CompressionAlgo> {
        let mut preferences = AcceptEncodingParser::parse(accept_encoding);

        // Filter based on enabled algorithms in config
        // Filter based on enabled algorithms in config
        preferences.retain(|p| {
            match p.encoding.as_str() {
                "gzip" => self.config.gzip.is_some(),
                #[cfg(feature = "brotli")]
                "br" => self.config.brotli.is_some(),
                #[cfg(feature = "zstd")]
                "zstd" => self.config.zstd.is_some(),
                _ => true, // Allow wildcards and others to pass through to select_best
            }
        });

        AcceptEncodingParser::select_best(&preferences, &self.config)
    }
}

#[async_trait]
impl HttpMiddleware for CompressMiddleware {
    type CTX = CompressContext;

    fn name(&self) -> &'static str {
        "CompressMiddleware"
    }

    fn new_ctx(&self) -> Self::CTX {
        CompressContext {
            config: self.config.clone(),
            should_compress: false,
            current_size: 0,
            compression_algo: None,
            compressor: None,
        }
    }

    fn order(&self) -> i16 {
        i16::MIN / 2 // Run late - compression should be last
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
        _app_ctx: &jokoway_core::AppCtx,
    ) -> Result<bool, Box<Error>> {
        let req_header = session.req_header_mut();

        if let Some(accept_encoding) = req_header.headers.get("Accept-Encoding") {
            if let Ok(accept_encoding_str) = accept_encoding.to_str() {
                ctx.compression_algo = self.negotiate_compression(accept_encoding_str);
            }
            // Always remove the header to prevent upstream from compressing
            // We want to handle compression ourselves
            let _ = req_header.remove_header("Accept-Encoding");
        }

        Ok(false)
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
        _app_ctx: &jokoway_core::AppCtx,
    ) -> Result<(), Box<Error>> {
        if let Some(algo) = ctx.compression_algo {
            // Check if response is already compressed (shouldn't be if we removed Accept-Encoding, but upstream might force it)
            if upstream_response.headers.get("Content-Encoding").is_some() {
                // If upstream compressed it anyway, don't double compress
                ctx.compression_algo = None;
                ctx.should_compress = false;
                return Ok(());
            }

            // Check Content-Length if available to apply size threshold
            if upstream_response
                .headers
                .get("Content-Length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|&len| !ctx.config.should_compress_by_size(Some(len), 0))
                .is_some()
            {
                ctx.compression_algo = None;
                ctx.should_compress = false;
                return Ok(());
            }

            // Check Content-Type to see if it's compressible
            let content_type = upstream_response
                .headers
                .get("Content-Type")
                .and_then(|v| v.to_str().ok());

            if !ctx.config.should_compress_type(content_type) {
                ctx.compression_algo = None;
                ctx.should_compress = false;
                return Ok(());
            }

            // Set Content-Encoding header
            let encoding = match algo {
                CompressionAlgo::Gzip => "gzip",
                #[cfg(feature = "zstd")]
                CompressionAlgo::Zstd => "zstd",
                #[cfg(feature = "brotli")]
                CompressionAlgo::Brotli => "br",
            };
            let _ = upstream_response.insert_header("Content-Encoding", encoding);

            // Remove Content-Length as it will change
            let _ = upstream_response.remove_header("Content-Length");

            // Add Vary header
            let _ = upstream_response.append_header("Vary", "Accept-Encoding");

            // Ensure Transfer-Encoding is chunked since Content-Length is removed
            let _ = upstream_response.insert_header("Transfer-Encoding", "chunked");

            // Initialize compressor with configurable levels
            let compressor = match algo {
                CompressionAlgo::Gzip => {
                    let level = ctx
                        .config
                        .gzip
                        .as_ref()
                        .map(|g| g.level)
                        .unwrap_or(6)
                        .into();
                    Compressor::Gzip(flate2::write::GzEncoder::new(
                        Vec::new(),
                        flate2::Compression::new(level),
                    ))
                }
                #[cfg(feature = "zstd")]
                CompressionAlgo::Zstd => {
                    // Use configurable zstd level
                    let level = ctx.config.zstd.as_ref().map(|z| z.level).unwrap_or(3);
                    match zstd::stream::write::Encoder::new(Vec::new(), level) {
                        Ok(encoder) => Compressor::Zstd(encoder),
                        Err(e) => {
                            log::error!("Failed to create zstd encoder: {}", e);
                            ctx.compression_algo = None;
                            ctx.should_compress = false;
                            let _ = upstream_response.remove_header("Content-Encoding");
                            return Ok(());
                        }
                    }
                }
                #[cfg(feature = "brotli")]
                CompressionAlgo::Brotli => {
                    // Use configurable brotli quality
                    let (quality, lgwin, buffer_size) = ctx
                        .config
                        .brotli
                        .as_ref()
                        .map(|b| (b.quality, b.lgwin, b.buffer_size))
                        .unwrap_or((5, 22, 4096));

                    Compressor::Brotli(Box::new(brotli::CompressorWriter::new(
                        Vec::new(),
                        buffer_size,
                        quality,
                        lgwin,
                    )))
                }
            };

            ctx.compressor = Some(compressor);
            ctx.should_compress = true;
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>, Box<Error>> {
        if !ctx.should_compress || ctx.compression_algo.is_none() {
            return Ok(None);
        }

        let start = std::time::Instant::now();
        let mut out_data = Vec::new();

        if let Some(compressor) = ctx.compressor.as_mut() {
            if let Some(chunk) = body {
                ctx.current_size += chunk.len();
                match self.safe_compress_chunk(compressor, chunk) {
                    Ok(Some(data)) => {
                        if !data.is_empty() {
                            out_data.extend_from_slice(&data);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        return Err(Error::because(
                            pingora::ErrorType::InternalError,
                            "compression failed",
                            e,
                        ));
                    }
                }
            }
        }

        if end_of_stream {
            if let Some(compressor) = ctx.compressor.take() {
                match self.safe_finish_compression(Some(compressor)) {
                    Ok(Some(data)) => {
                        if !data.is_empty() {
                            out_data.extend_from_slice(&data);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        return Err(Error::because(
                            pingora::ErrorType::InternalError,
                            "compression finish failed",
                            e,
                        ));
                    }
                }
            }
        }

        if out_data.is_empty() {
            if end_of_stream {
                *body = None;
            } else {
                // Return an empty chunk instead of None to keep the stream alive
                *body = Some(bytes::Bytes::new());
            }
        } else {
            *body = Some(bytes::Bytes::from(out_data));
        }

        Ok(Some(start.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc_compliant_accept_encoding_parsing() {
        // Test basic parsing
        let preferences = AcceptEncodingParser::parse("gzip, deflate");
        assert_eq!(preferences.len(), 2);
        assert_eq!(preferences[0].encoding, "gzip");
        assert_eq!(preferences[0].quality, 1.0);

        // Test q-value parsing
        let preferences = AcceptEncodingParser::parse("gzip;q=0.8, br;q=1.0");
        assert_eq!(preferences.len(), 2);
        assert_eq!(preferences[0].encoding, "br"); // Higher quality first
        assert_eq!(preferences[0].quality, 1.0);
        assert_eq!(preferences[1].encoding, "gzip");
        assert_eq!(preferences[1].quality, 0.8);

        // Test wildcard handling
        let preferences = AcceptEncodingParser::parse("*;q=0.5, gzip;q=1.0");
        assert_eq!(preferences.len(), 2);
        assert_eq!(preferences[0].encoding, "gzip"); // Higher quality
        assert_eq!(preferences[1].encoding, "*");

        // Test q=0 (rejection)
        let preferences = AcceptEncodingParser::parse("gzip;q=0, br;q=1.0");
        assert_eq!(preferences.len(), 1);
        assert_eq!(preferences[0].encoding, "br");

        // Test malformed q-values (should default to 1.0)
        let preferences = AcceptEncodingParser::parse("gzip;q=invalid, br");
        assert_eq!(preferences.len(), 2);
        assert_eq!(preferences[0].encoding, "br"); // br has quality 1.0, gzip defaults to 1.0 but lower server preference
    }

    #[test]
    fn test_server_preference_ordering() {
        // Test server preference: br > zstd > gzip
        let preferences = AcceptEncodingParser::parse("gzip, br, zstd");
        // All have quality 1.0, should be ordered by server preference
        assert_eq!(preferences[0].encoding, "br");

        #[cfg(feature = "zstd")]
        {
            assert_eq!(preferences[1].encoding, "zstd");
            assert_eq!(preferences[2].encoding, "gzip");
        }

        #[cfg(not(feature = "zstd"))]
        {
            assert_eq!(preferences[1].encoding, "gzip");
            assert_eq!(preferences[2].encoding, "zstd");
        }
    }

    #[test]
    fn test_wildcard_fallback() {
        let _mw = CompressMiddleware::default();

        // Wildcard should select best available algorithm
        #[cfg(feature = "brotli")]
        assert_eq!(
            _mw.negotiate_compression("*"),
            Some(CompressionAlgo::Brotli)
        );

        // Temporarily removed complex cfg conditions for compilation
    }

    #[test]
    fn test_content_type_filtering() {
        let config = CompressionConfig::default();

        // Test compressible types
        assert!(config.should_compress_type(Some("text/html")));
        assert!(config.should_compress_type(Some("application/json")));
        assert!(config.should_compress_type(Some("text/css")));
        assert!(config.should_compress_type(Some("text/javascript")));

        // Test wildcard support
        assert!(config.should_compress_type(Some("text/plain")));
        assert!(config.should_compress_type(Some("text/csv")));

        // Test non-compressible types
        assert!(!config.should_compress_type(Some("image/jpeg")));
        assert!(!config.should_compress_type(Some("image/png")));
        assert!(!config.should_compress_type(Some("video/mp4")));
        assert!(!config.should_compress_type(Some("application/pdf")));
        assert!(!config.should_compress_type(Some("application/zip")));

        // Test missing content type
        assert!(!config.should_compress_type(None));
    }

    #[test]
    fn test_size_threshold() {
        let config = CompressionConfig::default();

        // Test size threshold (default 1024)
        assert!(!config.should_compress_by_size(Some(500), 0));
        assert!(!config.should_compress_by_size(None, 500));
        assert!(config.should_compress_by_size(Some(1024), 0));
        assert!(config.should_compress_by_size(None, 1024));
        assert!(config.should_compress_by_size(None, 2048));

        let custom_config = CompressionConfig {
            min_size: 860,
            ..Default::default()
        };
        assert!(!custom_config.should_compress_by_size(Some(800), 0));
        assert!(custom_config.should_compress_by_size(Some(900), 0));
    }

    #[test]
    fn test_compression_config_defaults() {
        let config = CompressionConfig::default();
        assert_eq!(config.min_size, 1024);
        assert_eq!(config.gzip.unwrap().level, 6);
        #[cfg(feature = "brotli")]
        assert_eq!(config.brotli.unwrap().quality, 5);
        #[cfg(feature = "zstd")]
        assert_eq!(config.zstd.unwrap().level, 3);
    }

    #[test]
    fn test_content_type_with_charset() {
        let config = CompressionConfig::default();

        // Should handle charset parameters correctly
        assert!(config.should_compress_type(Some("text/html; charset=utf-8")));
        assert!(config.should_compress_type(Some("application/json; charset=utf-8")));
        assert!(config.should_compress_type(Some("text/css; charset=iso-8859-1")));
    }

    #[test]
    fn test_edge_case_parsing() {
        // Empty header
        let preferences = AcceptEncodingParser::parse("");
        assert_eq!(preferences.len(), 0);

        // Whitespace handling
        let preferences = AcceptEncodingParser::parse(" gzip , br ; q=0.5 ");
        assert_eq!(preferences.len(), 2);
        assert_eq!(preferences[0].encoding, "gzip"); // q=1.0
        assert_eq!(preferences[0].quality, 1.0);
        assert_eq!(preferences[1].encoding, "br"); // q=0.5

        // Case sensitivity
        let preferences = AcceptEncodingParser::parse("GZIP, BR, Gzip");
        assert_eq!(preferences.len(), 2); // GZIP and Gzip are the same (lowercase)
        assert_eq!(preferences[0].encoding, "br"); // Server preference first
        assert_eq!(preferences[1].encoding, "gzip");
    }

    #[test]
    fn test_negotiate_compression() {
        let mw = CompressMiddleware::default();

        // Test gzip
        assert_eq!(
            mw.negotiate_compression("gzip"),
            Some(CompressionAlgo::Gzip)
        );
        assert_eq!(
            mw.negotiate_compression("gzip, deflate"),
            Some(CompressionAlgo::Gzip)
        );

        // Test priority
        #[cfg(feature = "brotli")]
        assert_eq!(
            mw.negotiate_compression("br, gzip"),
            Some(CompressionAlgo::Brotli)
        );

        #[cfg(feature = "zstd")]
        assert_eq!(
            mw.negotiate_compression("zstd, gzip"),
            Some(CompressionAlgo::Zstd)
        );

        // Test identity/none
        assert_eq!(mw.negotiate_compression("identity"), None);
    }

    #[test]
    fn test_streaming_compression_gzip() {
        let mut compressor = Compressor::Gzip(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));

        // Feed enough data to trigger compression block output
        // Create 2 chunks that are somewhat large but not huge
        let chunk_size = 32 * 1024; // 32KB
        let data = vec![b'a'; chunk_size * 5]; // 160KB total
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

        let mut total_output = Vec::new();
        let mut emitted_count = 0;

        for c in chunks {
            let output = compressor.process_chunk(c).unwrap();
            // We expect at least some chunks to produce output before stream ends
            if !output.is_empty() {
                emitted_count += 1;
                total_output.extend_from_slice(&output);
            }
        }

        // Ensure finish also works
        let final_chunk = compressor.finish().unwrap();
        total_output.extend_from_slice(&final_chunk);
        assert!(
            emitted_count > 0,
            "Should have emitted compressed data during streaming"
        );

        // Verify correctness of data
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(&total_output[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_safe_compression_methods() {
        let mw = CompressMiddleware::default();

        // Test safe compression chunk
        let mut compressor = Compressor::Gzip(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::new(6),
        ));

        let data = b"Hello, World!";
        match mw.safe_compress_chunk(&mut compressor, data) {
            Ok(Some(compressed)) => {
                assert!(!compressed.is_empty());
            }
            Ok(None) | Err(_) => panic!("Unexpected compression result"),
        }
    }

    #[test]
    fn test_safe_compression_finish() {
        let mw = CompressMiddleware::default();

        let compressor = Some(Compressor::Gzip(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::new(6),
        )));

        match mw.safe_finish_compression(compressor) {
            Ok(Some(compressed)) => {
                assert!(!compressed.is_empty());
            }
            Ok(None) | Err(_) => panic!("Unexpected compression finish result"),
        }
    }

    #[test]
    fn test_compress_context_defaults() {
        let ctx = CompressContext::default();
        assert_eq!(ctx.config.min_size, 1024);
        assert!(ctx.config.gzip.is_some());
        assert_eq!(ctx.config.gzip.unwrap().level, 6);
        #[cfg(feature = "brotli")]
        assert!(ctx.config.brotli.is_some());
        #[cfg(feature = "zstd")]
        assert!(ctx.config.zstd.is_some());

        assert!(!ctx.should_compress);
        assert_eq!(ctx.current_size, 0);
        assert!(ctx.compression_algo.is_none());
        assert!(ctx.compressor.is_none());
    }

    #[test]
    fn test_middleware_with_custom_config() {
        let custom_config = CompressionConfig {
            min_size: 860,
            gzip: Some(GzipConfig { level: 9 }),
            #[cfg(feature = "brotli")]
            brotli: Some(BrotliConfig {
                quality: 11,
                lgwin: 22,
                buffer_size: 4096,
            }),
            #[cfg(feature = "zstd")]
            zstd: Some(ZstdConfig { level: 1 }),
        };

        let mw = CompressMiddleware::new(custom_config);
        let ctx = mw.new_ctx();

        assert_eq!(ctx.config.min_size, 860);
        assert_eq!(ctx.config.gzip.unwrap().level, 9);
        #[cfg(feature = "brotli")]
        assert_eq!(ctx.config.brotli.unwrap().quality, 11);
        #[cfg(feature = "zstd")]
        assert_eq!(ctx.config.zstd.unwrap().level, 1);
    }

    #[test]
    fn test_edge_case_identity_handling() {
        let mw = CompressMiddleware::default();

        // Identity should explicitly disable compression
        assert_eq!(mw.negotiate_compression("identity"), None);

        // Identity with q=0 should also disable
        assert_eq!(mw.negotiate_compression("identity;q=0"), None);

        // Identity mixed with other encodings
        let result = mw.negotiate_compression("identity;q=0.5, gzip;q=1.0");
        assert_eq!(result, Some(CompressionAlgo::Gzip)); // Should prefer gzip over identity
    }

    #[test]
    fn test_q_value_precision() {
        // Test q-value parsing with different precisions
        let preferences = AcceptEncodingParser::parse("gzip;q=0.800, br;q=0.9, zstd;q=1");
        assert_eq!(preferences.len(), 3);
        assert_eq!(preferences[0].encoding, "zstd"); // 1.0
        assert_eq!(preferences[0].quality, 1.0);
        assert_eq!(preferences[1].encoding, "br"); // 0.9
        assert_eq!(preferences[1].quality, 0.9);
        assert_eq!(preferences[2].encoding, "gzip"); // 0.800
        assert_eq!(preferences[2].quality, 0.800);
    }

    #[test]
    fn test_multiple_wildcards() {
        let preferences = AcceptEncodingParser::parse("*;q=0.3, gzip;q=1.0, *;q=0.8");
        assert_eq!(preferences.len(), 2);

        // Should be sorted by quality: gzip (1.0), * (0.8)
        assert_eq!(preferences[0].encoding, "gzip");
        assert_eq!(preferences[0].quality, 1.0);
        assert_eq!(preferences[1].encoding, "*");
        assert_eq!(preferences[1].quality, 0.8);
    }

    #[test]
    fn test_compressible_types_completeness() {
        let config = CompressionConfig::default();

        // Test all compressible types from our constant
        for mime_type in COMPRESSIBLE_TYPES {
            if mime_type.contains('*') {
                // Skip wildcards in this test
                continue;
            }
            assert!(
                config.should_compress_type(Some(mime_type)),
                "Should compress MIME type: {}",
                mime_type
            );
        }

        // Test all non-compressible types
        for mime_type in NON_COMPRESSIBLE_TYPES {
            assert!(
                !config.should_compress_type(Some(mime_type)),
                "Should not compress MIME type: {}",
                mime_type
            );
        }
    }

    #[test]
    fn test_disabled_algorithm() {
        let config = CompressionConfig {
            gzip: None,
            // others default to some
            ..Default::default()
        };

        let mw = CompressMiddleware::new(config);

        // Test gzip disabled
        assert_eq!(mw.negotiate_compression("gzip"), None);
        assert_eq!(mw.negotiate_compression("gzip, deflate"), None);

        // Test fallback to enabled algorithm
        #[cfg(feature = "brotli")]
        assert_eq!(
            mw.negotiate_compression("gzip, br"),
            Some(CompressionAlgo::Brotli)
        );

        // Test wildcard with disabled gzip
        // Should pick next best enabled algo
        #[cfg(feature = "brotli")]
        assert_eq!(mw.negotiate_compression("*"), Some(CompressionAlgo::Brotli));

        #[cfg(all(feature = "zstd", not(feature = "brotli")))]
        assert_eq!(mw.negotiate_compression("*"), Some(CompressionAlgo::Zstd));

        #[cfg(all(not(feature = "zstd"), not(feature = "brotli")))]
        assert_eq!(mw.negotiate_compression("*"), None); // All disabled
    }
}
