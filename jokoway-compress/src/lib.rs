use async_trait::async_trait;

use jokoway_core::{HttpMiddleware, JokowayExtension};
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingora::server::Server;
use std::io::Write;

pub struct CompressExtension;

impl JokowayExtension for CompressExtension {
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
        log::info!("Compress extension initialized");
        http_middlewares.push(std::sync::Arc::new(CompressMiddleware));
        Ok(())
    }
}

pub struct CompressMiddleware;

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
                let inner = encoder.get_mut();
                if inner.is_empty() {
                    return Ok(Vec::new());
                }
                Ok(std::mem::take(inner))
            }
            #[cfg(feature = "zstd")]
            Compressor::Zstd(encoder) => {
                encoder.write_all(chunk)?;
                let inner = encoder.get_mut();
                if inner.is_empty() {
                    return Ok(Vec::new());
                }
                Ok(std::mem::take(inner))
            }
            #[cfg(feature = "brotli")]
            Compressor::Brotli(encoder) => {
                encoder.write_all(chunk)?;
                let inner = encoder.get_mut();
                if inner.is_empty() {
                    return Ok(Vec::new());
                }
                Ok(std::mem::take(inner))
            }
        }
    }

    pub fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            Compressor::Gzip(encoder) => encoder.finish(),
            #[cfg(feature = "zstd")]
            Compressor::Zstd(encoder) => encoder.finish(),
            #[cfg(feature = "brotli")]
            Compressor::Brotli(encoder) => Ok(encoder.into_inner()),
        }
    }
}

#[derive(Default)]
pub struct CompressContext {
    pub compression_algo: Option<CompressionAlgo>,
    pub compressor: Option<Compressor>,
}

impl CompressMiddleware {
    fn negotiate_compression(&self, accept_encoding: &str) -> Option<CompressionAlgo> {
        // Parse Accept-Encoding header
        // Simple parsing: split by comma, trim, check for algo
        // Priority: br > zstd > gzip

        let parts: Vec<&str> = accept_encoding.split(',').map(|s| s.trim()).collect();

        #[cfg(feature = "brotli")]
        if parts.iter().any(|s| s.eq_ignore_ascii_case("br")) {
            return Some(CompressionAlgo::Brotli);
        }

        #[cfg(feature = "zstd")]
        if parts.iter().any(|s| s.eq_ignore_ascii_case("zstd")) {
            return Some(CompressionAlgo::Zstd);
        }

        if parts.iter().any(|s| s.eq_ignore_ascii_case("gzip")) {
            return Some(CompressionAlgo::Gzip);
        }

        None
    }
}

#[async_trait]
impl HttpMiddleware for CompressMiddleware {
    type CTX = CompressContext;

    fn name(&self) -> &'static str {
        "CompressMiddleware"
    }

    fn new_ctx(&self) -> Self::CTX {
        CompressContext::default()
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

            // Initialize compressor
            // #[allow(unused_mut)]
            let compressor = match algo {
                CompressionAlgo::Gzip => Compressor::Gzip(flate2::write::GzEncoder::new(
                    Vec::new(),
                    flate2::Compression::default(),
                )),
                #[cfg(feature = "zstd")]
                CompressionAlgo::Zstd => {
                    // Level 3 is default for zstd
                    match zstd::stream::write::Encoder::new(Vec::new(), 3) {
                        Ok(encoder) => Compressor::Zstd(encoder),
                        Err(e) => {
                            log::error!("Failed to create zstd encoder: {}", e);
                            ctx.compression_algo = None;
                            let _ = upstream_response.remove_header("Content-Encoding");
                            return Ok(());
                        }
                    }
                }
                #[cfg(feature = "brotli")]
                CompressionAlgo::Brotli => {
                    // Buffer size 4096, quality 11, lgwin 22
                    Compressor::Brotli(Box::new(brotli::CompressorWriter::new(
                        Vec::new(),
                        4096,
                        11,
                        22,
                    )))
                }
            };

            ctx.compressor = Some(compressor);
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
        if ctx.compression_algo.is_none() {
            return Ok(None);
        }

        let start = std::time::Instant::now();

        if let Some(compressor) = ctx.compressor.as_mut() {
            if let Some(chunk) = body {
                match compressor.process_chunk(chunk) {
                    Ok(data) => {
                        if !data.is_empty() {
                            *body = Some(bytes::Bytes::from(data));
                        } else {
                            *body = None;
                        }
                    }
                    Err(e) => {
                        log::error!("Compression error: {}", e);
                        *body = None;
                    }
                }
            }

            if end_of_stream {
                let compressed_data = match ctx.compressor.take().unwrap().finish() {
                    Ok(data) => Some(data),
                    Err(e) => {
                        log::error!("Compression finish error: {}", e);
                        None
                    }
                };

                if let Some(data) = compressed_data {
                    *body = Some(bytes::Bytes::from(data));
                }
            }
        }

        Ok(Some(start.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_compression() {
        let mw = CompressMiddleware;

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
}
