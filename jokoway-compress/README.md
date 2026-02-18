# Jokoway Compress Extension

HTTP compression middleware for Jokoway API Gateway, supporting Gzip, Brotli, and Zstd algorithms.

## Features

- **Multi-Algorithm Support**:
  - **Gzip**: Standard compression supported by all browsers.
  - **Brotli** (Optional): Higher compression ratio (requires `brotli` feature).
  - **Zstd** (Optional): High speed and ratio (requires `zstd` feature).
- **Smart Negotiation**: Automatically selects the best algorithm based on `Accept-Encoding` header and server preference (Brotli > Zstd > Gzip).
- **Intelligent Filtering**:
  - **Content-Type Whitelisting**: Compresses text-based formats (HTML, JSON, XML, CSS, JS, etc.) by default.
  - **Size Threshold**: Only compresses responses larger than a configurable limit (default: 1024 bytes).
  - **Already Compressed**: Automatically skips images, videos, and archives.

## Configuration

Add the compression configuration to your Jokoway YAML config in the `jokoway` section.

```yaml
jokoway:
  compression:
    min_size: 1024                # Minimum response size to compress (in bytes)
    content_types:                # Optional: Override default compressible types
        - "text/html"
        - "application/json"
    
    # Algorithm-specific settings
    gzip:
        level: 6                    # Compression level (1-9)
    
    brotli:                       # Requires 'brotli' feature
        quality: 5                  # Compression quality (0-11)
        lgwin: 22                   # Window size
        buffer_size: 4096 
    
    zstd:                         # Requires 'zstd' feature
        level: 3                    # Compression level
```

## Installation

It's already included in main crate `jokoway` via `compress-extension` feature.

## Defaults

- **Minimum Size**: 1024 bytes
- **Gzip Level**: 6
- **Brotli Quality**: 5
- **Zstd Level**: 3
- **Compressible Types**:
  - `text/*` (html, css, javascript, xml, plain, markdown, etc.)
  - `application/javascript`, `application/json`, `application/xml`
  - `image/svg+xml`
