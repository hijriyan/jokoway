# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### ⚙️  Miscellaneous

- Conditionally compile immediate certificate renewal for `pebble_tests` feature.
- Add cargo audit configuration
- Use `mozilla_intermediate_v5()` instead of `mozilla_intermediate()`

### ⛰️  Features

- Implement protocol-based service matching in the router to filter services by client protocol.
- Pass application context to all middleware methods.
- Add `jokoway-forwarded` extension to process forwarded headers and manage trusted proxies.
- Prioritize URI host over the Host header when determining the current host for forwarded header parsing.
- Integrate git-cliff for automated changelog and release notes generation.

### 🐛 Bug Fixes

- Clippy warnings
- Generate release notes job

### 📚 Documentation

- Update configuration details, new options for DNS, compression, SSL, and API.
- Convert a footnote to a regular paragraph in README.
- Switch jokoway service to host network mode (for testing forwarded middleware)
- Enable http_forwarded configuration in jokoway.yml.
- Update httpbin service port mapping, add jokoway dependency, and configure jokoway upstream to use 127.0.0.1 for httpbin.
- Update jokoway configuration and README

### 🔨 Refactor

- Reimplement router indexing and path matching using the `matchit` library.
- Streamline TLS cipher suite configuration and handling by unifying separate TLS 1.2 and 1.3 lists into a single vector of strings.
- Rename `AppCtx` to `Context` and `RouteContext` to `ProxyContext` for improved clarity.

- add new `shared_ctx` field to `ProxyContext`
- Unify HTTP and WebSocket middlewares into a single generic interface.
- Split context into global AppContext and per-request RequestContext, and update middleware signatures to use both.
- Optimize forwarded header parsing with `Arc<str>` for string fields, use `HeaderName` constants, and adjust extension order.
- Remove conditional early exit for middleware based on `settings.enabled`.
- Centralize X-Forwarded header constants in `models.rs` and update their usage in middleware and parser modules.
- Rename feature flags by removing the `-extension` suffix for consistency.
- Introduce structured prelude modules across crates for better import organization and clarity.
- Rename `SslSettings` to `TlsSettings` and remove `min_version`/`max_version` configuration options.
## [0.1.0-alpha.6] - 2026-02-20

### build

- Bump `jokoway-acme` and `jokoway-core` dependency versions to `0.1.0-alpha.3`.

### ⚙️  Miscellaneous

- Bump `jokoway` version to 0.1.0-alpha.2.
- Update jokoway-compress version to 0.1.0-alpha.2
- Bump project and Docker image versions to 0.1.0-alpha.3.
- Bump project versions to 0.1.0-alpha.4 and update dockerignore to exclude examples.
- Remove golang from Dockerfile build dependencies.
- Bump `jokoway`  to 0.1.0-alpha.6
- Just `build-push-image` on local machine

### ⛰️  Features

- Initial project setup for the jokoway API Gateway, including workspace configuration, license, readme, and basic crate structure.
- Implement initial Jokoway proxy server with core routing, transformation, and extension capabilities.
- Update example configuration to use httpbin upstreams, adjust listening ports.
- Refactor project into a multi-crate workspace and update extension/middleware handling.
- Switch load balancer selection from Weighted to RoundRobin, apply the full configured weight to each discovered IP, and refine load balancer error messages.
- Introduce configurable upstream update frequency and add a comprehensive health check integration test.
- Allow extensions to add, remove, and order HTTP and WebSocket middlewares during initialization.
- Enable HTTP/2 for HTTPS TLS settings
- Add Dockerfiles for Alpine and Distroless builds, and a .dockerignore file.
- Add OCI image labels to Dockerfiles.
- Add request filtering to websocket middlewares and integrate it into the proxy's request processing flow.
- Implement streaming compression by adding `process_chunk` and `finish` methods to `Compressor` and updating `CompressContext` to utilize them.
- Implement configurable HTTP compression middleware with Gzip, Brotli, and Zstd support, including content type and size-based rules.
- Add Justfile for image build automation and enhance Docker security by running containers as a non-root user.
- Add detailed installation, usage, and configuration instructions to the README.
- Add Crates.io and license badges, routing rules, and request/response transformers documentation to README.
- Add strict configuration validation
- Bump jokoway-acme version to 0.1.0-alpha.3.
- Add `#[serde(deny_unknown_fields)]` to various configuration structs and reformat an `if let` block.
- Add `update-dependent` command to justfile
- Bump `jokoway` to 0.1.0-alpha.5

- bump `jokoway-core` to 0.1.0-alpha.4
  - bump `jokoway-acme` to 0.1.0-alpha.4
  - bump `jokoway-compress` to 0.1.0-alpha.4
  - refine pingora dependency features
- Implement dynamic TLS Callback

- refactor `jokoway-acme` extension
  - include integration test for ACME using pebble
  - workspace dependency management.
- Switch ACME to production, update its storage path, and refactor the Docker volume for application data.
- Add GitHub Actions workflows for security auditing and comprehensive CI/CD, including testing, multi-platform releases, and Docker image builds.
- Add Rust build caching to CI and Dockerfile using rust-cache action and cargo-chef.
- Add `contents: read` and `checks: write` permissions to the audit workflow.
- Optimize CI builds with a new `ci` cargo profile, enhance Docker image metadata, and refactor router's request matching for improved efficiency and safety.

### 🐛 Bug Fixes

- Add 'vendored' feature to `utoipa-swagger-ui` and comment out SSL/ACME settings in `jokoway.yml`.
- Improve compression stream handling by adding explicit flushes, ensuring chunked transfer encoding, and enhancing test coverage for multiple algorithms.
- The DNS resolver must load the system configuration and route handling that is not available on the proxy.
- Test `test_load_from_file`
- `clippy` warnings
- Route rule definition in jokoway.yml httpbin
- Repeated DNS resolver initialization

- feat: Introduce UpstreamExtension
  - add a dynamic configuration example.

### 📚 Documentation

- Add comprehensive example configuration file for Jokoway with detailed settings for peers, SSL, ACME, API, DNS, upstreams, services, routing, and Pingora.
- Update config file path and example link in README usage instructions.
- Overhaul README to include expanded features, clearer installation steps, and a quick start guide.
- Add httpbin example with dedicated configuration, Docker Compose setup, and documentation, removing the old httpbin config file.
- Fix minimal configuration
- Add READMEs for ACME and Compress extensions and add `dep:jokoway-compress` to `compress-extension` feature
- Add httpbin deployment example using jokoway and Docker Compose, including configuration and instructions.

### 🔨 Refactor

- Remove Prometheus metrics integration, dependencies, configuration, and all related collection logic.
- Simplify curves string leaking and remove related comment
- Move ACME configuration models and logic to `jokoway-acme` and integrate with `jokoway-core`'s generic config system.
- Fix `clippy` warnings
- Consolidate route configuration by inlining `Rule` struct properties directly into the `Route` struct.
- Perform request transformer in `upstream_request_filter` and call new_ctx middleware in `early_request_filter`
- Remove unused `reload` function in ServiceManager
- Replace OpenSSL with BoringSSL across dependencies, tests, and Docker configurations, removing the Alpine Dockerfile.
- CA certificate handling
- Simplify `ok_or_else` usage and streamline ALPN protocol selection logic.
- Add dedicated `/opt/jokoway` directory.

### 🚀 Performance

- Optimize compression by using `bytes::Bytes` and `BytesMut` to reduce allocations and improve streaming performance.

### 🧪 Testing

- Add API integration tests for basic authentication, rate limiting, and CRUD operations for upstreams and services.
<!-- generated by git-cliff -->
