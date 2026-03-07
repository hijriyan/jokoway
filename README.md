# jokoway

<p align="center">
  <img src="https://raw.githubusercontent.com/hijriyan/jokoway/refs/heads/main/images/jokoway-logo.png" width="100%" alt="jokoway logo">
</p>

<p align="center">
  <a href="https://crates.io/crates/jokoway"><img src="https://img.shields.io/crates/v/jokoway" alt="Crates.io Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

Jokoway is a high-performance API Gateway built on Pingora (Rust) with dead-simple YAML configs. Inspired by Traefik’s expressive routing rules and Kong’s DB-less declarative configuration model.

<p align="center">
  This project is actually for learning and experimenting with Rust.
</p>

<p align="center">
  ⚠️ If you want to try it, go ahead, and I really appreciate any feedback. ⚠️
</p>

## 🌟 Key Features

* **🚀 High Performance**: Built on Cloudflare's **Pingora** framework, providing extreme speed, reliability, and security in Rust.
* **🚦 Expressive Routing Rules**: Traefik-style matching (Host, Path, Method, Headers, Queries) with full Regex support and priority control.
* **📄 DB-less Declarative Configuration**: Manage your entire infrastructure via a simple, version-controllable YAML file.
* **🔄 Request & Response Transformation**: Modify headers, paths, query parameters, and methods on the fly for both requests and responses.
* **🔐 Let's Encrypt Support**: Built-in Let's Encrypt support with automated issuance and renewal (HTTP-01 and TLS-ALPN-01).
* **⚖️ Advanced Load Balancing**: Support for backend clusters with weighted round-robin, active health checks (HTTP/TCP), and connection pooling.
* **🗜️ HTTP Compression**: built-in Gzip, Brotli, and Zstandard compression.
* **🌐 WebSocket Transformations**: Allow you to modify websocket message via Websocket Middleware.
* **📊 Management API**: Allow you to manage upstreams and services via HTTP API.
* **🔌 Highly Extensible**: Extend core functionality with a clean Rust-based middleware and extension system.

## 🔧 Installation

Jokoway can be installed as a binary via Cargo, run as a container with Docker, or built from the source.

### 📦 Using Cargo (Recommended for Rust Users)

Install the latest version of Jokoway directly from [crates.io](https://crates.io/crates/jokoway):

```sh
cargo install jokoway
```

### 🐳 Using Docker

Pull the official image from GitHub Container Registry:

```sh
docker pull ghcr.io/hijriyan/jokoway:latest
```

### 🛠️ Building From Source

**Prerequisites:**

* [Rust & Cargo](https://rustup.rs/) (Stable)
* `cmake` and `perl` (Required by Pingora dependencies)

```sh
# Clone the repository
git clone --depth 1 https://github.com/hijriyan/jokoway.git
cd jokoway

# Build in release mode
cargo build --release

# The binary will be available at:
# ./target/release/jokoway
```

## 🔨 Usage

### 🚀 Quick Start

1. **Create a minimal configuration** (`config.yml`):

```yaml
jokoway:
  http_listen: "0.0.0.0:8080"

  upstreams:
    - name: my_backend
      servers:
        - host: "127.0.0.1:3000"

  services:
    - name: my_service
      host: my_backend
      protocols: ["http"]
      routes:
        - rule: PathPrefix(`/`)
```

1. **Run Jokoway**:

```sh
# Enable logging to see what's happening
export RUST_LOG=info
jokoway -c config.yml
```

2. **Verify**:

```sh
curl http://localhost:8080/
```

### 📖 Running with Different Methods

#### Using the installed binary

```sh
jokoway -c path/to/config.yml
```

#### Using Docker

Mount your local configuration directory to the container:

```sh
docker run -d \
    -p 2014:2014 \
    -e RUST_LOG=info \
    --name jokoway \
    -v $(pwd)/config:/etc/jokoway/config \
    ghcr.io/hijriyan/jokoway:latest \
    -c /etc/jokoway/config/my_config.yml
```

#### Test Configuration

Validate your configuration without starting the server:

```sh
jokoway -c config.yml -t
```

## 📝 Configuration Guide

Jokoway uses a declarative YAML configuration file, making it easy to version-control your infrastructure. The configuration is divided into two main domains: 
1. **`jokoway`**: The operational gateway settings (routing, upstreams, TLS).
2. **`pingora`**: The underlying server engine settings.

> [!TIP]
> You can find a [full example configuration here](./jokoway.yml) showcasing all available options.

---

### 🌐 Core Gateway Settings (`jokoway`)

This section defines the basic behavior and network interfaces for Jokoway.

```yaml
jokoway:
  http_listen: "0.0.0.0:8080" # (Required) Address/port for HTTP traffic
  https_listen: "0.0.0.0:8443" # (Optional) Address/port for HTTPS traffic (Requires SSL config)
  http_server_options:
    keepalive_request_limit: 100
    h2c: false
    allow_connect_method_proxying: false
```

#### 🛠️ HTTP Server Options

Fine-tune the behavior of Jokoway's internal HTTP server.

| Field | Default | Description |
| :--- | :---: | :--- |
| `keepalive_request_limit` | `null` *(Unlimited)* | Maximum number of requests allowed per keep-alive connection. |
| `h2c` | `false` | Enable HTTP/2 over cleartext (without TLS). Useful for gRPC or internal proxying. |
| `allow_connect_method_proxying` | `true` | Allow proxying CONNECT requests when handling HTTP traffic. |

#### 🔎 DNS Resolution

Configure how Jokoway resolves upstream hostnames. If this entire section is omitted, Jokoway falls back to the system resolver (`/etc/resolv.conf`).

```yaml
jokoway:
  dns:
    system_conf: true
    use_hosts_file: true
    nameservers:
      - "1.1.1.1"
      - "8.8.8.8"
    timeout: 5
    attempts: 3
    strategy: "ipv4_then_ipv6"
    cache_size: 1024
```

| Field | Default | Description |
| :--- | :---: | :--- |
| `system_conf` | `true` | Load nameservers from the system configuration (`/etc/resolv.conf`). When `true`, any entries in `nameservers` are **added** to the system ones. When `false`, only user-provided `nameservers` are used. |
| `use_hosts_file` | `true` | Read entries from the system hosts file (`/etc/hosts`), allowing local hostname overrides. |
| `nameservers` | — | List of custom DNS server IP addresses (e.g., `"1.1.1.1"`, `"8.8.8.8"`). |
| `timeout` | `5` | Maximum seconds to wait for a DNS response. |
| `attempts` | `2` | Number of retry attempts before giving up. |
| `strategy` | `"ipv4_then_ipv6"` | IP resolution strategy. Accepted values: `"ipv4_then_ipv6"`, `"ipv6_then_ipv4"`, `"ipv4_only"`, `"ipv6_only"`. |
| `cache_size` | `1024` | Number of DNS entries to keep in the in-memory cache. |

> [!TIP]
> In **Docker containers**, the system resolver (`/etc/resolv.conf`) automatically points to Docker's embedded DNS server (`127.0.0.11`), which can resolve service names (e.g., `"httpbin"`) to container IPs. So if `system_conf` is `true` (the default), Docker service discovery works out of the box — no extra `nameservers` configuration needed.

#### 🗜️ Response Compression

Automatically compress HTTP responses to reduce bandwidth usage and improve page load times. Jokoway negotiates the best algorithm with the client via the `Accept-Encoding` header.

```yaml
jokoway:
  compression:
    min_size: 1024
    gzip:
      level: 6
    brotli:
      quality: 5
      lgwin: 22
      buffer_size: 4096
    zstd:
      level: 3
    content_types:
      - "text/html"
      - "text/css"
      - "application/json"
      - "application/javascript"
      - "image/svg+xml"
```

##### General Fields

| Field | Default | Description |
| :--- | :---: | :--- |
| `min_size` | `1024` | Minimum response body size (in bytes) before compression kicks in. Responses smaller than this are sent uncompressed. |
| `content_types` | *(see below)* | List of MIME types eligible for compression. If omitted, Jokoway uses a built-in list of industry-standard compressible types. |

##### Algorithm Configuration

Each algorithm is optional. Omitting an algorithm section disables it entirely. When multiple algorithms are enabled, Jokoway automatically selects the best one based on the client's `Accept-Encoding` header, using the priority order: **Brotli → Zstandard → Gzip**.

**Gzip** — widest client compatibility, always available.

| Field | Default | Range | Description |
| :--- | :---: | :---: | :--- |
| `level` | `6` | 1–9 | Compression level. Higher = better ratio but slower. |

**Brotli** — best compression ratio.

| Field | Default | Range | Description |
| :--- | :---: | :---: | :--- |
| `quality` | `5` | 1–11 | Compression quality. Higher = better ratio but slower. |
| `lgwin` | `22` | 10–24 | Sliding window size (as a power of 2). Larger = better ratio, more memory. |
| `buffer_size` | `4096` | — | Internal buffer size in bytes. |

**Zstandard (zstd)** — fastest compression speed.

| Field | Default | Range | Description |
| :--- | :---: | :---: | :--- |
| `level` | `3` | 1–22 | Compression level. Higher = better ratio but slower. |

> [!IMPORTANT]
> Brotli and Zstandard require their respective Cargo features to be enabled at compile time (`brotli` and `zstd`). Gzip is always available.

##### Default Content Types

If you don't specify a `content_types` list, Jokoway uses an industry-standard set (based on Cloudflare, NGINX, and Apache defaults) that includes: `text/html`, `text/css`, `text/javascript`, `application/javascript`, `application/json`, `application/xml`, `text/xml`, `text/plain`, `text/markdown`, `image/svg+xml`, and a `text/*` wildcard.

Already-compressed formats (e.g., `image/jpeg`, `image/png`, `video/mp4`, `application/zip`, `application/gzip`) are **always skipped** regardless of configuration.

### 🔐 Security & TLS (HTTPS)

Jokoway supports two approaches to TLS: **manual certificates** you provide yourself, and **automatic provisioning** via the ACME protocol (Let's Encrypt).

> [!WARNING]
> Both `ssl` and `acme` require `https_listen` to be configured in the `jokoway` section.

#### Manual Certificates (`ssl`)

Provide your own certificate and private key directly. Ideal for internal services, self-signed setups, or when you manage certificates externally.

```yaml
jokoway:
  ssl:
    server_cert: "/path/to/cert.pem"
    server_key: "/path/to/key.pem"
    cacert: "/path/to/ca.pem"
    sans: ["example.com", "localhost"]
    cipher_suites:
      - "TLS_AES_128_GCM_SHA256"
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
```

| Field | Required | Description |
| :--- | :---: | :--- |
| `server_cert` | ❌ | Path to the server certificate file (PEM format). |
| `server_key` | ❌ | Path to the server private key file (PEM format). |
| `cacert` | ❌ | Path to a CA certificate file. Setting this **enables mutual TLS (mTLS)** — clients must present a valid certificate signed by this CA to connect. |
| `sans` | ❌ | List of Subject Alternative Names (e.g., `["example.com", "localhost"]`). Only used when `server_cert` / `server_key` are **not** provided — in that case, Jokoway generates a self-signed certificate with these SANs as a fallback. |
| `cipher_suites` | ❌ | List of allowed cipher suites (e.g., `"TLS_AES_128_GCM_SHA256"`, `"TLS_AES_256_GCM_SHA384"`, `"TLS_CHACHA20_POLY1305_SHA256"`). |

> [!TIP]
> If you omit `server_cert` and `server_key` but provide `sans`, Jokoway will automatically generate a self-signed certificate. This is useful for local development and testing.

#### ACME (Automatic Certificate Management Environment)

Automatically issue and renew valid SSL certificates from a CA like Let's Encrypt — zero manual intervention required after initial configuration.

```yaml
jokoway:
  acme:
    ca_server: "https://acme-v02.api.letsencrypt.org/directory"
    email: "admin@example.com"
    storage: "/etc/jokoway/acme.json"
    challenge: "http-01"
    renewal_interval: 86400
```

| Field | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `ca_server` | ✅ | — | ACME directory URL. Use `https://acme-v02.api.letsencrypt.org/directory` for production, or `https://acme-staging-v02.api.letsencrypt.org/directory` for testing. |
| `email` | ✅ | — | Email address for ACME account registration and certificate expiry notifications. |
| `storage` | ✅ | — | Path to a JSON file where certificates and account data are persisted across restarts. |
| `challenge` | ❌ | `"http-01"` | Challenge type for domain validation: `"http-01"` (requires port 80) or `"tls-alpn-01"` (uses port 443). |
| `renewal_interval` | ❌ | `86400` | How often (in seconds) Jokoway checks whether certificates need renewal. Default is 86400 (1 day). |

> [!TIP]
> Always test with the **staging** CA server first to avoid hitting Let's Encrypt rate limits.

##### How does ACME work with Jokoway?

Jokoway automatically requests certificates for domains that appear in your routing rules. To obtain a certificate, simply use the `` Host(`example.com`) `` rule in any service route (see [Routing Rules Reference](#-routing-rules-reference)). Jokoway will handle issuance, validation, and renewal automatically.

### 🎛️ Management API

Provides an internal HTTP API for dynamically managing upstreams and services at runtime, without restarting Jokoway. It also serves interactive OpenAPI (Swagger) documentation.

> [!IMPORTANT]
> The Management API requires the `api` Cargo feature to be enabled at compile time.

```yaml
jokoway:
  api:
    listen: "127.0.0.1:9090"
    basic_auth:
      username: "admin"
      password: "secure_password"
    rate_limit:
      requests_per_second: 10
      burst: 5
    openapi:
      title: "Jokoway Management API"
      description: "Gateway router API"
      root_path: "/docs"
```

> [!CAUTION]
> The Management API gives full control over routing and upstreams. **Always bind to a private address** (e.g., `127.0.0.1`) and protect it with `basic_auth`. Never expose it to the public internet.

##### API Fields

| Field | Required | Description |
| :--- | :---: | :--- |
| `listen` | ❌ | Address and port to listen on (e.g., `"127.0.0.1:9090"`). If omitted, the API server is not started. |
| `basic_auth` | ❌ | Enable HTTP Basic Authentication. See **Basic Auth** below. |
| `rate_limit` | ❌ | Protect the API from excessive requests. See **Rate Limit** below. |
| `openapi` | ❌ | Customize the built-in OpenAPI/Swagger documentation. See **OpenAPI** below. |

##### Basic Auth

| Field | Required | Description |
| :--- | :---: | :--- |
| `username` | ✅ | Username for HTTP Basic Authentication. |
| `password` | ✅ | Password for HTTP Basic Authentication. |

##### Rate Limit

| Field | Required | Description |
| :--- | :---: | :--- |
| `requests_per_second` | ✅ | Maximum sustained requests per second allowed. |
| `burst` | ✅ | Maximum number of requests allowed in a burst before rate limiting kicks in. |

##### OpenAPI

Interactive API documentation is served at the configured `root_path`.

| Field | Default | Description |
| :--- | :---: | :--- |
| `title` | `"Jokoway API"` | Title displayed in the OpenAPI documentation page. |
| `description` | `"Jokoway Management API"` | Description shown in the API docs. |
| `root_path` | `"/docs"` | URL path where the Swagger UI is served (e.g., visit `http://127.0.0.1:9090/docs`). |

### 🏗️ Upstreams & Services

The heart of Jokoway's routing engine. **Upstreams** define your backend servers, and **Services** define how incoming requests find their way to those servers.

#### 1. Upstreams (Backend Clusters)

An upstream is a named pool of backend servers. Jokoway load-balances traffic across servers within an upstream using weighted round-robin.

```yaml
jokoway:
  upstreams:
    - name: api_cluster
      servers:
        - host: "10.0.0.1:3000"
          weight: 2
          tls: false
        - host: "10.0.0.2:3000"
          weight: 1
          tls: true
          peer_options:         # Override peer options for this server only
            read_timeout: 5
      health_check:
        type: "http"
        interval: 10
        timeout: 3
        unhealthy_threshold: 3
        healthy_threshold: 2
        path: "/health"
        method: "GET"
        expected_status: [200, 204]
        headers:
          User-Check: "Pingora-Health"
      update_frequency: 60
      peer_options:             # Default peer options for all servers
        read_timeout: 30
        idle_timeout: 60
        write_timeout: 30
        verify_cert: true
        verify_hostname: true
        tcp_recv_buf: 4096
        tcp_fast_open: true
        sni: "backend.example.com"
```

##### Upstream Fields

| Field | Required | Description |
| :--- | :---: | :--- |
| `name` | ✅ | Unique identifier for this upstream cluster. Services reference this name via the `host` field. |
| `servers` | ✅ | List of backend servers in this cluster. See **Server Fields** below. |
| `health_check` | ❌ | Active health monitoring configuration. See **Health Check Fields** below. |
| `update_frequency` | ❌ | How often (in seconds) to refresh the upstream configuration dynamically. |
| `peer_options` | ❌ | Default connection settings applied to **all** servers in this upstream. Individual servers can override these. See **Peer Options Fields** below. |

##### Server Fields

Each entry in the `servers` list represents a single backend instance.

| Field | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `host` | ✅ | — | Address of the backend server in `host:port` format (e.g., `"10.0.0.1:3000"`). |
| `weight` | ❌ | `1` | Relative weight for load balancing. A server with `weight: 2` receives twice the traffic of a server with `weight: 1`. |
| `tls` | ❌ | `false` | If `true`, Jokoway connects to this backend server over TLS (HTTPS). |
| `peer_options` | ❌ | — | Override the upstream-level `peer_options` for this specific server only. |

##### Health Check Fields

Active health checks periodically probe each backend server to determine if it is healthy and should receive traffic. Jokoway supports three check types: `http`, `https`, and `tcp`.

| Field | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `type` | ✅ | — | Health check protocol: `"http"`, `"https"`, or `"tcp"`. |
| `interval` | ❌ | `10` | Seconds between each health check probe. |
| `timeout` | ❌ | `3` | Maximum seconds to wait for a health check response before considering it failed. |
| `unhealthy_threshold` | ❌ | `3` | Number of consecutive failures before marking a server as **unhealthy**. |
| `healthy_threshold` | ❌ | `2` | Number of consecutive successes before marking a server as **healthy** again. |
| `path` | ❌ | — | *(HTTP/HTTPS only)* The URL path to probe (e.g., `"/health"`). |
| `method` | ❌ | — | *(HTTP/HTTPS only)* HTTP method for the probe (e.g., `"GET"`, `"HEAD"`). |
| `expected_status` | ❌ | — | *(HTTP/HTTPS only)* List of HTTP status codes that indicate a healthy response (e.g., `[200, 204]`). |
| `headers` | ❌ | — | *(HTTP/HTTPS only)* Custom headers to include in the health check request. |

##### Peer Options Fields

Peer options control how Jokoway connects to upstream backend servers. They can be set at the **upstream level** (applies to all servers) or at the **individual server level** (overrides the upstream default).

| Field | Default | Description |
| :--- | :---: | :--- |
| `read_timeout` | — | Timeout (in seconds) for reading a response from the upstream. |
| `idle_timeout` | — | Timeout (in seconds) before closing an idle keep-alive connection. |
| `write_timeout` | — | Timeout (in seconds) for writing a request to the upstream. |
| `verify_cert` | `false` | If `true`, verify the upstream server's TLS certificate. |
| `verify_hostname` | `false` | If `true`, verify that the upstream's TLS certificate hostname matches. |
| `tcp_recv_buf` | — | TCP receive buffer size in bytes. |
| `tcp_fast_open` | — | If `true`, enable TCP Fast Open for reduced latency on new connections. |
| `curves` | — | SSL/TLS curves to use for the connection. |
| `cacert` | — | Path to a CA certificate file for verifying the upstream's TLS certificate. |
| `client_cert` | — | Path to a client certificate file for mutual TLS (mTLS) with the upstream. |
| `client_key` | — | Path to a client private key file for mTLS. |
| `sni` | — | Server Name Indication (SNI) hostname to send during the TLS handshake. |

> [!TIP]
> You can use YAML anchors to define `peer_options` once and reuse them across multiple upstreams. See the [full example configuration](./jokoway.yml) for details.

#### 2. Services (Frontend Routes)

A service binds an upstream cluster to a set of routing rules. When an incoming request matches a route's rule, it is forwarded to the service's upstream.

```yaml
jokoway:
  services:
    - name: public_api
      host: api_cluster         # Must match an upstream name
      protocols: ["http", "https", "ws", "wss"]
      routes:
        - name: api-route
          rule: >-
            Host(`api.example.com`) && PathPrefix(`/v1`)
          priority: 100
          request_transformer: "StripPrefix(`/v1`)"
          response_transformer: "ReplaceHeader(`Server`, `Jokoway`)"
```

##### Service Fields

| Field | Required | Description |
| :--- | :---: | :--- |
| `name` | ✅ | Unique identifier for this service. |
| `host` | ✅ | The name of the **upstream** cluster to route traffic to. Must match an upstream's `name` field. |
| `protocols` | ✅ | List of protocols this service accepts: `"http"`, `"https"`, `"ws"` (WebSocket), `"wss"` (WebSocket over TLS). |
| `routes` | ✅ | List of routing rules. See **Route Fields** below. |

##### Route Fields

| Field | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `name` | ✅ | — | Unique identifier for this route. |
| `rule` | ✅ | — | A match expression using the routing rule syntax (see [Routing Rules Reference](#-routing-rules-reference)). |
| `priority` | ❌ | `0` | Higher values are evaluated first. Use this to ensure specific routes take precedence over broader catch-all rules. |
| `request_transformer` | ❌ | — | Transform the request before forwarding to the upstream. See [Request Transformers](#request-transformers-before-routing-to-upstream). |
| `response_transformer` | ❌ | — | Transform the response before sending to the client. See [Response Transformers](#response-transformers-before-sending-to-client). |

---

### ⚙️ Pingora Engine Settings

These settings configure the underlying [Pingora](https://github.com/cloudflare/pingora) server runtime. This is the `pingora` top-level key (separate from `jokoway`).

```yaml
pingora:
  # Core
  threads: 4
  work_stealing: true
  version: 1

  # Daemon / Process
  daemon: false
  pid_file: "/var/run/jokoway.pid"
  error_log: "/var/log/jokoway.log"
  upgrade_sock: "/tmp/jokoway_upgrade.sock"
  user: null
  group: null

  # Shutdown
  grace_period_seconds: 60
  graceful_shutdown_timeout_seconds: 30

  # Networking
  ca_file: null
  listener_tasks_per_fd: 1
  upstream_keepalive_pool_size: 128
  client_bind_to_ipv4: []
  client_bind_to_ipv6: []
  upstream_connect_offload_threadpools: null
  upstream_connect_offload_thread_per_pool: null
```

> [!NOTE]
> For most deployments, you only need to set `threads` and `work_stealing`. The defaults are production-ready. See the [Pingora ServerConf documentation](https://docs.rs/pingora/latest/pingora/server/configuration/struct.ServerConf.html) for advanced tuning.

## 🚦 Routing Rules Reference

Jokoway uses expressive matching rules. You can combine them effortlessly using logical operators to build highly specific routing paradigms: 
* `&&` (AND) 
* `||` (OR) 
* `!` (NOT)

**Example:** `` Host(`api.test.com`) && (PathPrefix(`/users`) || PathPrefix(`/orders`)) ``

| Rule Syntax | Description | Example |
| :--- | :--- | :--- |
| `Host(string)` | Exact domain match. This is used by the `acme` extension to request SSL certificates. | `` Host(`example.com`) `` |
| `HostRegexp(regex)` | Regex domain match. | `` HostRegexp(`^.*\.example\.com$`) `` |
| `Path(string)` | Exact path match. | `` Path(`/api/v1/health`) `` |
| `PathPrefix(string)` | Path starts-with match. | `` PathPrefix(`/api`) `` |
| `PathRegexp(regex)` | Regex path match. | `` PathRegexp(`^/user/[0-9]+$`) `` |
| `Method(string)` | HTTP Method match. | `` Method(`POST`) `` |
| `HeaderRegexp(k, v)` | Header name and Regex value match. | `` HeaderRegexp(`User-Agent`, `^Mozilla.*`) `` |
| `QueryRegexp(k, v)` | Query parameter name and Regex value match. | `` QueryRegexp(`id`, `^[0-9]+$`) `` |

---

## 🔄 Request / Response Transformers

Transformers mutate HTTP traffic on the fly. You can configure multiple transformers on a single route by separating them with a semicolon (`;`).

**Example:** `` StripPrefix(`/api`); AddPrefix(`/v2`); ReplaceHeader(`Host`, `backend.local`) ``

### Request Transformers (Before routing to Upstream)
Used to adapt the client request to map exactly to what the internal backend expects.

| Function | Description | Example |
| :--- | :--- | :--- |
| `ReplaceHeader(k, v)` | Replaces / sets a header value. | `` ReplaceHeader(`Host`, `backend.local`) `` |
| `AppendHeader(k, v)` | Appends to an existing header. | `` AppendHeader(`X-Forwarded-For`, `client-ip`) `` |
| `DeleteHeader(k)` | Removes a header entirely. | `` DeleteHeader(`Authorization`) `` |
| `ReplaceQuery(k, v)` | Sets a query parameter. | `` ReplaceQuery(`foo`, `bar`) `` |
| `AppendQuery(k, v)` | Appends a new query parameter. | `` AppendQuery(`debug`, `true`) `` |
| `DeleteQuery(k)` | Removes a query parameter. | `` DeleteQuery(`token`) `` |
| `StripPrefix(path)` | Strips prefix from the requested path. | `` StripPrefix(`/api`) `` |
| `AddPrefix(path)` | Prepends a prefix to the requested path. | `` AddPrefix(`/v1`) `` |
| `RewritePath(reg, rp)` | Rewrites the path using Regex capture groups. | `` RewritePath(`^/old/(.*)`, `/new/$1`) `` |
| `SetMethod(method)` | Changes the HTTP Method. | `` SetMethod(`PUT`) `` |

### Response Transformers (Before sending to Client)
Used to hide server-side details, enforce security headers, or append cache statuses before the client sees the response.

| Function | Description | Example |
| :--- | :--- | :--- |
| `ReplaceHeader(k, v)` | Sets a header on the response. | `` ReplaceHeader(`Server`, `Jokoway`) `` |
| `AppendHeader(k, v)` | Appends to a response header. | `` AppendHeader(`X-Cache-Status`, `MISS`) `` |
| `DeleteHeader(k)` | Strips an internal header. | `` DeleteHeader(`X-Powered-By`) `` |
