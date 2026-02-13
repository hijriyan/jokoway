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
  <strike>This is not intended for use in a production environment.</strike> This project is actually for learning and experimenting with Rust.
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
- [Rust & Cargo](https://rustup.rs/) (Stable)
- `cmake` and `perl` (Required by Pingora dependencies)

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
      routes:
        - rule: PathPrefix(`/`)
```

2. **Run Jokoway**:
```sh
# Enable logging to see what's happening
export RUST_LOG=info
jokoway -c config.yml
```

3. **Verify**:
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


## 📝 Configuration

Jokoway uses a declarative YAML configuration file. You can see a [full example configuration here](./config/jokoway.yml).

The configuration is divided into two main sections: `jokoway` for the gateway settings and `pingora` for the underlying engine settings.

### 🌐 Jokoway Core Settings

- **`http_listen`**: (String) The address and port to listen for HTTP traffic (e.g., `"0.0.0.0:8080"`).
- **`https_listen`**: (Optional String) The address and port for HTTPS traffic. Requires `ssl` configuration.
- **`dns`**: (Optional) Resolver settings for upstream name resolution.
  - `nameservers`: List of IP addresses (e.g., `["1.1.1.1", "8.8.8.8"]`).
  - `strategy`: Resolution strategy (`"ipv4_then_ipv6"`, `"ipv4_only"`, etc.).
- **`compression`**: (Optional) HTTP compression settings.
  - `min_size`: Minimum response size to compress in bytes (default: 1024).
  - `content_types`: List of MIME types to compress.
  - Supports **Gzip**, **Brotli**, and **Zstandard**.

### 🔐 Security & TLS

- **`ssl`**: (Optional) Manual server certificate configuration.
  - `server_cert`: Path to the certificate file.
  - `server_key`: Path to the private key file.
  - `ssl_min_version`: Minimum TLS version (e.g., `"1.2"`).
- **`acme`**: (Optional) Automatic TLS via Let's Encrypt.
  - `ca_server`: ACME directory URL.
  - `email`: Registration email.
  - `storage`: Path to store certificates (JSON).
  - `challenge`: `"http-01"` or `"tls-alpn-01"`.

### 🎛️ API & Management

- **`api`**: (Optional) Management API for monitoring and documentation.
  - `listen`: API address (e.g., `"127.0.0.1:9090"`).
  - `basic_auth`: Basic authentication credentials.
  - `rate_limit`: API request rate limiting.
  - `openapi`: Customizable OpenAPI documentation path and metadata.

### 🏗️ Upstreams & Services

The routing logic is defined by connecting **Services** to **Upstreams** using **Rules**.

#### Upstreams (Backend Clusters)
- **`upstreams`**: A list of backend server groups.
  - `name`: Unique name for the cluster.
  - `servers`: List of backend servers with `host`, `weight`, and `tls` settings.
  - `health_check`: Active health monitoring (HTTP, HTTPS, or TCP).
  - `peer_options`: Detailed connection settings (timeouts, mTLS, SNI, buffers).

#### Services (Frontend Configuration)
- **`services`**: A list of logical services.
  - `name`: Service identifier.
  - `host`: The name of the **Upstream** cluster to route to.
  - `protocols`: Supported protocols (`http`, `https`, `ws`, `wss`).
  - `routes`: A list of routing rules.

#### Routing Rules
Jokoway uses expressive rules for matching requests:
- **`rule`**: A match expression (e.g., `PathPrefix('/api')`, `Host('example.com')`).
- **`priority`**: (Optional) Higher priority rules match first.
- **`request_transformer`**: (Optional) Extension for modifying requests.
- **`response_transformer`**: (Optional) Extension for modifying responses.

### ⚙️ Pingora Engine Settings

Exposes the underlying Pingora server configuration.
- **`threads`**: Number of worker threads.
- **`daemon`**: Whether to run as a background process.
- **`error_log`**: Path to the error log file.
- **`pid_file`**: Path to the PID file.
- **`grace_period_seconds`**: Shutdown grace period.
- **`work_stealing`**: Enable/disable work stealing between threads.

## 🚦 Routing Rules

Jokoway uses rule expressions to match requests. Rules can be combined using logical operators: `&&` (AND), `||` (OR), and `!` (NOT).

| Rule | Description | Example |
| :--- | :--- | :--- |
| `Host` | Matches the request domain/host. | `` Host(`example.com`) `` |
| `HostRegexp` | Matches the host using Regex. | `` HostRegexp(`^.*\.example\.com$`) `` |
| `Path` | Matches the request path exactly. | `` Path(`/api/v1/health`) `` |
| `PathPrefix` | Matches the path if it starts with a specific prefix. | `` PathPrefix(`/api`) `` |
| `PathRegexp` | Matches the path using Regex. | `` PathRegexp(`^/user/[0-9]+$`) `` |
| `Method` | Matches the HTTP Method. | `` Method(`POST`) `` |
| `HeaderRegexp` | Matches a specific header using Regex. | `` HeaderRegexp(`User-Agent`, `^Mozilla.*`) `` |
| `QueryRegexp` | Matches a query parameter using Regex. | `` QueryRegexp(`id`, `^[0-9]+$`) `` |

## 🔄 Transformers

Transformers are used to modify the request before it is sent to the upstream or modify the response before it is sent back to the client.

### Request Transformers
Can be used in the `request_transformer` attribute of a route. Multiple transformers can be separated by a semicolon `;`.

| Function | Description | Example |
| :--- | :--- | :--- |
| `ReplaceHeader` | Replaces the header value. | `` ReplaceHeader(`Host`, `backend.local`) `` |
| `AppendHeader` | Appends a value to an existing header. | `` AppendHeader(`X-Forwarded-For`, `client-id`) `` |
| `DeleteHeader` | Deletes the header. | `` DeleteHeader(`Authorization`) `` |
| `ReplaceQuery` | Replaces the query parameter value. | `` ReplaceQuery(`foo`, `bar`) `` |
| `AppendQuery` | Appends a new query parameter. | `` AppendQuery(`debug`, `true`) `` |
| `DeleteQuery` | Deletes the query parameter. | `` DeleteQuery(`token`) `` |
| `StripPrefix` | Strips the prefix from the path. | `` StripPrefix(`/api`) `` |
| `AddPrefix` | Adds a prefix to the path. | `` AddPrefix(`/v1`) `` |
| `RewritePath` | Rewrites the path using Regex. | `` RewritePath(`^/old/(.*)`, `/new/$1`) `` |
| `SetMethod` | Changes the HTTP Method. | `` SetMethod(`PUT`) `` |

### Response Transformers
Can be used in the `response_transformer` attribute of a route.

| Function | Description | Example |
| :--- | :--- | :--- |
| `ReplaceHeader` | Replaces the header value in the response. | `` ReplaceHeader(`Server`, `Jokoway`) `` |
| `AppendHeader` | Appends a value to the response header. | `` AppendHeader(`X-Cache`, `MISS`) `` |
| `DeleteHeader` | Deletes the header from the response. | `` DeleteHeader(`X-Powered-By`) `` |
