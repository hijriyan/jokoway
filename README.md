# jokoway

<p align="center">
  <img src="https://raw.githubusercontent.com/hijriyan/jokoway/refs/heads/main/images/jokoway-logo.png" width="100%" alt="jokoway logo">
</p>

Jokoway is a high-performance API Gateway built on Pingora (Rust) with dead-simple YAML configs. Inspired by Traefik’s expressive routing rules and Kong’s DB-less declarative configuration model.

<p align="center">
  <strike>This is not intended for use in a production environment.</strike> This project is actually for learning and experimenting with Rust.
</p>

<p align="center">
  ⚠️ If you want to try it, go ahead, and I really appreciate any feedback. ⚠️ 
</p>

## 🌟 Key Features

* **Expressive Routing**: Traefik-style routing rules.
* **DB-less Declarative Config**: Manage your configuration without a database.
* **Highly Customizable**: Extend Jokoway's functionality with extensions.
* **Lets Encrypt**: Automatically issue and renew SSL certificates. (Supports HTTP-01 and TLS-ALPN-01 challenges)

## 🔧 Installation

### Using `cargo install`

```sh
cargo install jokoway
```

### Using Docker

**Prerequisites:**
- docker

```sh
docker pull ghcr.io/hijriyan/jokoway:latest
```

### From Source

**Prerequisites:**
- rust
- cargo

```sh
git clone --depth 1 https://github.com/hijriyan/jokoway.git
cd jokoway
cargo build --release
# The binary will be available at target/release/jokoway
```

## 🔨 Usage

### Using `cargo install`

```sh
jokoway -c config/jokoway.yml
```

### Using Docker

```sh
docker run -d \
    -p 2014:2014 \
    -e RUST_LOG=info \
    --name jokoway \
    -v $(pwd)/config:/etc/jokoway/config \
    ghcr.io/hijriyan/jokoway:latest \
    -c /etc/jokoway/config/httpbin.yml
```

### From Source

```sh
./target/release/jokoway -c config/jokoway.yml
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
