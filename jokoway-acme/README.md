# Jokoway ACME Extension

[Jokoway](https://github.com/hijriyan/jokoway) extension for Automatic Certificate Management Environment (ACME), enabling automatic HTTPS certificate issuance and renewal via Let's Encrypt (or other ACME-compliant CAs).

This crate integrates `instant-acme` with `pingora` (via `jokoway-core`) to handle certificate lifecycle management, including:

- **Automatic Issuance**: Requests certificates for configured domains.
- **Challenge Solving**: Supports `http-01` and `tls-alpn-01` challenges.
- **Auto-Renewal**: Background service monitors and renews expiring certificates.
- **Persistent Storage**: Saves account credentials and certificates to disk (JSON format).

## Installation

It's already included in main crate `jokoway` via `acme-extension` feature.

## Configuration

```yaml
# jokoway.yml
jokoway:
  acme:
    # URL of the ACME directory
    # Production: https://acme-v02.api.letsencrypt.org/directory
    # Staging: https://acme-staging-v02.api.letsencrypt.org/directory
    ca_server: "https://acme-v02.api.letsencrypt.org/directory"
    
    # Email for account registration and recovery
    email: "admin@example.com"
    
    # Path to store certificates and account data
    storage: "./acme.json"
    
    # Challenge type: "http-01" or "tls-alpn-01"
    challenge: "http-01"
    
    # Check interval in seconds (optional, default: 86400 / 24h)
    renewal_interval: 86400
```

## Architecture

The extension consists of three main components:

1. **`AcmeManager`**: Handles the core ACME logic (account creation, order placement, challenge handling, certificate download) and manages the in-memory certificate cache.
2. **`AcmeMiddleware`** (for `http-01`): Intercepts requests to `/.well-known/acme-challenge/*` and serves the key authorization.
3. **`AcmeTlsHandler`**:
    - **SNI Callback**: Selects the correct certificate from the cache based on the ServerName.
    - **ALPN Callback** (for `tls-alpn-01`): Negotiates usage of `acme-tls/1` protocol and serves the special validation certificate when required.
