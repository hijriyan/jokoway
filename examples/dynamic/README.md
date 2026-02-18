# Jokoway Dynamic Example

This example demonstrates how to use Jokoway with the API extension enabled to dynamically manage upstreams and services.

## Prerequisites

- `docker` (make sure it has `compose` plugin)
- `httpie` installed (or use `curl`).

## Running the Example

1. Start the server:

   ```bash
   docker compose up -d
   ```

2. The server listens on `0.0.0.0:2014` for traffic and `0.0.0.0:2025` for the API.

## Dynamic Configuration Tutorial

### 1. Add Upstream

We will add an upstream named `httpbin` pointing to `httpbin:8080` (httpbin service via docker).

```bash
http POST http://localhost:2025/upstreams/add \
  upstream:='{
    "name": "httpbin",
    "servers": [
      {
        "host": "httpbin:8080"
      }
    ]
  }'
```

### 2. Verify Upstream

Verify that the upstream has been added successfully.

```bash
http POST http://localhost:2025/upstreams/verify name=httpbin
```

### 3. Add Service and Route

Add a service named `httpbin_service` that uses the `httpbin` upstream. We will route requests with `Host: localhost:2014` to this service.

```bash
http POST http://localhost:2025/services/add \
  service:='{
    "name": "httpbin_service",
    "host": "httpbin",
    "protocols": ["http"],
    "routes": [
      {
        "name": "root",
        "rule": "Host(`localhost:2014`)",
        "priority": 1
      }
    ]
  }'
```

Test it:

```bash
http http://localhost:2014/get
```

### 4. Update Service and Route

Let's update the route to match a specific path prefix `/api` and strip it before forwarding to upstream.

```bash
http POST http://localhost:2025/services/update \
  name=httpbin_service \
  service:='{
    "name": "httpbin_service",
    "host": "httpbin",
    "protocols": ["http"],
    "routes": [
      {
        "name": "api_route",
        "rule": "Host(`localhost:2014`) && PathPrefix(`/api`)",
        "priority": 1,
        "request_transformer": "StripPrefix(`/api`)"
      }
    ]
  }'
```

Test valid path:

```bash
http http://localhost:2014/api/get
```
