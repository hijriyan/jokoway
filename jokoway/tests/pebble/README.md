# Pebble ACME Test Environment

This directory contains the local ACME test environment using [Pebble](https://github.com/letsencrypt/pebble), a miniature version of the Let's Encrypt ACME server designed for local testing.

It is used to verify the integration of the `jokoway-acme` extension, ensuring that Jokoway can successfully negotiate certificates via ACME challenges.

## Getting Started

### 1. Generate Test Certificates

Pebble requires a root CA and site certificates for its internal operations.

```bash
./gen_certs.sh
```

### 2. Start the Pebble Environment

The environment is containerized using Docker Compose.

```bash
docker compose up -d
```

### 3. Run Integration Tests

With Pebble running, you can execute the ACME suite:

```bash
cargo test --test acme_test --features acme_tests -- --nocapture
```

## Troubleshooting

If certificates fail to issue:

1. Ensure `docker compose up` is active.
2. Check if ports `14000` (ACME) or `5002/5003` (Jokoway listeners) are blocked by another process.
3. Check Pebble logs using `docker compose logs -f`.

## Cleanup

To stop and remove the test containers:

```bash
docker compose down
```
