# Builder stage
FROM rust:alpine AS builder
WORKDIR /app

# Install build dependencies for static linking
# musl-dev: Standard C library for Alpine
# openssl-dev: SSL/TLS support
# pkgconfig: Helper for compiling
# perl, make, gcc, g++, cmake: Build tools (needed for zstd-sys, libz-ng-sys, etc)
RUN apk add --no-cache musl-dev openssl-dev pkgconfig perl make gcc g++ cmake

# Set OPENSSL_STATIC=1 to link OpenSSL statically into the binary
# This is crucial for the binary to run in distroless (which has no shared libraries)
ENV OPENSSL_STATIC=1

# Copy source code
COPY . .

# Build the application in release mode
# The binary will be at /app/target/release/jokoway
RUN cargo build --release --bin jokoway

# Runtime stage: Distroless
# gcr.io/distroless/static-debian12 is a minimal image with no shell/package manager
# Check https://github.com/GoogleContainerTools/distroless for more info
FROM gcr.io/distroless/static-debian12

LABEL org.opencontainers.image.source=https://github.com/hijriyan/jokoway
LABEL org.opencontainers.image.authors="Aprila Hijriyan"
LABEL org.opencontainers.image.title="Jokoway"
LABEL org.opencontainers.image.description="Jokoway is a high-performance API Gateway built on Pingora (Rust) with dead-simple YAML configs."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.url="https://github.com/hijriyan/jokoway"
LABEL org.opencontainers.image.version="0.1.0-alpha.5"

# Copy the statically linked binary from builder
COPY --from=builder --chown=nonroot:nonroot /app/target/release/jokoway /

# Run as nonroot user
USER nonroot

# Set the entrypoint
ENTRYPOINT ["/jokoway"]
