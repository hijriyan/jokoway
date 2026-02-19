# Builder stage
# Use rust:1.92-bookworm (Debian 12) to match distroless/cc-debian12's glibc 2.36
# rust:1.92-slim uses Debian 13 (glibc 2.41) which is too new for distroless/cc-debian12
FROM rust:1.92-bookworm AS builder
WORKDIR /app

# Install build dependencies
# build-essential: gcc, g++, make
# cmake, perl, pkg-config: Build tools (needed for zstd-sys, libz-ng-sys, etc)
# libclang-dev, git: Required for boring-sys (BoringSSL) and bindgen
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake perl pkg-config libclang-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Build the application in release mode
# The binary will be at /app/target/release/jokoway
RUN cargo build --release --bin jokoway

# Create the directory for runtime
RUN mkdir -p /opt/jokoway

# Runtime stage: Distroless (Debian 12)
# gcr.io/distroless/cc-debian12 is required for dynamically linked binaries (glibc/libstdc++)
# Check https://github.com/GoogleContainerTools/distroless for more info
FROM gcr.io/distroless/cc-debian12

LABEL org.opencontainers.image.source=https://github.com/hijriyan/jokoway
LABEL org.opencontainers.image.authors="Aprila Hijriyan"
LABEL org.opencontainers.image.title="Jokoway"
LABEL org.opencontainers.image.description="Jokoway is a high-performance API Gateway built on Pingora (Rust) with dead-simple YAML configs."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.url="https://github.com/hijriyan/jokoway"
LABEL org.opencontainers.image.version="0.1.0-alpha.5"

# Copy the binary from builder
COPY --from=builder --chown=nonroot:nonroot /app/target/release/jokoway /
COPY --from=builder --chown=nonroot:nonroot /opt/jokoway /opt/jokoway

# Set working directory to /opt/jokoway (owned by nonroot)
WORKDIR /opt/jokoway

# Run as nonroot user
USER nonroot

# Set the entrypoint
ENTRYPOINT ["/jokoway"]
