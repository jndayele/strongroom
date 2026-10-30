# syntax=docker/dockerfile:1

# Stage 1: Build the static/minimal Rust binary (pinned by SHA-256 digest)
FROM rust:1.86.0-bookworm@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081 AS builder

WORKDIR /app

# Copy manifests first to cache dependencies
COPY Cargo.toml Cargo.lock ./

# Create a minimal dummy target to pre-compile dependencies
RUN mkdir -p src && \
    printf '#![forbid(unsafe_code)]\nfn main() {}\n' > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src

# Copy actual source code and tests
COPY src ./src
COPY tests ./tests
COPY migrations ./migrations

# Touch source files to ensure cargo rebuilds our crate, then build release binary
RUN touch src/main.rs src/lib.rs && \
    cargo build --release --locked --bin strongroom-backend && \
    strip /app/target/release/strongroom-backend

# Stage 2: Minimal distroless runtime image (non-root, read-only root filesystem compatible, pinned by SHA-256 digest)
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:ce0d66bc0f64aae46e6a03add867b07f42cc7b8799c949c2e898057b7f75a151

WORKDIR /

COPY --from=builder --chown=65532:65532 /app/target/release/strongroom-backend /strongroom-backend

# Run as nonroot user (UID/GID 65532)
USER 65532:65532

ENV HOST=0.0.0.0
ENV PORT=3000

EXPOSE 3000

# Notes on read-only root filesystem:
# This binary writes no files to disk. Run with `docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges:true`.
ENTRYPOINT ["/strongroom-backend"]
