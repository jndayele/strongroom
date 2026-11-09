# Stage 1: Build the static/minimal Rust binary
FROM rust:1.86.0-bookworm AS builder

WORKDIR /build

# Copy workspace configuration and manifests
COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml ./
COPY apps/api/Cargo.toml ./apps/api/Cargo.toml
COPY apps/api/src ./apps/api/src

RUN cargo build --release --locked --package strongroom-api

# Stage 2: Minimal distroless runtime image running as non-root
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

COPY --from=builder /build/target/release/strongroom-api /app/strongroom-api

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app/strongroom-api"]
