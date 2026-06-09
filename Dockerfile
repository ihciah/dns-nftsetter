# Stage 1: Build
FROM rust:alpine AS builder

# Install system build dependencies
RUN apk add --no-cache musl-dev pkgconfig libpcap-dev

WORKDIR /usr/src/dns-nftsetter

# Copy Cargo files and build dependencies first to leverage Docker layer caching
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy source code and build the application
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM alpine:latest

# Install runtime dependencies (libpcap is required)
RUN apk add --no-cache libpcap

# Copy the binary from the builder stage
COPY --from=builder /usr/src/dns-nftsetter/target/release/dns-nftsetter /usr/local/bin/dns-nftsetter

ENTRYPOINT ["/usr/local/bin/dns-nftsetter"]
