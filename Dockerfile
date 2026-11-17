FROM rust:1.100-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p shallow-copy-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/shallow-copy-server /usr/local/bin/shallow-copy-server
EXPOSE 8080
CMD ["shallow-copy-server"]
