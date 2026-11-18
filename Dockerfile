FROM node:22-bookworm-slim AS web-builder
WORKDIR /app/apps/web
COPY apps/web/package*.json ./
COPY apps/web/tsconfig.json ./
RUN npm install
COPY apps/web/src ./src
COPY apps/web/index.html ./
RUN npm run build && cp index.html dist/index.html

FROM rust:1.100-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p shallow-copy-server -p archive-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/shallow-copy-server /usr/local/bin/shallow-copy-server
COPY --from=builder /app/target/release/archive-cli /usr/local/bin/archive-cli
COPY --from=web-builder /app/apps/web/dist /app/apps/web/dist
COPY --from=web-builder /app/apps/web/index.html /app/apps/web/index.html
EXPOSE 8080
CMD ["shallow-copy-server"]
