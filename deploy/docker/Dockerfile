FROM rust:1.85 AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin homa-node

FROM debian:bookworm-slim
RUN useradd -m -u 10001 homa
WORKDIR /opt/homa
RUN mkdir -p /var/lib/homa /etc/homa
COPY --from=builder /build/target/release/homa-node /usr/local/bin/homa-node
COPY node.toml.example /etc/homa/node.toml
RUN chown -R homa:homa /var/lib/homa /etc/homa
USER homa
EXPOSE 8545 7000 7001
ENTRYPOINT ["homa-node", "run", "--config", "/etc/homa/node.toml"]
