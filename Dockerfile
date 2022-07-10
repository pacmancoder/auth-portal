FROM rust:1.62-slim-bullseye as builder
WORKDIR /usr/src/auth-portal
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
COPY --from=builder /usr/local/cargo/bin/auth-portal /usr/local/bin/auth-portal
EXPOSE 8080/tcp
VOLUME ["/data"]

ENV AP_CONFIG="/data/auth-portal.toml"
ENV AP_PORT="8080"
ENV AP_ADDRESS="0.0.0.0"
ENV RUST_LOG=warn

ENTRYPOINT ["/usr/local/bin/auth-portal"]
CMD [ "serve" ]
