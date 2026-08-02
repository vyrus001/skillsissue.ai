FROM rust:1.96.0-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p skill-relay

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/empty /run/secrets /run/skillsissue \
    && chown 65532:65532 /var/empty /run/secrets /run/skillsissue
COPY --from=build /src/target/release/skill-relay /usr/local/bin/skill-relay
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65532:65532
WORKDIR /var/empty
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD ["skill-relay", "check", "--unix-socket", "/run/skillsissue/relay.sock", "--timeout-seconds", "2"]
ENTRYPOINT ["skill-relay", "serve"]
