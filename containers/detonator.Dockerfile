FROM rust:1.96.0-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p skill-detonate --bin skill-detonate \
    && cargo build --locked --release -p skills-core --bin skills-state

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates docker.io \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/skill-detonate /usr/local/bin/skill-detonate
COPY --from=build /src/target/release/skills-state /usr/local/bin/skills-state
WORKDIR /workspace
ENTRYPOINT ["skill-detonate"]
