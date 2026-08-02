FROM rust:1.96.0-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p skill-detonate --bin skill-harness

FROM node:22.22.0-bookworm-slim@sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94 AS agent-clis
WORKDIR /opt/agent-clis
COPY containers/agent-clis/package.json containers/agent-clis/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --audit=false --fund=false \
    && node node_modules/@anthropic-ai/claude-code/install.cjs \
    && node_modules/.bin/codex --version \
    && node_modules/.bin/claude --version

FROM node:22.22.0-bookworm-slim@sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94
COPY containers/python-requirements.txt /tmp/python-requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates coreutils curl python-is-python3 python3 python3-greenlet python3-pip python3-requests python3-typing-extensions python3-yaml wget \
    && python3 -m pip install --no-cache-dir --no-deps --require-hashes --target /usr/local/lib/python3.11/dist-packages -r /tmp/python-requirements.txt \
    && rm -f /tmp/python-requirements.txt \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /work/skill /home/detonator /run/skillsissue \
    && chown -R 65532:65532 /work /home/detonator /run/skillsissue \
    && ln -s /opt/agent-clis/node_modules/.bin/codex /usr/local/bin/codex \
    && ln -s /opt/agent-clis/node_modules/.bin/claude /usr/local/bin/claude
COPY --from=agent-clis /opt/agent-clis /opt/agent-clis
COPY --from=build /src/target/release/skill-harness /usr/local/bin/skill-harness
USER 65532:65532
WORKDIR /work/skill
ENTRYPOINT ["/usr/local/bin/skill-harness"]
