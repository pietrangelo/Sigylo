# Image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
#
# The audit runs offline, so this build fetches every crate and npm package and every tool the
# repository's checks use (.github/workflows/ci.yml), then builds and tests the workspace, the Wasm
# engine, the web client, the Worker and the desktop shell. threat_model.md, next to this file, says
# what to attack and how to run each part.

# Ubuntu 24.04, the CI runner. x86-64 only: rustup-init below is the x86_64 build.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 PATH=/root/.cargo/bin:$PATH
# PostgreSQL 16 for supabase/tests and scripts/e2e.sh; WebKitGTK for the Tauri shell in app/.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential pkg-config curl git python3 postgresql postgresql-client \
      libwebkit2gtk-4.1-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev file \
    && rm -rf /var/lib/apt/lists/*

# Stable Rust, as in CI.
RUN curl -fsSLo /tmp/rustup-init https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain stable \
         -c rustfmt -c clippy -t wasm32-unknown-unknown \
    && rm /tmp/rustup-init && cargo --version

# Node 22, as in CI.
COPY --from=node:22-bookworm /usr/local/bin/node /usr/local/bin/node
COPY --from=node:22-bookworm /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && node --version && npm --version

# The pinned tools (CLAUDE.md §1): wasm-bindgen-cli matches crates/sigylo-wasm/Cargo.toml.
RUN cargo install wasm-bindgen-cli@0.2.129 --locked \
    && cargo install worker-build@0.8.7 --locked

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# An ARG, so that it bounds the memory of this build without reaching the audit environment.
ARG CARGO_BUILD_JOBS=4

# Every crate (both workspaces, all targets), every npm package, Chromium for Playwright and the
# wrangler that scripts/e2e.sh runs.
RUN cargo fetch --locked \
    && (cd app && cargo fetch --locked) \
    && (cd web && npm ci --no-fund --no-audit && npx playwright install --with-deps chromium) \
    && npx --yes wrangler@4.151.1 --version

# Native workspace and its tests, the Wasm engine and the web client, the Worker bundle, the desktop
# shell. A step that fails fails the build, and primary_contact gets the log.
RUN cargo build --workspace --all-targets --locked \
    && cargo test --workspace --locked --no-run \
    && cargo run -p architecture-guard \
    && (cd web && npm run build && npm run build:app) \
    && (cd worker && worker-build --release) \
    && (cd app && cargo build --all-targets --locked && cargo test --locked --no-run)

# Run the suites so the log shows the image works, without letting a failure abort the build.
RUN (timeout 1800 cargo test --workspace --locked || echo "WARNING: cargo test reported failures") \
    && (timeout 900 bash supabase/tests/run.sh || echo "WARNING: supabase/tests reported failures") \
    && (cd web && timeout 900 npm test || echo "WARNING: web tests reported failures") \
    && (timeout 1800 bash scripts/e2e.sh || echo "WARNING: scripts/e2e.sh reported failures")

# Everything is fetched. From here on cargo and npm must not wait for a registry they cannot reach.
ENV CARGO_NET_OFFLINE=true npm_config_offline=true
