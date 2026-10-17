#!/usr/bin/env bash
# Compiles the Sealing shell to Wasm and generates its JS bindings into
# src/lib/wasm (git-ignored). Needs the wasm32-unknown-unknown target and
# wasm-bindgen-cli at the exact version pinned in crates/sigylo-wasm.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cargo build --manifest-path "$root/Cargo.toml" -p sigylo-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir "$root/web/src/lib/wasm" \
  "$root/target/wasm32-unknown-unknown/release/sigylo_wasm.wasm"
