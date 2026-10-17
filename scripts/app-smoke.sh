#!/usr/bin/env bash
# Smoke test of the desktop app in a virtual display: builds the web client
# for the app and the Tauri shell, then drives the real webview over
# WebDriver (app/smoke/smoke.mjs).
#
#   bash scripts/app-smoke.sh
#
# Needs what the app build needs (see app/README.md) plus Xvfb,
# WebKitWebDriver (package webkit2gtk-driver) and tauri-driver.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"

(cd "$root/web" && npm ci --no-fund --no-audit && npm run build:app)
(cd "$root/app" && cargo build)

# The app saves files to the XDG downloads folder: point it at a temporary one.
downloads="$(mktemp -d)"
mkdir -p "$downloads/config"
echo "XDG_DOWNLOAD_DIR=\"$downloads\"" > "$downloads/config/user-dirs.dirs"
export XDG_CONFIG_HOME="$downloads/config"
display=":${SIGYLO_DISPLAY:-99}"
Xvfb "$display" -screen 0 1280x1024x24 >/dev/null 2>&1 &
xvfb_pid=$!
DISPLAY="$display" tauri-driver --port 4444 >/dev/null 2>&1 &
driver_pid=$!
trap 'kill "$driver_pid" "$xvfb_pid" 2>/dev/null || true; rm -rf "$downloads"' EXIT
for _ in $(seq 1 50); do curl -sf -o /dev/null http://127.0.0.1:4444/status && break; sleep 0.2; done

DISPLAY="$display" node "$root/app/smoke/smoke.mjs" "$root/app/target/debug/sigylo-app" "$downloads"
