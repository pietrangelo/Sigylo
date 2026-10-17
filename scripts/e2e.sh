#!/usr/bin/env bash
# End-to-end: the real Worker (wrangler dev / workerd) serving the built web
# client, PostgreSQL with the migrations, and Chromium driving the UI.
#
#   bash scripts/e2e.sh
#
# Needs PostgreSQL 15+ binaries, Rust with wasm32-unknown-unknown,
# wasm-bindgen-cli and worker-build at the pinned versions, Node 22.
set -euo pipefail
# Chromium writes downloads with names in the locale's charset: without UTF-8
# a file called "caffè.txt" would be saved as "download".
export LC_ALL=C.UTF-8
root="$(cd "$(dirname "$0")/.." && pwd)"
pg_bin="${SIGYLO_PG_BIN:-$(dirname "$(command -v initdb 2>/dev/null || ls -d /usr/lib/postgresql/*/bin/initdb | tail -1)")}"
port=55432

tmp="$(mktemp -d)"
as_postgres=()
if [[ "$(id -u)" == 0 ]]; then chown postgres "$tmp"; as_postgres=(runuser -u postgres --); fi
"${as_postgres[@]}" "$pg_bin/initdb" -D "$tmp/data" -U postgres -A trust >/dev/null
"${as_postgres[@]}" "$pg_bin/pg_ctl" -D "$tmp/data" -o "-p $port -k $tmp -c listen_addresses=127.0.0.1" -l "$tmp/log" -w start >/dev/null
wrangler_pid=""
cleanup() {
    [[ -n "$wrangler_pid" ]] && kill -- "-$wrangler_pid" 2>/dev/null || true
    "${as_postgres[@]}" "$pg_bin/pg_ctl" -D "$tmp/data" -m immediate stop >/dev/null || true
    rm -rf "$tmp"
}
trap cleanup EXIT

admin="postgres://postgres@127.0.0.1:$port/postgres"
for migration in "$root"/supabase/migrations/*.sql; do psql "$admin" -q -X -v ON_ERROR_STOP=1 -f "$migration"; done
psql "$admin" -q -X -c "alter role sigylo_relay login password 'relay-test-only'"

(cd "$root/web" && npm ci --no-fund --no-audit && npm run build)
# Own process group, so cleanup stops npx, wrangler and workerd together.
# R2 is simulated locally in "$tmp/state"; the suite runs the cron (purge and
# garbage collection) through wrangler's local explorer API.
(cd "$root/worker" && exec setsid npx --yes wrangler@4.151.1 dev --var DB_TLS:disable \
    --var OPAQUE_SERVER_SEED:e2e-only-not-a-secret-AAAAAAAAAAAAAAAAAAAAA \
    --persist-to "$tmp/state" --ip 127.0.0.1 --port 8787 >"$tmp/wrangler.log" 2>&1) &
wrangler_pid=$!
ready=""
for _ in $(seq 1 300); do
    if curl -sf -o /dev/null http://127.0.0.1:8787/; then ready=1; break; fi
    kill -0 "$wrangler_pid" 2>/dev/null || break
    sleep 1
done
if [[ -z "$ready" ]]; then
    echo "wrangler dev did not start:" >&2
    tail -40 "$tmp/wrangler.log" >&2
    exit 1
fi

if ! (cd "$root/web" && SIGYLO_E2E_DATABASE_URL="$admin" SIGYLO_E2E_STATE="$tmp/state" npx playwright test "$@"); then
    echo "--- wrangler dev log (last 60 lines) ---" >&2
    tail -60 "$tmp/wrangler.log" >&2
    exit 1
fi
