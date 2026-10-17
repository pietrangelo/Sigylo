#!/usr/bin/env bash
# Applies the migrations to a throwaway PostgreSQL, runs the SQL privilege
# tests, then the Rust vault contract tests against it.
#
#   bash supabase/tests/run.sh            # needs PostgreSQL 15+ binaries (initdb, pg_ctl)
#   SIGYLO_PG_BIN=/usr/lib/postgresql/16/bin bash supabase/tests/run.sh
#
# With SIGYLO_TEST_DATABASE_URL already set (CI service container), the
# throwaway cluster is skipped and that database is used instead.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
pg_bin="${SIGYLO_PG_BIN:-$(dirname "$(command -v initdb 2>/dev/null || ls -d /usr/lib/postgresql/*/bin/initdb | tail -1)")}"

if [[ -z "${SIGYLO_TEST_DATABASE_URL:-}" ]]; then
    tmp="$(mktemp -d)"
    port=55432
    as_postgres=()
    if [[ "$(id -u)" == 0 ]]; then
        chown postgres "$tmp"
        as_postgres=(runuser -u postgres --)
    fi
    "${as_postgres[@]}" "$pg_bin/initdb" -D "$tmp/data" -U postgres -A trust >/dev/null
    "${as_postgres[@]}" "$pg_bin/pg_ctl" -D "$tmp/data" -o "-p $port -k $tmp -c listen_addresses=127.0.0.1" -l "$tmp/log" -w start >/dev/null
    trap '"${as_postgres[@]}" "$pg_bin/pg_ctl" -D "$tmp/data" -m immediate stop >/dev/null; rm -rf "$tmp"' EXIT
    export SIGYLO_TEST_DATABASE_URL="postgres://postgres@127.0.0.1:$port/postgres"
fi

psql_admin=(psql "$SIGYLO_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -q -X)
for migration in "$root"/supabase/migrations/*.sql; do
    "${psql_admin[@]}" -f "$migration"
done
# Locally the relay role logs in with a throwaway password; in production the
# operator sets its own (see README).
"${psql_admin[@]}" -c "alter role sigylo_relay login password 'relay-test-only'"

relay_url="$(sed -E 's#://[^@]+@#://sigylo_relay:relay-test-only@#' <<<"$SIGYLO_TEST_DATABASE_URL")"
export SIGYLO_TEST_RELAY_URL="$relay_url"

echo "== SQL privilege tests"
"${psql_admin[@]}" -f "$root/supabase/tests/privileges.sql"
psql "$relay_url" -v ON_ERROR_STOP=1 -q -X -f "$root/supabase/tests/relay_cannot_read.sql"

echo "== Vault contract tests (Rust, against this database)"
(cd "$root" && cargo test -p custody-adapters --test postgres_vault -- --test-threads=1)
