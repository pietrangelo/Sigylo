"""Fails when a wrangler.toml carries a switch meant for `wrangler dev` only,
or anything of the database the relay no longer has.

VAULT_PLACEMENT (CLAUDE.md §3-ter) turns off the EU placement of the Durable
Objects. scripts/e2e.sh passes it on the command line; it must never be in the
file that ships. DB_TLS, LEGACY_VAULT and any `hyperdrive` table belonged to
the PostgreSQL the relay used to reach through Hyperdrive: none may come back.
The file is read with a TOML parser, so no spelling of the key slips through:
indented, quoted, dotted or in any table.

    python3 scripts/local-switches.py worker/wrangler.toml
"""

import sys
import tomllib

# For wrangler dev only.
LOCAL = {"VAULT_PLACEMENT"}
# The database that is gone, and its switches.
GONE = {"DB_TLS", "LEGACY_VAULT", "hyperdrive"}
SWITCHES = LOCAL | GONE


def found(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in SWITCHES:
                yield ".".join(path + (key,))
            yield from found(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from found(value, path + (str(index),))


def main(file):
    with open(file, "rb") as f:
        config = tomllib.load(f)
    keys = list(found(config))
    if keys:
        print(
            f"::error file={file}::{', '.join(keys)}: VAULT_PLACEMENT is for wrangler dev only;"
            " DB_TLS, LEGACY_VAULT and hyperdrive belong to the database the relay no longer has"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
