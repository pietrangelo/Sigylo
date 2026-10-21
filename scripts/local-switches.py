"""Fails when a wrangler.toml carries a switch meant for `wrangler dev` only.

DB_TLS and VAULT_PLACEMENT (CLAUDE.md §3-ter) turn off TLS to the database and
the EU placement of the vault. scripts/e2e.sh passes them on the command line;
they must never be in the file that ships. The file is read with a TOML parser,
so no spelling of the key slips through: indented, quoted, dotted or in any
table.

    python3 scripts/local-switches.py worker/wrangler.toml
"""

import sys
import tomllib

SWITCHES = {"DB_TLS", "VAULT_PLACEMENT"}


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
        print(f"::error file={file}::{', '.join(keys)}: DB_TLS and VAULT_PLACEMENT are for wrangler dev only")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
