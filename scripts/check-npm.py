"""Fails when npm could fetch or run code that no lock file pins.

Fetching wrangler on the fly (with the yes flag of npx, or a version after
its name) resolves its whole tree afresh on every run and lets its install
scripts run next to the Cloudflare token (CLAUDE.md §6).
Wrangler is instead an exact dev dependency of worker/, installed with
`npm ci --ignore-scripts` from worker/package-lock.json and called as
`./node_modules/.bin/wrangler` (or `npx --no-install wrangler`).

    python3 -I scripts/check-npm.py --lock worker/package-lock.json \
        .github/workflows/*.y*ml scripts/*

Each lock file must exist, and every package in it must come from the npm
registry with a sha512 integrity. No other file may give npx its yes flag
(long or short), nor run wrangler through npx without `--no-install`.
"""

import argparse
import json
import re
import sys

REGISTRY = "https://registry.npmjs.org/"
NPX = re.compile(r"\bnpx\b(.*)")
SEPARATORS = re.compile(r"&&|\|\||[;|&()`]")


def lock_problems(path):
    try:
        with open(path, encoding="utf-8") as f:
            lock = json.load(f)
    except FileNotFoundError:
        yield f"{path}: missing"
        return
    except (OSError, ValueError) as error:
        yield f"{path}: unreadable: {error}"
        return
    packages = lock.get("packages") if isinstance(lock, dict) else None
    if not isinstance(packages, dict) or "" not in packages:
        yield f"{path}: no `packages` (lockfileVersion 2 or later)"
        return
    for name, entry in packages.items():
        if name == "":
            continue
        if not isinstance(entry, dict):
            yield f"{path}: {name}: not an object"
            continue
        if entry.get("link") is True:
            yield f"{path}: {name}: a link, not a registry package"
            continue
        resolved = entry.get("resolved")
        integrity = entry.get("integrity")
        if not isinstance(resolved, str) or not resolved.startswith(REGISTRY):
            yield f"{path}: {name}: resolved {resolved!r} is not from {REGISTRY}"
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            yield f"{path}: {name}: no sha512 integrity"


def call_problems(path):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError) as error:
        yield f"{path}: unreadable: {error}"
        return
    for number, line in enumerate(lines, 1):
        # Each command of the line on its own: one `--no-install` must not
        # cover a second npx after `&&`.
        for match in filter(None, map(NPX.search, SEPARATORS.split(line))):
            args = match.group(1).split()
            if "--yes" in args or "-y" in args:
                yield f"{path}:{number}: the yes flag lets npx fetch and run what no lock pins"
            tool = next((a for a in args if not a.startswith("-")), "")
            if tool.startswith("wrangler") and "--no-install" not in args:
                yield f"{path}:{number}: npx {tool} may fetch wrangler: use the locked ./node_modules/.bin/wrangler"


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", action="append", default=[], required=True)
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv)
    found = []
    for lock in args.lock:
        found.extend(lock_problems(lock))
    for path in args.files:
        found.extend(call_problems(path))
    for problem in found:
        print(f"::error::{problem}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
