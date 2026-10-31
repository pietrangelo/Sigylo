"""Fails when a job that holds a credential worth stealing could run code
that no lock pins, or when a workflow grants more than it needs.

A job holds such a credential when it has an `environment` (the Cloudflare
token lives in `production`, CLAUDE.md §6), reads a secret, or may write to
the repository. Such a job builds nothing (CLAUDE.md §6, §5):

* its steps use only actions/checkout, actions/setup-node without a cache,
  and actions/download-artifact;
* its commands run no cargo, rustup, worker-build, make, pip, yarn, pnpm or
  bun; npm only as `npm ci --ignore-scripts`; npx only with `--no-install`.

Write permissions: never for a whole workflow, and for a job only where
WRITERS allows it (the job that attaches the app installers to the draft
release).

    python3 -I scripts/check-workflows.py .github/workflows
"""

import pathlib
import re
import sys

import yaml

WRITERS = {("app-release", "release"): {"contents"}}
TOKEN_JOB_ACTIONS = {"actions/checkout", "actions/setup-node", "actions/download-artifact"}
BUILDERS = re.compile(r"\b(cargo|rustup|rustc|worker-build|make|pip3?|yarn|pnpm|bunx?|tauri)\b")
NPM = re.compile(r"\bnpm\b(.*)")
NPX = re.compile(r"\bnpx\b(.*)")
SEPARATORS = re.compile(r"&&|\|\||[;|&()`]")


def writes(permissions):
    """The scopes a `permissions` value may write."""
    if permissions in ("write-all", "write"):
        return {"*"}
    if isinstance(permissions, dict):
        return {scope for scope, level in permissions.items() if level == "write"}
    return set()


def strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from strings(key)
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)


def holds_credential(job):
    return (
        "environment" in job
        or bool(writes(job.get("permissions")))
        or any("secrets." in text for text in strings(job))
    )


def command_problems(where, command):
    for number, line in enumerate(command.splitlines(), 1):
        code = line.split("#", 1)[0]
        if match := BUILDERS.search(code):
            yield f"{where}: line {number} runs {match.group(1)}"
        # Each command of the line on its own: `npm ci --ignore-scripts &&
        # npm run build` holds two.
        for part in SEPARATORS.split(code):
            if match := NPM.search(part):
                args = match.group(1).split()
                if args[:1] != ["ci"] or "--ignore-scripts" not in args:
                    yield f"{where}: line {number}: npm only as `npm ci --ignore-scripts`"
            if (match := NPX.search(part)) and "--no-install" not in match.group(1).split():
                yield f"{where}: line {number}: npx only with --no-install"


def problems(stem, workflow):
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        yield f"{stem}: no jobs mapping"
        return
    if writes(workflow.get("permissions", "write-all")):
        yield f"{stem}: the workflow-wide permissions must be read-only (and given)"
    for name, job in workflow["jobs"].items():
        where = f"{stem}: jobs.{name}"
        if not isinstance(job, dict):
            yield f"{where}: not a mapping"
            continue
        extra = writes(job.get("permissions")) - WRITERS.get((stem, name), set())
        if extra:
            yield f"{where}: may not write {', '.join(sorted(extra))}"
        if not holds_credential(job):
            continue
        if "uses" in job:
            yield f"{where}: a reusable workflow next to a credential"
        for index, step in enumerate(job.get("steps") or []):
            at = f"{where}.steps[{index}]"
            if not isinstance(step, dict):
                yield f"{at}: not a mapping"
                continue
            if "uses" in step:
                action = str(step["uses"]).split("@", 1)[0]
                if action not in TOKEN_JOB_ACTIONS:
                    yield f"{at}: {action} next to a credential"
                if action == "actions/setup-node" and "cache" in (step.get("with") or {}):
                    yield f"{at}: no npm cache next to a credential"
            if "run" in step:
                yield from command_problems(at, str(step["run"]))


def main(directory):
    files = sorted(
        path
        for path in pathlib.Path(directory).iterdir()
        if path.is_file() and path.suffix in (".yml", ".yaml")
    )
    if not files:
        print(f"::error::no workflow in {directory}")
        return 1
    found = []
    for path in files:
        try:
            workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            found.append(f"{path}: does not parse: {error}")
            continue
        found.extend(problems(path.stem, workflow))
    for problem in found:
        print(f"::error::{problem}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
