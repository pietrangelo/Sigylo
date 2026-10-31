"""Fails when a workflow uses an action or a reusable workflow that is not
pinned to a commit.

A moved tag of a third-party action would run next to the Cloudflare token
and the page about to be published (CLAUDE.md §6). The workflows are read
with a YAML parser, so no spelling slips through: quoted keys, flow mappings,
anchors, `.yml` and `.yaml` files, and `uses` on a job (a reusable workflow)
as well as on a step. Allowed:

    owner/repo[/path]@<40 hex>        a commit
    ./path                            an action or workflow of this repository
    docker://image@sha256:<64 hex>    an image by digest

    python3 -I scripts/check-pins.py .github/workflows
"""

import pathlib
import re
import sys

import yaml

COMMIT = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[^@\s]+)?@[0-9a-f]{40}")
DIGEST = re.compile(r"docker://[^@\s]+@sha256:[0-9a-f]{64}")


def pinned(uses):
    if not isinstance(uses, str):
        return False
    if uses.startswith("./"):
        return ".." not in uses.split("/")
    return bool(COMMIT.fullmatch(uses) or DIGEST.fullmatch(uses))


def problems(name, workflow):
    """Every `uses` of the workflow that is not pinned, or a shape it cannot check."""
    if not isinstance(workflow, dict):
        yield f"{name}: not a mapping"
        return
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        yield f"{name}: no jobs mapping"
        return
    for job_name, job in jobs.items():
        where = f"{name}: jobs.{job_name}"
        if not isinstance(job, dict):
            yield f"{where}: not a mapping"
            continue
        if "uses" in job and not pinned(job["uses"]):
            yield f"{where}.uses: {job['uses']!r}"
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            yield f"{where}.steps: not a list"
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                yield f"{where}.steps[{index}]: not a mapping"
            elif "uses" in step and not pinned(step["uses"]):
                yield f"{where}.steps[{index}].uses: {step['uses']!r}"


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
        found.extend(problems(str(path), workflow))
    for problem in found:
        print(f"::error::{problem}: pin it to a full commit SHA, with the tag in a comment")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
