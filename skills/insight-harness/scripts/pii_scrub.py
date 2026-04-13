"""
PII scrubbing for skill showcase README content.

Detects identifying information from git config and the local environment,
then applies regex replacements with structural invariant checks (newline
count, code-fence count) to catch any regex that accidentally eats or
inserts content across a markdown boundary.

Reference implementation: skills/skill-showcase/scripts/build-showcase.js in
the claude-toolkit repo. The Python port keeps the rules listed in plan
docs/plans/2026-04-12-002 and the two structural invariants from the JS
version. Drift between the two is a real risk — see SanitizeError.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


class SanitizeError(Exception):
    """Raised when a scrub() call damages markdown structure (newlines or fences).

    A failure here means a replacement regex is buggy, not a user-facing issue.
    The caller should treat this as a hard failure (non-zero exit) so the bug
    surfaces immediately instead of silently corrupting downstream output.
    """


def _git_config(key: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "config", key],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        ).strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def _local_username() -> str:
    user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    if user:
        return user
    home = os.environ.get("HOME") or ""
    if home:
        return Path(home).name
    return ""


def detect_pii() -> list[tuple[re.Pattern[str], str]]:
    """Build the ordered list of (compiled_regex, replacement) pairs.

    Order matters: longer/more-specific patterns must run before shorter
    overlapping ones (e.g. `/Users/<u>/` before `/Users/<u>` so we don't
    leave a stray slash).
    """
    rules: list[tuple[str, str]] = []

    git_name = _git_config("user.name")
    git_email = _git_config("user.email")
    username = _local_username()

    if username:
        # Path replacements — trailing-slash variant first so it wins
        rules.append((f"/Users/{username}/", "~/"))
        rules.append((f"/Users/{username}", "~"))
        rules.append((f"/home/{username}/", "~/"))
        rules.append((f"/home/{username}", "~"))
        # GitHub URLs (longest-prefix host first)
        rules.append((f"raw.githubusercontent.com/{username}/", "raw.githubusercontent.com/<your-username>/"))
        rules.append((f"githubusercontent.com/{username}/", "githubusercontent.com/<your-username>/"))
        rules.append((f"github.com/{username}/", "github.com/<your-username>/"))
        # @-mentions tied to local username
        rules.append((f"@{username}", "@<your-username>"))

    if git_email:
        rules.append((git_email, "<your-email>"))

    if git_name:
        # Replace full name first, then bare first-name
        rules.append((git_name, "<your-name>"))

    # Compile and dedupe (preserve first occurrence so order is stable)
    seen: set[str] = set()
    compiled: list[tuple[re.Pattern[str], str]] = []
    for needle, repl in rules:
        if not needle or len(needle) < 2 or needle in seen:
            continue
        seen.add(needle)
        compiled.append((re.compile(re.escape(needle)), repl))
    return compiled


_FENCE_RE = re.compile(r"^```", re.MULTILINE)


def _newline_count(s: str) -> int:
    return s.count("\n")


def _fence_count(s: str) -> int:
    return len(_FENCE_RE.findall(s))


def scrub(text: str, rules: list[tuple[re.Pattern[str], str]] | None = None, context: str = "<unknown>") -> str:
    """Apply PII replacements to markdown text and verify structural invariants.

    Pass `rules` to reuse a precomputed ruleset across many calls (avoids
    re-shelling to git for every skill). Pass `context` for clearer error
    messages — typically the skill name or file path.

    Raises SanitizeError if newline count or fence count changes.
    """
    if rules is None:
        rules = detect_pii()
    if not text:
        return text

    in_newlines = _newline_count(text)
    in_fences = _fence_count(text)

    out = text
    for pattern, repl in rules:
        out = pattern.sub(repl, out)

    out_newlines = _newline_count(out)
    if out_newlines != in_newlines:
        raise SanitizeError(
            f"scrub() changed newline count in {context}: {in_newlines} -> {out_newlines}. "
            f"A replacement regex ate or inserted a newline."
        )

    out_fences = _fence_count(out)
    if out_fences != in_fences:
        raise SanitizeError(
            f"scrub() changed fence count in {context}: {in_fences} -> {out_fences}. "
            f"A replacement regex damaged a ``` fence line."
        )

    return out
