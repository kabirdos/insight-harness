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


def detect_pii(content_for_owner_scan: str = "") -> list[tuple[re.Pattern[str], str]]:
    """Build the ordered list of (compiled_regex, replacement) pairs.

    Order matters: longer/more-specific patterns must run before shorter
    overlapping ones (e.g. `/Users/<u>/` before `/Users/<u>` so we don't
    leave a stray slash).

    Pass `content_for_owner_scan` (typically the concatenated README text
    across all skills) to enable GitHub-owner detection — any owner that
    appears in `github.com/<owner>/` URLs gets a replacement, even when the
    owner doesn't match the local OS username (common case: local user
    `craig` but repos under org `kabirdos`). Without this, owner-bearing
    URLs leak.
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

    # GitHub owner scan — pulls owners from the actual content rather than
    # only matching the OS username. Mirrors detectGithubOwners() in the JS
    # reference. Skips owners we've already scrubbed via the username rules.
    if content_for_owner_scan:
        for owner in _detect_github_owners(content_for_owner_scan):
            if owner == username:
                continue
            rules.append((f"github.com/{owner}/", "github.com/<your-username>/"))
            rules.append((f"githubusercontent.com/{owner}/", "githubusercontent.com/<your-username>/"))
            rules.append((f"raw.githubusercontent.com/{owner}/", "raw.githubusercontent.com/<your-username>/"))

    if git_email:
        rules.append((git_email, "<your-email>"))

    if git_name:
        # Full name first, then first-name + possessive forms (matches JS
        # reference). Order matters: full name, then "First's", "First'",
        # then bare "First" — so possessives don't get partially eaten.
        rules.append((git_name, "<your-name>"))
        first = git_name.split()[0] if git_name.split() else ""
        if first and len(first) > 2:
            rules.append((f"{first}'s", "<your-name>'s"))
            rules.append((f"{first}'", "<your-name>'"))
            rules.append((first, "<your-name>"))

    # Compile and dedupe (preserve first occurrence so order is stable)
    seen: set[str] = set()
    compiled: list[tuple[re.Pattern[str], str]] = []
    for needle, repl in rules:
        if not needle or len(needle) < 2 or needle in seen:
            continue
        seen.add(needle)
        compiled.append((re.compile(re.escape(needle)), repl))
    return compiled


_GITHUB_OWNER_RE = re.compile(
    r"github(?:usercontent)?\.com/([a-zA-Z0-9][a-zA-Z0-9-]{0,38})/"
)


def _detect_github_owners(text: str) -> list[str]:
    """Return distinct GitHub owners that appear in github.com/<owner>/ URLs.

    Mirrors detectGithubOwners() in skill-showcase/scripts/build-showcase.js.
    Skips the placeholder we use for replacement so re-scrubbed text is a no-op.
    """
    owners: list[str] = []
    seen: set[str] = set()
    for match in _GITHUB_OWNER_RE.finditer(text):
        owner = match.group(1)
        if owner == "<your-username>":
            continue
        if owner in seen:
            continue
        seen.add(owner)
        owners.append(owner)
    return owners


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
