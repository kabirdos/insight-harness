#!/usr/bin/env python3
"""
Codex Harness Profile Extractor (Phase 1 — standalone profile).

Reads OpenAI Codex CLI's local data under ``~/.codex/`` and emits a standalone
HTML profile plus a per-tool JSON island shaped ``{"tool": "codex", ...}``.
Phase 1 stops short of publishing or touching the insightharness.com schema —
it de-risks the parser and the privacy scrub against real Codex data before any
cross-tool contract is committed (Phases 2/3 own storage and the agent payload).

Only locally-visible Codex CLI usage is captured (mobile / web / Cowork are
server-side and invisible); the rendered profile states this limit plainly.

SAFETY (filled in by later units):
- A POSITIVE read-allowlist governs which rollout fields are ever read
  (``payload.type``, ``timestamp``, ``payload.info.total_token_usage``, the
  unwrapped inner command binary, and whitelisted skill/plugin metadata).
- An emit-time two-tier secret gate scans the serialized output before writing.
- ``pii_scrub`` is identity-only (NOT a secret detector), so the read-allowlist
  is the primary control and the secret gate is the backstop.

This module mirrors ``extract.py`` for the Claude harness. The reusable PURE
helpers below are imported directly (verified: no import side effects); the
path-/shape-coupled parts are reimplemented for Codex's real data shapes.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

# --- Reused PURE helpers (verified safe to import: no module side effects) ---
# Identity-only scrubber + its error type (NOT a secret detector — see R7).
from pii_scrub import SanitizeError, detect_pii, scrub  # noqa: F401
# Skill frontmatter / description / showcase pipeline + the safe command-name
# normalizer + the agent-tool surface detector. All operate on already-read
# values or on directory presence; none of them assume Claude-specific paths.
from extract import (  # noqa: F401
    build_skill_meta,
    derive_description_from_body,
    detect_agent_tools,
    extract_safe_command_name,
    parse_skill_frontmatter,
    _finalize_showcase,
    _read_hero_image,
    _read_raw_readme,
    _truncate_to_bytes,
)

# --- Codex roots (single-rooted + shallow, mirroring extract.py's CLAUDE_DIR) -
# These are module globals so tests can `patch.object(codex_extract, "CODEX_DIR",
# tmp)` and re-derive — see Phase-1 plan Unit 1 ("Patterns to follow").
CODEX_DIR = Path.home() / ".codex"
CODEX_SESSIONS_DIR = CODEX_DIR / "sessions"
CODEX_SKILLS_DIR = CODEX_DIR / "skills"
CODEX_RULES_DIR = CODEX_DIR / "rules"
CODEX_CONFIG_PATH = CODEX_DIR / "config.toml"
CODEX_VERSION_PATH = CODEX_DIR / "version.json"

# Output lives under the Codex root (the 2026-04-09 prototype precedent), so
# Codex artifacts stay inside the Codex namespace rather than squatting in
# Claude's ~/.claude/usage-data/.
CODEX_USAGE_DATA_DIR = CODEX_DIR / "usage-data"

VERSION = "0.1.0"  # Phase 1 scaffold — bump as units land.


def build_arg_parser() -> argparse.ArgumentParser:
    """Argparse skeleton for the Codex extractor.

    Mirrors extract.py's `--include-skills` / `--no-include-skills` pair
    (default: include). Later units add token / safety / publish flags.
    """
    parser = argparse.ArgumentParser(
        prog="codex_extract",
        description=(
            "Extract a standalone OpenAI Codex CLI harness profile from "
            "~/.codex/ (Phase 1: local generation only, no publish)."
        ),
    )
    parser.add_argument(
        "--include-skills",
        dest="include_skills",
        action="store_true",
        default=True,
        help="Include per-skill showcase content (README + hero). Default: on.",
    )
    parser.add_argument(
        "--no-include-skills",
        dest="include_skills",
        action="store_false",
        help="Opt out of per-skill showcase content for a smaller profile.",
    )
    return parser


def generate_html(data: dict) -> str:
    """Render the Codex HTML profile.

    SCAFFOLD ONLY — Unit 5 reimplements this with the real Codex section set,
    the JSON island (``{"tool": "codex", ...}``), the thin-tool caveat, and the
    honest local-only limit. For now it emits a minimal, valid HTML document so
    the output contract (a written file + a printed path) can be exercised end
    to end.
    """
    generated_at = datetime.now().isoformat(timespec="seconds")
    include_skills = bool(data.get("include_skills", True))
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head><meta charset=\"utf-8\">"
        "<title>Codex Harness Profile</title></head>\n"
        "<body>\n"
        "  <h1>Codex Harness Profile</h1>\n"
        f"  <p>Generated {generated_at} by codex_extract {VERSION}.</p>\n"
        "  <p>Local Codex CLI usage only — mobile, web, and Cowork activity is "
        "server-side and not captured here.</p>\n"
        f"  <!-- include_skills={include_skills} -->\n"
        "  <!-- scaffold: sections filled in by later units -->\n"
        "</body>\n"
        "</html>\n"
    )


def main(argv=None) -> int:
    """Output contract: write the HTML profile under ``~/.codex/usage-data/``
    and print its absolute path as the FINAL stdout line.

    Returns an exit code (0 on success / clean no-data exit). The
    ``__main__`` guard calls ``sys.exit(main())``.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # Edge case: absent ~/.codex → clean "no Codex data" exit, no crash.
    # Read CODEX_DIR at call time (not a precomputed constant) so a test that
    # patches the global is reflected in the message.
    if not CODEX_DIR.exists():
        print(
            f"No Codex data found at {CODEX_DIR} — nothing to extract.",
            file=sys.stderr,
        )
        return 0

    print("Generating Codex profile (scaffold)...", file=sys.stderr)
    data = {"include_skills": args.include_skills}
    html = generate_html(data)

    CODEX_USAGE_DATA_DIR.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    report_path = (CODEX_USAGE_DATA_DIR / f"{date_str}-codex-harness.html").resolve()
    report_path.write_text(html, encoding="utf-8")

    # Final stdout line = the canonical report path (the output contract the
    # skill instructions read).
    print(str(report_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
