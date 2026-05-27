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
import json
import sys
from collections import Counter
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


# --- Rollout parsing (Unit 2) ------------------------------------------------
# Codex stores each session as one ``rollout-<ts>-<id>.jsonl`` under
# ``sessions/YYYY/MM/DD/`` (verified against real ~/.codex). Two on-disk shapes
# coexist (R9):
#   * 2026 "payload envelope":  {"timestamp", "type", "payload": {"type", ...}}
#   * 2025 "legacy flat":       {"timestamp", "type", ...}  (no payload, no
#                                token_count records)
# Every file counts as ONE session toward session_count + timespan regardless of
# format; token / tool detail is read ONLY from the payload-envelope shape.
#
# POSITIVE read-allowlist (R5): the ONLY fields ever read off a record are
#   - the envelope ``timestamp`` (for timespan),
#   - ``payload.type`` (to route),
#   - ``payload.info.total_token_usage.total_tokens`` on token_count records,
#   - the unwrapped inner command BINARY (first token only) on shell calls.
# Content carriers are never touched: message.content, reasoning.*,
# agent_message.message, task_complete.last_agent_message, update_plan,
# spawn_agent.message, *_output.output, apply_patch.*, web_search_call.action,
# session_meta instruction/nickname/summary/git fields, text, thread_name,
# user_message. Nothing else is read, so they cannot leak by construction.

# Shell-runner wrappers to strip so we classify the INNER command, not the
# runner. A leading runner followed by a -c/-lc flag means "run this string".
_SHELL_RUNNERS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
_RUNNER_FLAGS = {"-c", "-lc", "-ic", "-l"}


def _unwrap_command(arguments: str):
    """Return the first-token command name for ONE function_call's arguments.

    ``arguments`` is a JSON string. Two real shapes (verified against ~/.codex):
      * ``shell``        -> {"command": ["bash", "-lc", "<full cmd>"], ...}
      * ``exec_command`` -> {"cmd": "<full cmd string>", ...}

    For the list shape we strip a leading shell-runner wrapper (``bash``/``sh``/
    ``zsh`` ... followed by ``-lc``/``-c``) and feed the inner command STRING to
    the reused ``extract_safe_command_name`` normalizer. For the string shape we
    feed it directly. Either way we return ONLY the first program token (e.g.
    ``curl``), never the full command — the secret-bearing arg yields ``curl``
    and the ``sk-...`` token never escapes this function.
    """
    if not arguments:
        return None
    try:
        args = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(args, dict):
        return None

    command = args.get("command")
    inner = None
    if isinstance(command, list):
        toks = [t for t in command if isinstance(t, str)]
        # Strip a leading "<runner> <flag>" wrapper so we read the real command.
        if (
            len(toks) >= 3
            and toks[0] in _SHELL_RUNNERS
            and toks[1] in _RUNNER_FLAGS
        ):
            inner = toks[2]
        elif toks:
            # Bare argv list (no shell wrapper): the binary is the first token.
            inner = toks[0]
    elif isinstance(command, str):
        inner = command
    elif isinstance(args.get("cmd"), str):
        # exec_command shape: a raw command string under "cmd".
        inner = args["cmd"]

    if not inner:
        return None
    # extract_safe_command_name returns ONLY the program name (plus a strict
    # node test-runner second token), never an arbitrary argument.
    return extract_safe_command_name(inner)


def _parse_envelope_timestamp(value):
    """Parse a rollout envelope timestamp into a naive ISO datetime, or None.

    Codex writes RFC3339 with a trailing ``Z``; ``fromisoformat`` on older
    Pythons rejects ``Z``, so normalize it. Timestamps are compared/sorted as
    strings downstream after normalizing to ``isoformat(timespec="seconds")``.
    """
    if not isinstance(value, str) or not value:
        return None
    raw = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    # Drop tz so first/last render uniformly; Codex sessions are wall-clock.
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt


def parse_rollouts(cutoff: datetime | None = None) -> dict:
    """Parse every Codex rollout under ``CODEX_SESSIONS_DIR`` (recursively).

    Returns a privacy-safe aggregate dict:
      ``session_count``      every rollout file (both formats) counts as one.
      ``total_tokens``       SUM over sessions of each session's MAX cumulative
                             ``total_tokens`` (R3 — cumulative-per-session, so we
                             take the last/max within a session, not a per-record
                             sum which would inflate ~Nx).
      ``command_names``      Counter of first-token command names (R6).
      ``first_session`` /    ISO timespan bounds across ALL counted sessions.
      ``last_session``
      ``payload_format_sessions`` / ``legacy_format_sessions`` — format split.

    Reads CODEX_SESSIONS_DIR at call time so a test ``patch.object`` is honored.
    """
    sessions_dir = CODEX_SESSIONS_DIR

    session_count = 0
    payload_sessions = 0
    legacy_sessions = 0
    total_tokens = 0
    command_names: Counter = Counter()
    all_session_timestamps: list[datetime] = []

    if not sessions_dir.exists():
        return _empty_rollout_result()

    for rollout in sorted(sessions_dir.rglob("rollout-*.jsonl")):
        if not rollout.is_file():
            continue
        try:
            if cutoff is not None:
                mtime = datetime.fromtimestamp(rollout.stat().st_mtime)
                if mtime < cutoff:
                    continue
        except OSError:
            continue

        # Per-session accumulators. token_max is the MAX cumulative total within
        # THIS session; we add only that single value to the global total.
        session_token_max = 0
        is_payload_format = False
        session_timestamps: list[datetime] = []

        try:
            with open(rollout, "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(record, dict):
                        continue

                    # Timespan: read ONLY the envelope timestamp (allowlisted).
                    ts = _parse_envelope_timestamp(record.get("timestamp"))
                    if ts is not None:
                        session_timestamps.append(ts)

                    payload = record.get("payload")
                    if not isinstance(payload, dict):
                        # Legacy flat record (or a payload-less envelope): nothing
                        # token/tool-related is read here by design.
                        continue
                    is_payload_format = True
                    ptype = payload.get("type")

                    if ptype == "token_count":
                        # R3: cumulative within session — keep the running max.
                        info = payload.get("info")
                        if not isinstance(info, dict):
                            continue  # info==null record → skip, no NoneType crash
                        usage = info.get("total_token_usage")
                        if not isinstance(usage, dict):
                            continue
                        total = usage.get("total_tokens")
                        if isinstance(total, int) and total > session_token_max:
                            session_token_max = total

                    elif ptype == "function_call":
                        # R6: emit only the first-token command name.
                        name = _unwrap_command(payload.get("arguments"))
                        if name:
                            command_names[name] += 1
        except OSError:
            continue

        # Every readable rollout is a session toward count + timespan (R9).
        session_count += 1
        if is_payload_format:
            payload_sessions += 1
        else:
            legacy_sessions += 1
        total_tokens += session_token_max
        all_session_timestamps.extend(session_timestamps)

    if session_count == 0:
        return _empty_rollout_result()

    first_session = None
    last_session = None
    if all_session_timestamps:
        first_session = min(all_session_timestamps).isoformat(timespec="seconds")
        last_session = max(all_session_timestamps).isoformat(timespec="seconds")

    return {
        "session_count": session_count,
        "payload_format_sessions": payload_sessions,
        "legacy_format_sessions": legacy_sessions,
        "total_tokens": total_tokens,
        "command_names": dict(command_names.most_common(30)),
        "first_session": first_session,
        "last_session": last_session,
    }


def _empty_rollout_result() -> dict:
    """The zero-data shape (absent/empty sessions dir) — same keys, no crash."""
    return {
        "session_count": 0,
        "payload_format_sessions": 0,
        "legacy_format_sessions": 0,
        "total_tokens": 0,
        "command_names": {},
        "first_session": None,
        "last_session": None,
    }


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
