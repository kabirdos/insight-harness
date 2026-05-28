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
import re
import sys
import tomllib
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


# --- Skill inventory (Unit 3) ------------------------------------------------
# Codex stores user-level skills as ``~/.codex/skills/<name>/SKILL.md`` (verified
# against the real tree). Unlike the Claude extractor there is no plugin-skill
# cache walk and no flat ``*.md`` commands dir here — Codex plugins are declared
# in config.toml (see ``extract_plugins_from_config``), not on disk as skills.
#
# D4 — INVENTORY ONLY: Codex loads skills into context; there is no reliable
# per-skill invocation signal the way Claude's session logs carry Skill-tool
# calls. So we emit ONLY ``{name, description, installPointer}`` and deliberately
# attach NO ``calls`` / usage-count field. The Claude ``extract_skill_inventory``
# is ``SKILLS_DIR``-coupled and also threads runtime call counts; we mirror its
# two-pass owner-aware scrub structure but reimplement the walk for Codex roots.
#
# The two-pass approach (collect raw READMEs → build owner-aware scrub rules from
# the whole corpus → finalize) is load-bearing for privacy: a third-party skill
# whose README links ``github.com/<upstream-owner>/...`` must have that owner
# scrubbed to a placeholder even though it never matches the local OS username,
# and the LOCAL identity must NOT be injected in place of the upstream owner.


# Known token PREFIXES (R7 tier-a). ``pii_scrub`` is identity-only — it does NOT
# strip credentials — so a README that embeds a live token would otherwise carry
# it straight into the emitted skill excerpt. The full two-tier emit gate is
# Unit 6's job over the serialized profile; here we apply the unambiguous-prefix
# redaction directly to the README excerpt the inventory emits so a third-party
# README can never leak a credential through the showcase pipeline.
_KNOWN_SECRET_RE = re.compile(
    r"(?:Bearer\s+)?(?:sk-|ghp_|AKIA)[A-Za-z0-9_\-]+"
)
_SECRET_PLACEHOLDER = "<redacted-secret>"


def _redact_known_secrets(text: str | None) -> str | None:
    """Replace unambiguous token shapes (``sk-``/``Bearer ``/``ghp_``/``AKIA``)
    in a free-text excerpt with a placeholder. Identity scrubbing (``pii_scrub``)
    does not cover credentials, so this is the credential backstop for emitted
    README text. Returns the input unchanged when there is nothing to redact."""
    if not text:
        return text
    return _KNOWN_SECRET_RE.sub(_SECRET_PLACEHOLDER, text)


def extract_skill_inventory_codex(include_showcase: bool = True) -> list[dict]:
    """Walk Codex user skills and return an inventory-only list.

    Returns a list of ``{name, description, installPointer}`` dicts. NO ``calls``
    or usage-count field is emitted (D4 — Codex has no reliable invocation
    signal). Skills whose frontmatter declares ``repo: private`` or ``repo: none``
    are excluded ENTIRELY (not even listed), exactly as the Claude extractor
    treats them.

    When ``include_showcase`` is True, performs the Claude-style two-pass scrub:
      1. Pre-scan: read every candidate README raw (unscrubbed).
      2. Build owner-aware scrub rules from the concatenated corpus so any
         ``github.com/<owner>/`` owner is scrubbed even when it differs from the
         local OS username (no mis-attribution rewrite to the local identity).
      3. Finalize: scrub + hero + per-skill cap; body-derive a blank description.

    Reads ``CODEX_SKILLS_DIR`` at call time so a test ``patch.object`` is honored.
    """
    skills_dir = CODEX_SKILLS_DIR
    if not skills_dir.exists():
        return []

    skills: list[dict] = []
    # (meta, skill_md_path, raw_readme) staged for the second (scrub) pass.
    pending: list[tuple[dict, Path, str]] = []

    def _stage(meta, sp):
        if not meta:
            return
        # Privacy: repo: private/none excludes the skill entirely — it is never
        # listed (mirrors the Claude extractor's hard exclusion). Inventory-only
        # output has no runtime-call pathway to re-leak it through.
        repo = (meta.get("repo") or "").strip().lower()
        if repo in ("private", "none"):
            return
        # The install pointer for a Codex user skill is its directory name (the
        # name a user would `codex skills add`/reference it by). Codex has no
        # plugin-skill cache, so there is no namespaced "<plugin>:<skill>" form.
        install_pointer = sp.parent.name if sp.stem == "SKILL" else sp.stem
        if include_showcase:
            pending.append((meta, sp, _read_raw_readme(sp)))
        else:
            skills.append(_inventory_entry(meta, install_pointer))

    for sp in sorted(skills_dir.glob("*/SKILL.md")):
        _stage(parse_skill_frontmatter(sp), sp)

    if include_showcase:
        # Owner-aware rules built from the FULL corpus (so a third-party owner in
        # any one README is scrubbed everywhere, and the local identity is never
        # substituted in for an upstream owner).
        combined = "\n".join(raw or "" for _, _, raw in pending)
        scrub_rules = detect_pii(content_for_owner_scan=combined)
        for meta, sp, raw_readme in pending:
            install_pointer = sp.parent.name if sp.stem == "SKILL" else sp.stem
            showcase = _finalize_showcase(raw_readme, sp, scrub_rules)
            # Identity scrub happened inside _finalize_showcase; layer the
            # credential redaction on top (pii_scrub is identity-only, R7).
            readme_md = _redact_known_secrets(showcase["readme_markdown"])
            entry = _inventory_entry(meta, install_pointer)
            # Blank frontmatter description → body-derive from the scrubbed body.
            if not entry["description"] and readme_md:
                entry["description"] = derive_description_from_body(readme_md)
            entry["readmeMarkdown"] = readme_md
            entry["heroBase64"] = showcase["hero_base64"]
            entry["heroMimeType"] = showcase["hero_mime_type"]
            skills.append(entry)

    return skills


def _inventory_entry(meta: dict, install_pointer: str) -> dict:
    """Build the inventory-only entry: name, description, installPointer.

    Deliberately omits any ``calls`` / usage-count field (D4). The name falls
    back to the install pointer (directory stem) when frontmatter omits it.
    """
    return {
        "name": meta.get("name") or install_pointer,
        "description": meta.get("description") or "",
        "installPointer": install_pointer,
    }


# --- Plugins from config.toml (Unit 3, R10) ----------------------------------
# Codex's plugin model is config-declared, NOT a ``~/.codex/plugins`` dir walk.
# The real config.toml uses quoted, marketplace-qualified section keys:
#   [plugins."github@openai-curated"]
#   enabled = true
# We emit ``{name, enabled}`` where ``name`` is the section key (the part inside
# the quotes, e.g. ``github@openai-curated``) and ``enabled`` is the boolean
# beneath it (defaulting to False when absent). We never read marketplace source
# paths, connector UUIDs, or any other config section here.


def _load_config_toml() -> dict:
    """Parse ``CODEX_CONFIG_PATH`` (TOML) into a dict, or {} on any failure.

    Python 3.11+ ships ``tomllib`` in the stdlib; this repo targets 3.14, so no
    third-party TOML dependency is needed. Read at call time so test patches of
    ``CODEX_CONFIG_PATH`` are honored.
    """
    path = CODEX_CONFIG_PATH
    if not path.is_file():
        return {}
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def extract_plugins_from_config() -> list[dict]:
    """Return the Codex plugin inventory from config.toml ``[plugins.*]`` (R10).

    Each entry is ``{name, enabled}``. ``name`` is the plugin section key (e.g.
    ``github@openai-curated``); ``enabled`` is the boolean under it (False when
    absent or non-boolean). Sourced from config — not a directory walk — because
    Codex declares plugins in config.toml. Returns [] when there is no config or
    no ``[plugins]`` table.
    """
    config = _load_config_toml()
    plugins_table = config.get("plugins")
    if not isinstance(plugins_table, dict):
        return []

    entries: list[dict] = []
    for name, body in plugins_table.items():
        enabled = False
        if isinstance(body, dict):
            raw = body.get("enabled")
            if isinstance(raw, bool):
                enabled = raw
        entries.append({"name": name, "enabled": enabled})
    # Stable order so output is deterministic across runs.
    entries.sort(key=lambda e: e["name"])
    return entries


# --- Safety posture (Unit 4, R4/R8) ------------------------------------------
# Codex's safety/automation posture lives in two places (verified against the
# real ~/.codex):
#
#   config.toml
#     approvals_reviewer = "user"                     # top-level enum
#     [projects."/Users/<me>/Coding/proj"]            # ← ABSOLUTE-PATH section
#     trust_level = "trusted"                          #    key is a LEAK; read
#                                                      #    only the VALUE below.
#     [apps.connector_<uuid>.tools.<tool>]            # ← connector UUID section
#     approval_mode = "approve"                        #    key is a LEAK + would
#                                                      #    trip the Unit-6 entropy
#                                                      #    gate; read only VALUE.
#   rules/*.rules
#     prefix_rule(pattern=["git", "add", "<path>"], decision="allow")
#       ↑ a STRUCTURED DSL, not a shell string. Later pattern elements routinely
#         carry absolute home-dir paths AND Bearer tokens (the real default.rules
#         has `["/bin/zsh","-lc","curl ... Authorization: Bearer $(...auth.json)"]`).
#         We extract pattern[0] (the binary) ONLY and discard EVERYTHING after it
#         plus the decision. extract_safe_command_name is a bash-STRING tokenizer
#         and is the wrong tool here, so we do not feed rule lines to it.
#
# The emitted shape is enums + binaries only:
#   {rulesAllowlist:[binaries], approvalsReviewer, approvalModes:[enums],
#    trustLevels:[enums]}
# Never the project-path section keys, never the connector UUID section key.

# Matches the `pattern=[ ... ]` list literal inside a prefix_rule(...) call. We
# capture the bracketed body and JSON-parse it so we read element [0] structurally
# rather than string-slicing (which could accidentally surface a later element).
# Non-greedy up to the first closing bracket; rule patterns are single-line in the
# real DSL (one prefix_rule per line).
_PREFIX_RULE_PATTERN_RE = re.compile(r"pattern\s*=\s*(\[[^\]]*\])")


def _rule_binary(line: str):
    """Extract ``pattern[0]`` (the binary) from ONE ``prefix_rule(...)`` line.

    Returns the first pattern element as a string, or ``None`` if the line is not
    a well-formed ``prefix_rule`` with a non-empty string pattern[0]. EVERY later
    pattern element and the ``decision`` are discarded and never read — this is
    the load-bearing privacy control, because later elements carry absolute paths
    and Bearer tokens in the real rules file.

    We only honor ``prefix_rule`` (allow-list rules); ``deny_rule`` and other DSL
    forms are ignored so we never surface a binary that was actually denied.
    """
    stripped = line.strip()
    if not stripped.startswith("prefix_rule"):
        return None
    m = _PREFIX_RULE_PATTERN_RE.search(stripped)
    if not m:
        return None
    try:
        # The DSL uses JSON-compatible array syntax (double-quoted strings), so
        # json.loads parses the bracketed body directly.
        pattern = json.loads(m.group(1))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(pattern, list) or not pattern:
        return None
    first = pattern[0]
    # pattern[0] must be a non-empty string. It MAY be an absolute binary path
    # (e.g. "/bin/zsh") — that is the program, not a leaked argument — but it must
    # be a single token with no embedded whitespace (a multi-token pattern[0]
    # would mean a malformed rule, not a real binary).
    if not isinstance(first, str):
        return None
    first = first.strip()
    if not first or any(c.isspace() for c in first):
        return None
    return first


def parse_rules_allowlist() -> list[dict]:
    """Parse every ``*.rules`` file under ``CODEX_RULES_DIR`` and return the
    deduped sorted list of allow-rule BINARIES (``pattern[0]`` only).

    Returns ``[]`` when the rules dir is absent/empty. Reads the dir at call time
    so a test ``patch.object`` is honored. Only ``pattern[0]`` of each
    ``prefix_rule`` is ever materialized — later elements (paths/tokens) and the
    ``decision`` are dropped inside ``_rule_binary`` and never reach this list.
    """
    rules_dir = CODEX_RULES_DIR
    if not rules_dir.exists():
        return []

    binaries: set[str] = set()
    for rule_file in sorted(rules_dir.glob("*.rules")):
        if not rule_file.is_file():
            continue
        try:
            with open(rule_file, "r", errors="replace") as fh:
                for line in fh:
                    binary = _rule_binary(line)
                    if binary:
                        binaries.add(binary)
        except OSError:
            continue
    return sorted(binaries)


def _collect_approval_modes(apps_table) -> list[str]:
    """Walk an ``[apps.*]`` config subtree and collect ``approval_mode`` VALUES.

    Reads ONLY the ``approval_mode`` leaf value wherever it appears in the nested
    ``[apps.connector_<uuid>.tools.<tool>]`` structure. The connector-UUID section
    KEY and the tool name are never read or emitted (they are an identity leak and
    the UUID would trip the Unit-6 entropy gate). Returns a deduped sorted list.
    """
    modes: set[str] = set()

    def _walk(node):
        if not isinstance(node, dict):
            return
        for key, val in node.items():
            if key == "approval_mode" and isinstance(val, str) and val:
                modes.add(val)
            elif isinstance(val, dict):
                # Recurse into nested tables (connector_<uuid>, .tools, .<tool>)
                # WITHOUT ever reading `key` itself — the UUID stays unread.
                _walk(val)

    _walk(apps_table)
    return sorted(modes)


def _collect_trust_levels(projects_table) -> list[str]:
    """Collect distinct ``trust_level`` VALUES from the ``[projects.*]`` subtree.

    The ``[projects."<absolute-path>"]`` section KEYS are absolute home-dir /
    project-name leaks and are NEVER read — we iterate only ``.values()`` and read
    the ``trust_level`` enum beneath each. Returns a deduped sorted list, so the
    project COUNT and per-project shape are not revealed either.
    """
    levels: set[str] = set()
    if not isinstance(projects_table, dict):
        return []
    # NOTE: iterate values() only — the keys are the absolute paths we must drop.
    for body in projects_table.values():
        if isinstance(body, dict):
            level = body.get("trust_level")
            if isinstance(level, str) and level:
                levels.add(level)
    return sorted(levels)


def extract_safety_posture() -> dict:
    """Produce the Codex 'Safety & Automation' data — enums + binaries only (R4).

    Returns::

        {
          "rulesAllowlist":   [binaries],   # pattern[0] of each prefix_rule
          "approvalsReviewer": "<enum>"|None,  # top-level approvals_reviewer
          "approvalModes":    [enums],       # per-app approval_mode VALUES
          "trustLevels":      [enums],       # per-project trust_level VALUES
        }

    NEVER emits the ``[projects."<path>"]`` section keys (home-dir/project-name
    leaks) and NEVER reads the ``[apps.connector_<uuid>]`` section key (the
    connector UUID — only the ``approval_mode`` value beneath it). Degrades to
    empty structures / ``None`` when config or rules are absent (the renderer
    shows "none configured").
    """
    config = _load_config_toml()

    reviewer = config.get("approvals_reviewer")
    if not isinstance(reviewer, str) or not reviewer:
        reviewer = None

    approval_modes = _collect_approval_modes(config.get("apps"))
    trust_levels = _collect_trust_levels(config.get("projects"))
    rules_allowlist = parse_rules_allowlist()

    return {
        "rulesAllowlist": rules_allowlist,
        "approvalsReviewer": reviewer,
        "approvalModes": approval_modes,
        "trustLevels": trust_levels,
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
