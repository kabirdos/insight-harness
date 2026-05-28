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
import html as _html_lib
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

# Function-call ``name`` values that route to the command extractor (R6) rather
# than counting as a generic tool. ``shell`` and ``exec_command`` are the two
# real-Codex shapes whose ``arguments`` carry a structured command list/string.
_SHELL_TOOL_NAMES = {"shell", "exec_command", "container.exec"}

# MCP/connector tool names take the shape ``mcp__<server>__<tool>`` (verified
# against real ~/.codex sessions and the cross-tool MCP convention). Bucketing
# them to a single ``mcp:*`` label is R8 — emitting verbatim would reveal the
# connected server (Gmail/Slack/etc.) and any embedded connector UUID, which is
# an identity leak. The bucket is intentionally generic ("this user has SOME
# MCP traffic"), not per-server.
_MCP_BUCKET = "mcp:*"


def _normalize_tool_name(name: str) -> str | None:
    """Return a privacy-safe tool-name label for the toolUsage counter.

    * ``mcp__<server>__<tool>`` (any number of segments) → ``mcp:*`` (R8 —
      never reveal connector identity / UUID).
    * Empty / non-string → ``None`` (caller skips).
    * Otherwise the raw name is returned. Codex's native tool names (e.g.
      ``apply_patch``, ``update_plan``, ``view_image``, ``spawn_agent``) are
      generic CLI primitives, not user identifiers, so they pass through.
    """
    if not isinstance(name, str) or not name:
        return None
    if name.startswith("mcp__"):
        return _MCP_BUCKET
    return name


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
    # Generic function_call tool counter (non-shell), with MCP names bucketed
    # at counting time so the verbatim ``mcp__<server>__<tool>`` form is never
    # materialized into the aggregate (R8).
    tool_usage: Counter = Counter()
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
                        fname = payload.get("name")
                        if isinstance(fname, str) and fname in _SHELL_TOOL_NAMES:
                            # R6: emit only the first-token command name.
                            name = _unwrap_command(payload.get("arguments"))
                            if name:
                                command_names[name] += 1
                        else:
                            # Generic tool call (apply_patch / update_plan /
                            # mcp__*/etc.). Bucket MCP identities at counting
                            # time so they cannot leak from the Counter.
                            bucketed = _normalize_tool_name(fname)
                            if bucketed:
                                tool_usage[bucketed] += 1
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
        "tool_usage": dict(tool_usage.most_common(30)),
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
        "tool_usage": {},
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


# --- Profile assembly (Unit 5) ----------------------------------------------
# Unit 5 wires Units 2/3/4 together into a Codex-shaped HTML profile and a
# tool-only JSON island. Key invariants:
#
#  * ENVELOPE (R1): the only committed envelope key is ``tool``. We deliberately
#    do NOT emit ``schema_version``/``generated_at`` — those belong to Phase 2's
#    cross-tool contract once it also retrofits the Claude island + DB column.
#  * ISLAND ⊆ RENDERED (R11): every key in the JSON island must correspond to
#    data the HTML actually renders. ``ALLOWED_ISLAND_KEYS`` is the constant
#    set; ``_assert_island_subset_of_rendered`` enforces it at emit time so an
#    island-only field cannot silently ship a leak.
#  * IDENTITY SCRUBBING (R8): no ``repository_url``, ``commit_hash``, ``branch``,
#    or ``cwd`` is read or emitted (the rollout parser's positive read-allowlist
#    handles this by construction); MCP tool names are bucketed at counting time
#    (see ``_normalize_tool_name``).
#  * ACTIVITY FLOOR (R12): below the floor the renderer emits a SLIM SHELL with
#    a prominent "local CLI data only — this person may use Codex more
#    elsewhere" caveat. Above the floor we render the full profile but ALWAYS
#    still include the local-only limit statement.
#  * NO HARDCODED AUTHOR CLAIMS (Phase-0 F6): every prose claim is derived from
#    data, not a baked-in narrative. Sections with no data say so explicitly.

# Activity-floor threshold. The real ~/.codex has ~hundreds of rollouts for a
# heavy user; below ~5 sessions the profile is mostly empty (no meaningful
# token total, no command pattern), so we render the slim shell instead of
# pretending it's a full profile. A token-only fallback handles users with
# few but heavy sessions (a single big session can clear 200k tokens).
ACTIVITY_FLOOR_SESSIONS = 5
ACTIVITY_FLOOR_TOKENS = 50_000

# The committed island schema. Every key here must correspond to a section the
# HTML actually renders (R11). The set is checked in two directions:
#   * island_keys ⊆ rendered_sections (no hidden field)
#   * island_keys are stable so Phase 2 can plan its merge without surprise.
ALLOWED_ISLAND_KEYS = frozenset({
    "tool",
    "stats",
    "toolUsage",
    "cliTools",
    "skillInventory",
    "plugins",
    "safety",
    "workflowData",
    "workSurfaces",
    "localOnly",
})


def _he(value) -> str:
    """HTML-escape ``value`` (coerced to str). Centralized so every section
    helper goes through the same escaper and no raw string slips into the DOM."""
    return _html_lib.escape("" if value is None else str(value), quote=True)


def _meets_activity_floor(stats: dict) -> bool:
    """True iff the Codex slice has enough signal to render as a full profile.

    R12 — below the floor we render a slim shell + caveat instead of a fake
    full profile. The OR-of-two-floors (sessions or tokens) catches both a
    long-tail user (many small sessions) and a power user with a few huge
    sessions.
    """
    sessions = stats.get("sessionCount") or 0
    tokens = stats.get("totalTokens") or 0
    return (sessions >= ACTIVITY_FLOOR_SESSIONS) or (tokens >= ACTIVITY_FLOOR_TOKENS)


def assemble_profile(include_skills: bool = True) -> dict:
    """Gather every Unit-2/3/4 output into a single profile dict.

    Returns a dict keyed by the same names as ``ALLOWED_ISLAND_KEYS`` plus a
    ``meta`` block (generation timestamp, version) used only by the HTML header
    (not emitted in the island). Reads CODEX_* globals at call time so a test
    ``patch.object`` repoints the whole tree.
    """
    rollouts = parse_rollouts()
    skills = extract_skill_inventory_codex(include_showcase=include_skills)
    plugins = extract_plugins_from_config()
    safety = extract_safety_posture()

    # R13 — desktop presence via the shared detector. Surface ONLY the Codex
    # entries (CLI + desktop) so other tools' presence isn't a side channel.
    agent_tools = detect_agent_tools()
    desktop_presence = [
        {
            "tool": t.get("tool"),
            "present": bool(t.get("present")),
            "lastActive": t.get("lastActive"),
        }
        for t in agent_tools
        if isinstance(t.get("tool"), str) and t["tool"].startswith("Codex")
    ]

    timespan = None
    first = rollouts.get("first_session")
    last = rollouts.get("last_session")
    if first and last:
        timespan = {"first": first, "last": last}

    stats = {
        "totalTokens": rollouts.get("total_tokens", 0),
        "sessionCount": rollouts.get("session_count", 0),
        "payloadFormatSessions": rollouts.get("payload_format_sessions", 0),
        "legacyFormatSessions": rollouts.get("legacy_format_sessions", 0),
        "timespan": timespan,
    }

    # The HTML's "CLI Commands" panel renders this directly.
    cli_tools = dict(rollouts.get("command_names", {}))
    tool_usage = dict(rollouts.get("tool_usage", {}))

    # Workflow Phases: Codex's rollout parser does not currently classify a
    # phase signal (the cost would require reading content carriers, which the
    # positive read-allowlist forbids). Surface an empty structure — the HTML
    # renders the honest "no phase signal collected" message rather than
    # fabricating phases. Phase 2 may add a phase-from-tool-sequence heuristic.
    workflow_data = {"phaseSequence": [], "phaseTransitions": {}}

    return {
        "meta": {
            "generatedAt": datetime.now().isoformat(timespec="seconds"),
            "version": VERSION,
        },
        "stats": stats,
        "toolUsage": tool_usage,
        "cliTools": cli_tools,
        "skillInventory": skills,
        "plugins": plugins,
        "safety": safety,
        "workflowData": workflow_data,
        "workSurfaces": {"desktopPresence": desktop_presence},
    }


def build_island(profile: dict) -> dict:
    """Produce the ``{tool: "codex", ...}`` JSON island envelope.

    R1 — envelope key is ``tool`` ONLY (no ``schema_version`` /
    ``generated_at``). R11 — every key must be in ``ALLOWED_ISLAND_KEYS`` and
    correspond to a rendered section.
    """
    island = {
        "tool": "codex",
        "stats": profile["stats"],
        "toolUsage": profile["toolUsage"],
        "cliTools": profile["cliTools"],
        "skillInventory": profile["skillInventory"],
        "plugins": profile["plugins"],
        "safety": profile["safety"],
        "workflowData": profile["workflowData"],
        "workSurfaces": profile["workSurfaces"],
        # Always-true flag (R12): this is local-CLI-only data, period.
        "localOnly": True,
    }
    extra = set(island.keys()) - ALLOWED_ISLAND_KEYS
    if extra:
        # Defense in depth: the constant set is the contract. A typo or a new
        # field added without updating ALLOWED_ISLAND_KEYS would otherwise
        # silently ship.
        raise AssertionError(
            f"island contains keys not in ALLOWED_ISLAND_KEYS: {sorted(extra)}"
        )
    return island


# Rendered-section labels for the R11 ⊆ check. Each label corresponds to one
# of the section helpers below; the renderer collects which sections actually
# emitted content and that set must be a superset of the island's keys minus
# the envelope-level ``tool`` / ``localOnly`` markers (which are rendered as
# the page header and the always-on caveat, not their own sections).
_ISLAND_KEY_TO_RENDERED_SECTION = {
    "stats": "Tokens",
    "toolUsage": "Tool Usage",
    "cliTools": "CLI Commands",
    "skillInventory": "Skills",
    "plugins": "Plugins",
    "safety": "Safety & Automation",
    "workflowData": "Workflow Phases",
    "workSurfaces": "Work Surfaces",
}


def _assert_island_subset_of_rendered(island: dict, rendered_sections: set) -> None:
    """R11 — every island data key must be a section the HTML renders.

    Skips the envelope-level markers (``tool``, ``localOnly``) which are
    rendered as the page header/caveat, not as their own ``<section>``. Raises
    AssertionError if any island data key has no matching rendered section so a
    leak via an island-only field is impossible.
    """
    envelope_only = {"tool", "localOnly"}
    for key in island.keys():
        if key in envelope_only:
            continue
        section = _ISLAND_KEY_TO_RENDERED_SECTION.get(key)
        if section is None:
            raise AssertionError(
                f"island key {key!r} has no _ISLAND_KEY_TO_RENDERED_SECTION mapping"
            )
        if section not in rendered_sections:
            raise AssertionError(
                f"island key {key!r} maps to unrendered section {section!r}"
            )


# --- HTML section helpers ----------------------------------------------------
# Each helper takes the relevant slice of the profile and returns (section_html,
# section_label). The label is appended to rendered_sections for the R11 check
# even when the section is empty — the HTML always renders the SECTION SHELL so
# the island/HTML correspondence does not depend on data presence.


# The always-on local-only caveat — rendered both above and below the activity
# floor. This is the load-bearing honest-limit statement; the prose is derived
# (no hardcoded author claims) so it never makes a quantitative promise we
# can't back from data.
_LOCAL_ONLY_CAVEAT = (
    "Local Codex CLI usage only — this profile reflects what is recorded "
    "under <code>~/.codex/</code> on this machine. Mobile, web, and Cowork "
    "activity is server-side and not captured here. This person may use "
    "Codex more elsewhere."
)


def _render_thin_tool_caveat() -> str:
    """The slim-shell caveat for users below the activity floor (R12).

    Stated as "local CLI data only" without claiming the user is inactive —
    they may simply be using Codex elsewhere (mobile / web / Cowork). Prose
    intentionally avoids any author-specific quantitative claim (F6).
    """
    return (
        '<section class="caveat thin-tool"><h2>Limited local Codex signal</h2>'
        '<p><strong>Local CLI data only — this person may use Codex more '
        "elsewhere.</strong> The Codex CLI activity recorded under "
        "<code>~/.codex/</code> on this machine is below the threshold for a "
        "full profile. Mobile, web, and Cowork sessions are server-side and "
        "not captured here.</p></section>"
    )


def _render_header(profile: dict, full_profile: bool) -> str:
    """Page header + the always-on local-only caveat (R12)."""
    meta = profile["meta"]
    return (
        '<header class="codex-profile-header">'
        "<h1>Codex Harness Profile</h1>"
        f'<p class="meta">Generated {_he(meta["generatedAt"])} '
        f"by codex_extract {_he(meta['version'])}.</p>"
        f'<p class="local-only-limit">{_LOCAL_ONLY_CAVEAT}</p>'
        "</header>"
    )


def _render_tokens_section(stats: dict) -> tuple[str, str]:
    """Tokens section — total + session count + timespan + format split.

    Prose is derived from the numbers, not hardcoded. A 0-token slice says so
    rather than implying activity that isn't in the data (F6).
    """
    total = stats.get("totalTokens") or 0
    sessions = stats.get("sessionCount") or 0
    payload_n = stats.get("payloadFormatSessions") or 0
    legacy_n = stats.get("legacyFormatSessions") or 0
    timespan = stats.get("timespan")

    timespan_html = ""
    if timespan and timespan.get("first") and timespan.get("last"):
        timespan_html = (
            f'<p class="meta">Sessions span <strong>{_he(timespan["first"])}'
            f'</strong> to <strong>{_he(timespan["last"])}</strong>.</p>'
        )

    # Honest-limit detail: token totals come from the current payload-envelope
    # format only. Legacy sessions still COUNT (R9) but contribute no tokens.
    detail = ""
    if legacy_n > 0:
        detail = (
            f'<p class="meta">Of {_he(sessions)} sessions, '
            f'{_he(payload_n)} use the current payload format (token detail '
            f'available) and {_he(legacy_n)} use the legacy format '
            "(counted toward session totals; no per-session token detail).</p>"
        )

    body = (
        '<section class="codex-tokens">'
        "<h2>Tokens</h2>"
        f'<div class="kv-row"><span>Total tokens (cumulative-per-session, '
        f'summed across sessions):</span><strong>{_he(total):>}</strong></div>'
        f'<div class="kv-row"><span>Sessions counted:</span>'
        f'<strong>{_he(sessions)}</strong></div>'
        + timespan_html
        + detail
        + "</section>"
    )
    return body, "Tokens"


def _render_tool_usage_section(tool_usage: dict) -> tuple[str, str]:
    """Tool Usage — generic function_call tally (apply_patch, update_plan,
    etc.). MCP tool names are bucketed at counting time, so any ``mcp:*`` row
    here is the entire MCP-traffic bucket, not a server-specific identifier."""
    if not tool_usage:
        rows = '<p class="empty">No tool-call signal in this slice.</p>'
    else:
        items = sorted(tool_usage.items(), key=lambda kv: (-kv[1], kv[0]))
        rows = "".join(
            f'<div class="kv-row"><span class="mono">{_he(name)}</span>'
            f'<strong>{_he(count)}</strong></div>'
            for name, count in items
        )
    return (
        '<section class="codex-tool-usage"><h2>Tool Usage</h2>' + rows + "</section>",
        "Tool Usage",
    )


def _render_cli_tools_section(cli_tools: dict) -> tuple[str, str]:
    """CLI Commands — first-token of unwrapped shell commands (R6). The full
    command string is never emitted; only the binary name lands here."""
    if not cli_tools:
        rows = '<p class="empty">No CLI command activity recorded.</p>'
    else:
        items = sorted(cli_tools.items(), key=lambda kv: (-kv[1], kv[0]))
        rows = "".join(
            f'<div class="kv-row"><span class="mono">{_he(name)}</span>'
            f'<strong>{_he(count)}</strong></div>'
            for name, count in items
        )
    return (
        '<section class="codex-cli-tools"><h2>CLI Commands</h2>' + rows + "</section>",
        "CLI Commands",
    )


def _render_skills_section(skills: list) -> tuple[str, str]:
    """Skills — INVENTORY ONLY (D4): name + description + installPointer. No
    usage counts (Codex has no reliable per-skill invocation signal)."""
    if not skills:
        rows = '<p class="empty">No skills declared under <code>~/.codex/skills/</code>.</p>'
    else:
        rows = "".join(
            f'<div class="skill-entry">'
            f'<h3>{_he(s.get("name") or s.get("installPointer") or "")}</h3>'
            f'<p>{_he(s.get("description") or "")}</p>'
            f'<p class="meta">Install pointer: '
            f'<code>{_he(s.get("installPointer") or "")}</code></p>'
            "</div>"
            for s in skills
        )
    return (
        '<section class="codex-skills"><h2>Skills</h2>'
        '<p class="meta">Inventory only — Codex loads skills into context; '
        "there is no reliable per-skill invocation signal at this layer.</p>"
        + rows
        + "</section>",
        "Skills",
    )


def _render_plugins_section(plugins: list) -> tuple[str, str]:
    """Plugins — name + enabled flag from config.toml ``[plugins.*]`` (R10)."""
    if not plugins:
        rows = '<p class="empty">No plugins declared in <code>config.toml</code>.</p>'
    else:
        rows = "".join(
            f'<div class="kv-row"><span class="mono">{_he(p.get("name"))}</span>'
            f'<span class="badge {"on" if p.get("enabled") else "off"}">'
            f'{"enabled" if p.get("enabled") else "disabled"}</span></div>'
            for p in plugins
        )
    return (
        '<section class="codex-plugins"><h2>Plugins</h2>' + rows + "</section>",
        "Plugins",
    )


def _render_safety_section(safety: dict) -> tuple[str, str]:
    """Safety & Automation — enums + binaries only (R4)."""
    reviewer = safety.get("approvalsReviewer")
    approval_modes = safety.get("approvalModes") or []
    trust_levels = safety.get("trustLevels") or []
    rules = safety.get("rulesAllowlist") or []

    reviewer_html = (
        f'<div class="kv-row"><span>Approvals reviewer:</span>'
        f'<strong>{_he(reviewer)}</strong></div>'
        if reviewer
        else '<div class="kv-row"><span>Approvals reviewer:</span>'
        '<span class="meta">none configured</span></div>'
    )

    def _enum_row(label, values):
        if not values:
            return (
                f'<div class="kv-row"><span>{_he(label)}:</span>'
                f'<span class="meta">none configured</span></div>'
            )
        chips = "".join(
            f'<span class="chip">{_he(v)}</span>' for v in values
        )
        return (
            f'<div class="kv-row"><span>{_he(label)}:</span>'
            f'<span class="chips">{chips}</span></div>'
        )

    rules_html = (
        '<p class="empty">No rules allowlist configured.</p>'
        if not rules
        else (
            '<h3>Allowlisted rule binaries</h3><div class="chips">'
            + "".join(f'<span class="chip mono">{_he(b)}</span>' for b in rules)
            + "</div>"
        )
    )

    return (
        '<section class="codex-safety"><h2>Safety &amp; Automation</h2>'
        + reviewer_html
        + _enum_row("Approval modes", approval_modes)
        + _enum_row("Trust levels", trust_levels)
        + rules_html
        + "</section>",
        "Safety & Automation",
    )


def _render_workflow_phases_section(workflow: dict) -> tuple[str, str]:
    """Workflow Phases — honest empty state when no phase signal is available."""
    transitions = workflow.get("phaseTransitions") or {}
    if not transitions:
        body = (
            '<p class="empty">No phase signal collected — Codex Phase 1 does '
            "not infer phases from content (content carriers are never read).</p>"
        )
    else:
        items = sorted(transitions.items(), key=lambda kv: (-kv[1], kv[0]))
        body = "".join(
            f'<div class="kv-row"><span class="mono">{_he(k)}</span>'
            f'<strong>{_he(v)}</strong></div>'
            for k, v in items
        )
    return (
        '<section class="codex-workflow"><h2>Workflow Phases</h2>' + body + "</section>",
        "Workflow Phases",
    )


def _render_work_surfaces_section(work_surfaces: dict) -> tuple[str, str]:
    """Work Surfaces — Codex CLI + desktop presence (R13). Directory presence
    + mtime ONLY; contents are never read."""
    presence = work_surfaces.get("desktopPresence") or []
    if not presence:
        rows = '<p class="empty">No Codex surfaces detected.</p>'
    else:
        rows = "".join(
            f'<div class="kv-row"><span>{_he(t.get("tool"))}</span>'
            f'<span class="badge {"on" if t.get("present") else "off"}">'
            f'{"present" if t.get("present") else "absent"}</span>'
            + (
                f'<span class="meta">last active {_he(t.get("lastActive"))}</span>'
                if t.get("present") and t.get("lastActive")
                else ""
            )
            + "</div>"
            for t in presence
        )
    return (
        '<section class="codex-work-surfaces"><h2>Work Surfaces</h2>'
        '<p class="meta">Directory presence + mtime only; contents are not '
        "read.</p>" + rows + "</section>",
        "Work Surfaces",
    )


def _render_footer(profile: dict) -> str:
    meta = profile["meta"]
    return (
        '<footer class="codex-profile-footer">'
        f'<p class="meta">Generated by codex_extract {_he(meta["version"])} '
        f'at {_he(meta["generatedAt"])}. Local-CLI scope; no upload.</p>'
        "</footer>"
    )


def _render_island_script(island: dict) -> str:
    """Serialize the island and embed it in a ``<script type="application/json"
    id="harness-data">…</script>`` tag, mirroring extract.py's pattern.

    The mandatory ``</script>`` escape prevents a serialized field from
    breaking out of the script element — same defense as the Claude extractor
    (see ``extract.py`` lines 2572-2574)."""
    serialized = json.dumps(island, separators=(",", ":"))
    serialized = serialized.replace("</script>", r"<\/script>")
    return (
        '<script type="application/json" id="harness-data">'
        + serialized
        + "</script>"
    )


_CSS = """
:root { --ink:#1a1a1a; --muted:#666; --bg:#f8f7f4; --card:#fff;
  --accent:#1e3a5f; --green:#2d6a4f; --amber:#b45309; --border:#e5e7eb; }
* { box-sizing:border-box; }
body { margin:0; font:16px/1.5 system-ui,-apple-system,sans-serif;
  background:var(--bg); color:var(--ink); padding:2rem; }
.codex-profile { max-width:880px; margin:0 auto; }
header.codex-profile-header { background:var(--card); padding:1.5rem;
  border:1px solid var(--border); border-radius:8px; margin-bottom:1.5rem; }
header.codex-profile-header h1 { margin:0 0 0.5rem 0; }
.local-only-limit { background:#fef3c7; border-left:4px solid var(--amber);
  padding:0.75rem 1rem; margin:0.75rem 0 0 0; }
section { background:var(--card); padding:1.25rem; border:1px solid var(--border);
  border-radius:8px; margin-bottom:1rem; }
section h2 { margin:0 0 0.75rem 0; font-size:1.15rem; }
.caveat.thin-tool { background:#fef3c7; border-color:var(--amber); }
.kv-row { display:flex; justify-content:space-between; gap:1rem;
  padding:0.35rem 0; border-bottom:1px dashed var(--border); }
.kv-row:last-child { border-bottom:none; }
.meta { color:var(--muted); font-size:0.9rem; margin:0.25rem 0; }
.empty { color:var(--muted); font-style:italic; }
.mono { font-family:"Source Code Pro",monospace; }
.chips, .tags { display:flex; gap:0.35rem; flex-wrap:wrap; }
.chip { background:#eef2f5; border-radius:4px; padding:0.15rem 0.5rem;
  font-size:0.85rem; }
.badge { font-size:0.8rem; padding:0.15rem 0.5rem; border-radius:4px; }
.badge.on { background:#ecfdf5; color:var(--green); }
.badge.off { background:#f3f4f6; color:var(--muted); }
.skill-entry { padding:0.5rem 0; border-bottom:1px solid var(--border); }
.skill-entry:last-child { border-bottom:none; }
footer.codex-profile-footer { margin-top:1.5rem; text-align:center; }
"""


def render_html(profile: dict, island: dict) -> str:
    """Render the full Codex HTML profile + the embedded JSON island.

    R12 — below the activity floor we emit a SLIM SHELL with the thin-tool
    caveat and the local-only limit, NOT the full section set. Above the floor
    we emit every section helper (which renders its own empty-state when its
    slice has no data). Either way the island always carries the full key set
    so a consumer's parser doesn't have two shapes to handle — the slim shell's
    sections are merely visually de-emphasized in the page.
    """
    full = _meets_activity_floor(profile["stats"])

    rendered_sections: set[str] = set()
    sections_html: list[str] = []

    if not full:
        # Slim shell — caveat first, then a minimal Stats section so the user
        # sees what we DID record, but no Tool/CLI/Skills/Safety detail beyond
        # the section shells (which still render their empty states).
        sections_html.append(_render_thin_tool_caveat())

    # Always render every section shell so the island ⊆ rendered invariant
    # holds regardless of activity level. Empty sections render an honest
    # "no signal" message; this is the F6 guard (no hardcoded claims).
    for renderer, key in (
        (_render_tokens_section, "stats"),
        (_render_tool_usage_section, "toolUsage"),
        (_render_cli_tools_section, "cliTools"),
        (_render_skills_section, "skillInventory"),
        (_render_plugins_section, "plugins"),
        (_render_safety_section, "safety"),
        (_render_workflow_phases_section, "workflowData"),
        (_render_work_surfaces_section, "workSurfaces"),
    ):
        html_part, label = renderer(profile[key])
        sections_html.append(html_part)
        rendered_sections.add(label)

    # R11 — enforce the subset relationship BEFORE serializing the island into
    # the page. A failure here is a programming error, not a user-data issue.
    _assert_island_subset_of_rendered(island, rendered_sections)

    body_inner = (
        _render_header(profile, full_profile=full)
        + "".join(sections_html)
        + _render_footer(profile)
    )

    island_script = _render_island_script(island)

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        '<head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        "<title>Codex Harness Profile</title>"
        f"<style>{_CSS}</style>"
        "</head>\n"
        '<body><div class="codex-profile">'
        + body_inner
        + "</div>"
        + island_script
        + "</body></html>\n"
    )


# --- Unit 6 — two-tier emit-time secret gate (R7) ----------------------------
# The positive read-allowlist (R5), structured rule/command parsing (R4/R6), and
# identity scrubbing (R8) are the PRIMARY controls. This gate is the BACKSTOP:
# it scans the SERIALIZED output (HTML string + island JSON string) before any
# write hits disk. Two tiers, deliberately:
#
#   * TIER (a) — UNAMBIGUOUS TOKEN PREFIXES (`sk-`, `Bearer `, `AKIA`, `ghp_`):
#     a hit is a real credential leak with negligible false-positive risk, so
#     we FAIL LOUD — raise ``SecretLeakError``, alert stderr, exit non-zero,
#     and leave the disk untouched. ``Bearer `` is required to be followed by
#     a non-``<`` character so documentation placeholders like
#     ``Authorization: Bearer <token>`` do not trip the gate.
#
#   * TIER (b) — HIGH-ENTROPY HEURISTIC, SCOPED TO POST-ALLOWLIST TEXT:
#     a Shannon-entropy threshold over token runs of length >= 20, applied ONLY
#     to (i) the textual ``description`` / ``readmeMarkdown`` fields in the
#     island and (ii) the rendered HTML PROSE body content. Explicitly excludes
#     already-budgeted high-entropy content the plan intends to emit:
#     hero-image data URIs (the ``data:image/...;base64,...`` blob in
#     ``heroBase64``), skill ``installPointer`` / ID values, and hash/UUID-like
#     strings. A hit redacts the offending field to a placeholder and emits a
#     stderr warning; the run CONTINUES with the redacted output written.
#
# The two-tier split is load-bearing: a single fail-loud entropy gate would
# block benign harnesses (hero data URIs + skill IDs would trip it) so its
# threshold would inevitably be loosened until it missed real tokens, or it
# would block every profile from generating. Splitting unambiguous-prefix from
# entropic gives us a real abort on the cases that warrant it and a graceful
# redaction on the case where false positives are likely.


class SecretLeakError(RuntimeError):
    """Raised by the tier-a secret gate when an unambiguous credential prefix
    (``sk-``, ``Bearer ``, ``AKIA``, ``ghp_``) reaches the serialized output.

    On this error the report file is NOT written. The caller (``main``) catches
    it, emits a stderr alert, and exits non-zero — failing the run is the
    correct response because these prefixes do not produce false positives.
    """


# Tier (a) — unambiguous token-prefix patterns. ``Bearer `` requires a
# non-``<`` character after the space so documentation placeholders like
# ``Bearer <token>`` are not flagged. The other prefixes are followed by a
# typical token-character run (>= 8 chars) to avoid matching the bare prefix in
# documentation prose. These prefixes are intentionally narrow and high-signal.
_TIER_A_PATTERNS = (
    ("sk-",     re.compile(r"sk-[A-Za-z0-9_\-]{8,}")),
    ("Bearer",  re.compile(r"Bearer\s+[A-Za-z0-9_\-][A-Za-z0-9_\-\.=/+]{4,}")),
    ("AKIA",    re.compile(r"AKIA[A-Za-z0-9]{8,}")),
    ("ghp_",    re.compile(r"ghp_[A-Za-z0-9]{8,}")),
)

# Tier (b) — Shannon entropy threshold + minimum run length. Token runs are
# contiguous spans of [A-Za-z0-9_\-+/=] (covers base64, base64url, hex, and
# typical opaque-token shapes); we measure their character entropy. A length
# floor of 20 keeps short identifiers (UUIDs without dashes are 32 hex chars
# — see UUID-shape allowlist below) out of the candidate set unless they are
# truly opaque. Threshold 4.5 bits/char is what real opaque tokens hit;
# English prose runs ~2.5-3.5, hex/UUIDs ~3.5-4.0, base64 IDs ~4.5-5.5.
_TIER_B_MIN_RUN = 20
_TIER_B_ENTROPY_THRESHOLD = 4.5
_TIER_B_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")

# UUID-shape allowlist for tier (b). UUIDs with or without dashes are by
# construction high-entropy hex strings; the safety extractor already strips
# the connector-UUID SECTION KEY, and any UUID that reaches a text field is
# almost certainly a benign skill/install identifier, not a credential.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?"
    r"[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"
)
# Pure-hex runs (commit hashes, content hashes) — also benign-by-shape.
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_TIER_B_REDACTED = "<redacted-by-secret-gate>"


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits per character) of ``s``. 0.0 for an empty string.

    A high-entropy random run hits >= 4.5; English text and structured
    identifiers stay well below.
    """
    if not s:
        return 0.0
    import math
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _is_entropy_allowlisted(token: str) -> bool:
    """True iff a high-entropy token matches a shape the plan intends to emit.

    Excludes hero-image data URIs (we don't scan those at all — see the caller),
    UUIDs (with or without dashes — benign install/skill identifiers), and
    pure-hex runs (content hashes, commit hashes — already stripped from
    identity-bearing positions by R8 but harmless when they slip into a text
    field). Returns True so the caller passes the token through without
    redacting.
    """
    if _UUID_RE.match(token):
        return True
    if _HEX_RE.match(token):
        return True
    return False


def _scan_tier_a(serialized: str, source_label: str) -> None:
    """Raise ``SecretLeakError`` if the SERIALIZED output contains an
    unambiguous credential prefix. ``source_label`` is included in the error
    message so the operator can tell whether the leak was in the HTML or the
    island JSON.
    """
    for prefix, pat in _TIER_A_PATTERNS:
        m = pat.search(serialized)
        if m:
            # Truncate the matched run in the error so the leak does not echo
            # to stderr verbatim (a sensible posture even though stderr is
            # local-only). The label + prefix are enough for an operator to
            # locate the source.
            hit = m.group(0)
            snippet = hit[:8] + "..." if len(hit) > 11 else hit
            raise SecretLeakError(
                f"tier-a secret gate: {prefix!r} prefix found in {source_label} "
                f"({snippet!r}); the report was NOT written."
            )


def _redact_tier_b_in_text(text: str) -> tuple[str, list[str]]:
    """Return ``(redacted_text, hits)``. Replaces every high-entropy token run
    that is NOT shape-allowlisted with ``<redacted-by-secret-gate>``.

    Empty / None-ish input returns unchanged. ``hits`` lists the redacted-run
    summaries (length + first 4 chars) for the stderr warning; the full run is
    never returned.
    """
    if not text:
        return text, []
    hits: list[str] = []

    def _replace(match: re.Match) -> str:
        token = match.group(0)
        if _is_entropy_allowlisted(token):
            return token
        if _shannon_entropy(token) < _TIER_B_ENTROPY_THRESHOLD:
            return token
        hits.append(f"len={len(token)} starts={token[:4]!r}")
        return _TIER_B_REDACTED

    redacted = _TIER_B_TOKEN_RE.sub(_replace, text)
    return redacted, hits


def _redact_tier_b_in_island(island: dict) -> tuple[dict, list[str]]:
    """Walk the textual fields of the island and redact high-entropy tokens.

    Scope (R7 tier-b): ONLY the ``description`` and ``readmeMarkdown`` fields of
    each ``skillInventory`` entry. ``heroBase64`` (the data-URI blob), ``name``,
    ``installPointer``, and every other field — including the entire ``stats`` /
    ``safety`` / ``toolUsage`` / ``cliTools`` tree — are NOT scanned, because
    they are either intentionally high-entropy (hero image, install IDs) or
    already constrained to enums / counts / first-token binaries by upstream
    parsers.

    Returns a tuple of ``(redacted_island, hit_summaries)``. ``hit_summaries``
    is a list of human-readable strings the caller logs to stderr; it never
    contains the full unredacted token.
    """
    summaries: list[str] = []
    # Shallow-copy the dict so we don't mutate the caller's reference;
    # skillInventory is the only list we touch and we rebuild its entries.
    new_island = dict(island)
    skills = new_island.get("skillInventory")
    if not isinstance(skills, list):
        return new_island, summaries

    new_skills = []
    for entry in skills:
        if not isinstance(entry, dict):
            new_skills.append(entry)
            continue
        new_entry = dict(entry)
        for field in ("description", "readmeMarkdown"):
            val = new_entry.get(field)
            if isinstance(val, str) and val:
                redacted, hits = _redact_tier_b_in_text(val)
                if hits:
                    summaries.extend(
                        f"skill {new_entry.get('name', '?')!r}.{field}: {h}"
                        for h in hits
                    )
                    new_entry[field] = redacted
        new_skills.append(new_entry)
    new_island["skillInventory"] = new_skills
    return new_island, summaries


# Matches <script>...</script> and <style>...</style> blocks so the HTML
# prose-text scan can excise them (script bodies carry the serialized island
# JSON, which we scan separately; style bodies are CSS, not prose).
_SCRIPT_OR_STYLE_RE = re.compile(
    r"<(script|style)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL
)
# Matches an HTML tag — used to strip markup so we get the textual body.
_TAG_RE = re.compile(r"<[^>]+>")
# data:...;base64,XXXX — already-budgeted high-entropy content (hero images);
# excise before the entropy scan so the showcase pipeline's hero blob does not
# false-positive the gate.
_DATA_URI_RE = re.compile(r"data:[\w/+\-]+;base64,[A-Za-z0-9+/=]+")


def _html_prose_text(html: str) -> str:
    """Return the rough textual body of ``html`` with script/style blocks and
    data: URIs excised, then tags stripped. This is what the tier-b entropy
    scan operates on — NOT the raw HTML, because the raw HTML includes the
    embedded JSON island and intentional high-entropy hero data URIs that
    would false-positive the gate.
    """
    no_script = _SCRIPT_OR_STYLE_RE.sub(" ", html)
    no_data_uri = _DATA_URI_RE.sub(" ", no_script)
    text_only = _TAG_RE.sub(" ", no_data_uri)
    return text_only


def _scan_serialized_output(html: str, island: dict) -> tuple[str, dict, list[str]]:
    """The full two-tier emit gate. Runs over the SERIALIZED output (HTML
    string + island JSON string) BEFORE the file is written.

    Returns ``(html, island, warnings)`` — the (possibly redacted) HTML and
    island and the list of tier-b warning strings to log. Raises
    ``SecretLeakError`` if tier (a) trips on either serialization.

    Order of operations (the order matters):

      1. TIER (a) FIRST — scan the ORIGINAL serialized HTML and the ORIGINAL
         serialized island JSON for the unambiguous credential prefixes. If
         we ran tier (b) first, a high-entropy token like ``ghp_FAKE...``
         would be redacted before tier (a) saw it and the run would silently
         continue with a written file — exactly the wrong outcome. Tier (a)
         is the fail-loud signal; it must observe the raw serialization.
      2. Tier (b) redaction over the island's text fields. If anything was
         redacted, the HTML is updated so the redaction propagates to the
         page body too.
      3. Tier (b) redaction over the HTML prose text (excluding script/style
         and data URIs). Catches high-entropy runs that survived in prose
         that wasn't sourced from the island (e.g. future prose helpers).
    """
    warnings: list[str] = []

    # Step 1: tier-a on the ORIGINAL HTML and the ORIGINAL serialized island.
    # A hit here is a real credential leak — fail loud BEFORE any redaction.
    original_island_serialized = json.dumps(island, separators=(",", ":"))
    _scan_tier_a(html, "rendered HTML")
    _scan_tier_a(original_island_serialized, "island JSON")

    # Step 2: tier-b on island text fields. Propagate redactions into the
    # rendered HTML so the page reflects the field-level redaction.
    redacted_island, island_hits = _redact_tier_b_in_island(island)
    warnings.extend(island_hits)
    if island_hits:
        for entry, orig_entry in zip(redacted_island["skillInventory"], island["skillInventory"]):
            if not isinstance(entry, dict) or not isinstance(orig_entry, dict):
                continue
            for field in ("description", "readmeMarkdown"):
                orig = orig_entry.get(field)
                new = entry.get(field)
                if isinstance(orig, str) and isinstance(new, str) and orig != new:
                    # Replace the original-text fragments wherever they appear
                    # in the HTML (HTML-escaped form too, just in case).
                    html = html.replace(orig, new)
                    html = html.replace(_html_lib.escape(orig, quote=True), new)

    # Step 3: tier-b on HTML prose body (script + style + data URIs already
    # excluded). If a high-entropy token survived in prose that wasn't from
    # the island fields, replace it directly in the rendered HTML.
    prose = _html_prose_text(html)
    _, prose_hits_raw = _redact_tier_b_in_text(prose)
    if prose_hits_raw:
        # Re-derive the actual token strings so we can substitute them in the
        # HTML directly (the hit summary only carries a fingerprint).
        for match in _TIER_B_TOKEN_RE.finditer(prose):
            tok = match.group(0)
            if _is_entropy_allowlisted(tok):
                continue
            if _shannon_entropy(tok) < _TIER_B_ENTROPY_THRESHOLD:
                continue
            warnings.append(f"html prose: len={len(tok)} starts={tok[:4]!r}")
            html = html.replace(tok, _TIER_B_REDACTED)

    return html, redacted_island, warnings


def generate_profile(include_skills: bool = True) -> tuple[str, dict, dict]:
    """End-to-end: assemble, build the island, render the HTML, then run the
    Unit-6 two-tier secret gate over the SERIALIZED output.

    Returns ``(html, island, profile)`` so tests can assert against the
    structured island AND the rendered HTML without re-parsing the page. The
    returned ``html`` / ``island`` have already passed the gate (and may carry
    tier-b redactions); on a tier-a hit the gate raises ``SecretLeakError``
    and the caller (``main``) does not write the report.
    """
    profile = assemble_profile(include_skills=include_skills)
    island = build_island(profile)
    html = render_html(profile, island)
    # The gate is the LAST step before the caller writes. It runs over the
    # serialized HTML and the serialized island JSON exactly as they will hit
    # disk — there is no post-gate rewrite that could re-introduce a leak.
    html, island, warnings = _scan_serialized_output(html, island)
    for w in warnings:
        print(
            f"codex_extract: tier-b secret gate redacted a high-entropy run "
            f"({w}); the field was replaced with {_TIER_B_REDACTED!r}.",
            file=sys.stderr,
        )
    return html, island, profile


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

    print("Generating Codex profile...", file=sys.stderr)
    try:
        html, _island, _profile = generate_profile(include_skills=args.include_skills)
    except SecretLeakError as exc:
        # Tier (a) — unambiguous credential prefix reached the serialized
        # output. The disk is intentionally untouched; the operator must
        # investigate the source (a leaked token in a SKILL.md README, a
        # planted text field, or a parser regression) before retrying.
        print(
            f"codex_extract: SECRET LEAK DETECTED — {exc}",
            file=sys.stderr,
        )
        print(
            "codex_extract: the report was NOT written. Inspect the offending "
            "source (likely a ~/.codex/skills/*/README.md or a config field) "
            "and retry once the credential is removed.",
            file=sys.stderr,
        )
        return 2

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
