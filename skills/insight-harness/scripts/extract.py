#!/usr/bin/env python3
"""
Harness Profile Extractor v2 — extracts harness metadata from Claude Code session data.

SAFETY: This script uses a field WHITELIST. It never reads tool_use.input (except
for Skill and Agent tool_use where only .input.skill / .input.subagent_type /
.input.model / .input.run_in_background are read), message text content,
tool_result content, or any field that could contain project-specific information.

For Bash commands, ONLY the first token (command name) is extracted using a safe
4-step normalizer that strips env var assignments and comment lines.
"""

import base64
import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict
from pathlib import Path

from pii_scrub import SanitizeError, detect_pii, scrub

CLAUDE_DIR = Path.home() / ".claude"
PROJECTS_DIR = CLAUDE_DIR / "projects"
SESSION_META_DIR = CLAUDE_DIR / "usage-data" / "session-meta"
SKILLS_DIR = CLAUDE_DIR / "skills"
PLUGINS_DIR = CLAUDE_DIR / "plugins"
COMMANDS_DIR = CLAUDE_DIR / "commands"
HOOKS_DIR = CLAUDE_DIR / "hooks"
AGENTS_DIR = CLAUDE_DIR / "agents"

DAYS = 30
VERSION = "2.6.0"  # Keep in sync with SKILL.md frontmatter and plugin.json
ENV_ASSIGN = re.compile(r'^([A-Z_][A-Z0-9_]*)=')


def safe_json_load(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def extract_safe_command_name(bash_command):
    """Extract ONLY the program name from a bash command, safely.

    For Node-style runners (npm, npx, pnpm, bun, yarn) we additionally look
    at the second token ONLY if it matches a hardcoded allowlist of known
    test runners. This lets us classify `npm test` as testing instead of
    implementation. The allowlist is strict — we never return an arbitrary
    second token.
    """
    if not bash_command:
        return None
    for line in bash_command.strip().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            break
    else:
        return None
    tokens = line.split()
    if not tokens:
        return None
    token = tokens[0]
    # Env var assignment — NEVER return the value
    if ENV_ASSIGN.match(token):
        remaining = tokens[1:]
        while remaining and ENV_ASSIGN.match(remaining[0]):
            remaining = remaining[1:]
        if remaining and not remaining[0].startswith('$') and not remaining[0].startswith('"'):
            # Apply the same Node-runner allowlist after env stripping
            first = remaining[0]
            if first in {"npm", "npx", "pnpm", "bun", "yarn"} and len(remaining) >= 2:
                second = remaining[1]
                if second in _NODE_TEST_SUBCOMMANDS:
                    return f"{first} {second}"
            return first
        return None  # Skip — no downstream command visible
    # Absolute path — return basename only
    if token.startswith('/'):
        clean = token.replace('\\ ', ' ')
        base = os.path.basename(clean) or None
        token = base or token
    # Node runner: look at second token only if it's a known test runner
    if token in {"npm", "npx", "pnpm", "bun", "yarn"} and len(tokens) >= 2:
        second = tokens[1]
        if second in _NODE_TEST_SUBCOMMANDS:
            return f"{token} {second}"
    return token


# Strict allowlist of Node subcommands that indicate test execution.
# ONLY these exact strings are ever returned as part of a two-token command name.
_NODE_TEST_SUBCOMMANDS = {
    "test",
    "jest",
    "vitest",
    "mocha",
    "ava",
    "cypress",
    "playwright",
    "test:unit",
    "test:integration",
    "test:e2e",
}


# ── Static Config ──────────────────────────────────────────────────────────

def extract_settings():
    settings = safe_json_load(CLAUDE_DIR / "settings.json") or {}
    hooks = []
    for event, matchers in settings.get("hooks", {}).items():
        for mb in matchers:
            matcher = mb.get("matcher", "(all)")
            for h in mb.get("hooks", []):
                cmd = h.get("command", "")
                # Extract meaningful script name from command
                # For inline bash, look for .py or known binary names
                script_name = "inline-bash"
                if cmd:
                    # Look for Python script references
                    py_match = re.search(r'(\w+\.py)', cmd)
                    if py_match:
                        script_name = py_match.group(1)
                    elif 'dcg' in cmd.split():
                        script_name = "dcg"
                    else:
                        # Take the first meaningful token
                        first = cmd.strip().split()[0] if cmd.strip() else ""
                        if first and first not in ('#', 'if', 'then', 'fi', '{', '}', 'else'):
                            script_name = Path(first).name or "inline-bash"
                hooks.append({"event": event, "matcher": matcher or "(all)", "script": script_name})
    enabled_plugins = {}
    for pid, enabled in settings.get("enabledPlugins", {}).items():
        name = pid.split("@")[0]
        marketplace = pid.split("@")[1] if "@" in pid else "unknown"
        enabled_plugins[name] = {"enabled": enabled, "marketplace": marketplace}
    return {
        "hooks": hooks,
        "enabled_plugins": enabled_plugins,
        "env_flags": list(settings.get("env", {}).keys()),
        "has_statusline": "statusLine" in settings,
        "default_permission_mode": settings.get("permissions", {}).get("defaultMode", "default"),
    }


def extract_installed_plugins():
    raw = safe_json_load(PLUGINS_DIR / "installed_plugins.json") or {}
    data = raw.get("plugins", raw) if isinstance(raw, dict) else {}
    plugins = []
    for pid, info in data.items():
        if pid == "version":
            continue
        name = pid.split("@")[0]
        marketplace = pid.split("@")[1] if "@" in pid else "unknown"
        if isinstance(info, list):
            info = info[0] if info else {}
        if not isinstance(info, dict):
            continue
        plugins.append({
            "name": name, "marketplace": marketplace,
            "version": info.get("version", "unknown"),
            "installed": info.get("installedAt", ""),
            "updated": info.get("lastUpdated", ""),
        })
    return plugins


# ── Showcase data collection (--include-skills) ────────────────────────────

# Image format magic bytes — extension is not trusted
_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_JPEG_SIG = b"\xff\xd8\xff"

# Per-skill payload caps (post-PII-scrub). See plan
# docs/plans/2026-04-12-002 → "Hard payload caps".
MAX_HERO_BYTES = 300 * 1024
MAX_README_BYTES = 100 * 1024
MAX_PER_SKILL_BYTES = 400 * 1024
TRUNCATION_MARKER = "\n\n<!-- truncated -->\n"

# Global serialized harness_json budget — enforced in generate_html(), not here.
MAX_HARNESS_JSON_BYTES = 6 * 1024 * 1024


def _enforce_showcase_budget(harness_json, max_bytes):
    """Drop showcase fields from low-priority skills until serialized JSON fits.

    Iterates skillInventory in calls-desc order. For each skill, measures the
    serialized total; if adding that skill's showcase fields would push the
    JSON past max_bytes, those fields are nulled (keeping name/calls/source/
    description/category) and a stderr warning names the skill and the running
    byte counter. Mutates harness_json in place.

    If the non-showcase payload alone exceeds max_bytes, this function emits a
    loud warning rather than silently shipping an oversized payload — the
    upload pipeline can catch it on the receiving end via the same byte check.
    """
    skills = harness_json.get("skillInventory")

    initial = len(json.dumps(harness_json))
    if initial <= max_bytes:
        return

    if skills:
        # Strategy: walk in REVERSE calls order (lowest-call first) and null
        # showcase fields until we fit. The list is already sorted desc by calls
        # in generate_html(), so iterate from the end.
        for entry in reversed(skills):
            if "readme_markdown" not in entry and "hero_base64" not in entry:
                continue
            had_content = bool(entry.get("readme_markdown") or entry.get("hero_base64"))
            if not had_content:
                continue
            entry["readme_markdown"] = None
            entry["hero_base64"] = None
            entry["hero_mime_type"] = None
            running = len(json.dumps(harness_json))
            print(
                f"  showcase budget cap: dropped showcase fields for {entry.get('name')!r} "
                f"(serialized total now {running} bytes, cap {max_bytes})",
                file=sys.stderr,
            )
            if running <= max_bytes:
                return

    # Fell out of the loop without converging. Could happen when:
    # (a) skillInventory is empty/missing showcase fields (only non-showcase
    #     payload is over budget), or
    # (b) all showcase fields nulled but rest of harness_json still > cap.
    # Either way, the local HTML still ships (user wants the report for their
    # own review), but we set a structured marker so the upload pipeline can
    # detect and reject it instead of failing mid-POST. The marker makes this
    # a HARD cap from the upload pipeline's perspective even though the
    # extractor itself can't shrink non-showcase fields without breaking
    # other features.
    final = len(json.dumps(harness_json))
    if final > max_bytes:
        harness_json["_payloadOverBudget"] = {
            "bytes": final,
            "cap": max_bytes,
            "reason": "non-showcase payload exceeds cap; cannot shrink further without dropping non-opt-in features",
        }
        print(
            f"  HARD CAP EXCEEDED: harness_json is {final} bytes (cap {max_bytes}) after "
            f"dropping all showcase fields. Set _payloadOverBudget marker on JSON for "
            f"upload-side detection. Cause: non-showcase payload bloat (skill inventory, "
            f"workflow data, etc.) — not fixable via --include-skills toggles.",
            file=sys.stderr,
        )


def _read_hero_image(assets_dir):
    """Return (raw_bytes, mime_type) for assets/hero.{png,jpg,jpeg} or (None, None).

    Rejects oversized files and any whose magic bytes don't match png/jpeg.
    Logs the reason to stderr so users know why a hero didn't ship.
    """
    if not assets_dir.is_dir():
        return None, None
    for name in ("hero.png", "hero.jpg", "hero.jpeg"):
        p = assets_dir / name
        if not p.is_file():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size > MAX_HERO_BYTES:
            print(f"  hero too large ({size} > {MAX_HERO_BYTES} bytes): {p}", file=sys.stderr)
            return None, None
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if data.startswith(_PNG_SIG):
            return data, "image/png"
        if data.startswith(_JPEG_SIG):
            return data, "image/jpeg"
        print(f"  hero rejected (magic-byte mismatch): {p}", file=sys.stderr)
        return None, None
    return None, None


def _skill_md_body(skill_md_path):
    """Return the markdown body of a SKILL.md (everything after closing frontmatter)."""
    try:
        text = skill_md_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if not text.startswith("---"):
        return text
    end = text.find("---", 3)
    if end == -1:
        return ""
    return text[end + 3:].lstrip("\n")


def _truncate_to_bytes(text, limit):
    """Truncate text to at most `limit` UTF-8 bytes, then append the marker."""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    head = encoded[:limit]
    # Back off to a valid UTF-8 char boundary
    while head and (head[-1] & 0xC0) == 0x80:
        head = head[:-1]
    return head.decode("utf-8", errors="ignore") + TRUNCATION_MARKER


def _read_raw_readme(skill_md_path):
    """First-pass helper: read raw (unscrubbed) README content for a skill."""
    skill_dir = skill_md_path.parent
    readme_path = skill_dir / "README.md"
    if readme_path.is_file():
        try:
            return readme_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
    return _skill_md_body(skill_md_path)


def _finalize_showcase(raw_readme, skill_md_path, scrub_rules):
    """Second-pass helper: scrub PII + read hero + apply per-item caps.

    Splitting from _read_raw_readme lets extract_skill_inventory() do a
    full pre-scan of all READMEs first to detect GitHub owners (e.g. orgs
    that don't match the local OS username), then build owner-aware scrub
    rules once and apply them everywhere. Without this two-pass approach
    the scrubber leaks any owner the user doesn't share a name with.
    """
    skill_dir = skill_md_path.parent

    readme_md = ""
    if raw_readme:
        try:
            scrubbed = scrub(raw_readme, rules=scrub_rules, context=str(skill_md_path))
        except SanitizeError as e:
            print(f"  PII scrub failed for {skill_md_path}: {e}", file=sys.stderr)
            scrubbed = ""
        readme_md = _truncate_to_bytes(scrubbed, MAX_README_BYTES)

    hero_bytes, mime = _read_hero_image(skill_dir / "assets")
    hero_b64 = base64.b64encode(hero_bytes).decode("ascii") if hero_bytes else None

    # Per-skill 400KB cap: drop hero first, then truncate README harder
    readme_size = len(readme_md.encode("utf-8"))
    hero_size = len(hero_b64) if hero_b64 else 0
    if readme_size + hero_size > MAX_PER_SKILL_BYTES:
        if hero_b64 and readme_size <= MAX_PER_SKILL_BYTES:
            print(f"  per-skill cap exceeded; dropping hero for {skill_md_path}", file=sys.stderr)
            hero_b64, mime = None, None
        else:
            readme_md = _truncate_to_bytes(readme_md, MAX_PER_SKILL_BYTES)
            hero_b64, mime = None, None

    return {
        "readme_markdown": readme_md or None,
        "hero_base64": hero_b64,
        "hero_mime_type": mime,
    }


def extract_skill_inventory(include_showcase=False):
    """Walk skill directories and return inventory list.

    When include_showcase=True, performs a two-pass collection:
      1. Pre-scan: read all candidate READMEs into memory
      2. Build owner-aware scrub rules from concatenated content
      3. Finalize: scrub + read heroes + cap

    Also tracks a private_skills set (skill names with repo: private/none)
    so generate_html() can filter them out of the runtime-invocations
    pathway too — without this filter, a private skill that was actually
    invoked still leaks via the call counter.
    """
    skills = []
    # Private/none skills must also be excluded from the runtime-call inventory
    # in generate_html. We collect names here and stash them on the returned
    # list via a sentinel attribute so the caller can access it without
    # changing the function's primary return type.
    private_names = set()

    # Stage 1: collect skill metadata + raw READMEs (without scrubbing yet)
    pending = []  # list of (meta, sp, source, raw_readme)

    def _stage(meta, sp, source):
        if not meta:
            return
        # Privacy: repo: private/none always excludes the skill — regardless
        # of whether showcase data is being collected. Otherwise passing
        # --no-include-skills would silently re-expose private skill names
        # via the runtime call counter, which contradicts the SKILL.md
        # guarantee that these skills are "skipped entirely".
        repo = (meta.get("repo") or "").strip().lower()
        if repo in ("private", "none"):
            # Track the *skill name* so generate_html can also filter it
            # out of the runtime-invocations pathway. Plugin skills appear
            # in invocations as "plugin:<owner>/<repo>:<skill>" — the
            # SKILL.md frontmatter name often matches just the trailing
            # segment, so we record both forms.
            name = meta.get("name") or sp.parent.name
            private_names.add(name)
            if source.startswith("plugin:"):
                private_names.add(f"{source[len('plugin:'):]}:{name}")
            return

        if include_showcase:
            raw_readme = _read_raw_readme(sp)
            pending.append((meta, sp, source, raw_readme))
        else:
            meta["source"] = source
            skills.append(meta)

    for sp in SKILLS_DIR.glob("*/SKILL.md"):
        _stage(parse_skill_frontmatter(sp), sp, "user")
    for sp in SKILLS_DIR.glob("*.md"):
        if sp.name != "SKILL.md":
            _stage(parse_skill_frontmatter(sp), sp, "user")
    for sp in PLUGINS_DIR.glob("cache/*/*/*/skills/*/SKILL.md"):
        m = parse_skill_frontmatter(sp)
        if m:
            parts = sp.parts
            ci = parts.index("cache")
            _stage(m, sp, f"plugin:{parts[ci+1]}/{parts[ci+2]}")
    for cp in PLUGINS_DIR.glob("cache/*/*/*/commands/*.md"):
        m = parse_skill_frontmatter(cp)
        if m:
            parts = cp.parts
            ci = parts.index("cache")
            _stage(m, cp, f"plugin:{parts[ci+1]}/{parts[ci+2]}")
    for cp in COMMANDS_DIR.glob("*.md"):
        skills.append({"name": cp.stem, "description": "", "allowed_tools": [], "user_invocable": True, "source": "command"})

    # Stage 2 + 3: build owner-aware rules from full corpus, then finalize
    if include_showcase:
        combined = "\n".join(raw or "" for _, _, _, raw in pending)
        scrub_rules = detect_pii(content_for_owner_scan=combined)
        for meta, sp, source, raw_readme in pending:
            showcase = _finalize_showcase(raw_readme, sp, scrub_rules)
            meta["readme_markdown"] = showcase["readme_markdown"]
            meta["hero_base64"] = showcase["hero_base64"]
            meta["hero_mime_type"] = showcase["hero_mime_type"]
            meta["category"] = meta.get("category") or None
            meta["source"] = source
            skills.append(meta)

    # Attach the deny-set to the list via a sentinel attribute. This is
    # simpler than changing the return type and rippling through callers.
    skills_with_deny = _SkillInventoryList(skills)
    skills_with_deny.private_skill_names = private_names
    return skills_with_deny


class _SkillInventoryList(list):
    """Plain list subclass that carries a private_skill_names attribute.

    Used so callers that treat the return value as `list` keep working,
    while `generate_html` can read the deny-set without us changing the
    public signature of `extract_skill_inventory`.
    """
    private_skill_names: set


def parse_skill_frontmatter(path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except IOError:
        return None
    if not text.startswith("---"):
        return None
    end = text.find("---", 3)
    if end == -1:
        return None
    meta = {}
    for line in text[3:end].strip().split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if key == "name": meta["name"] = val
            elif key == "description": meta["description"] = val[:120]
            elif key == "allowed-tools": meta["allowed_tools"] = [t.strip() for t in val.split(",")]
            elif key == "user-invocable": meta["user_invocable"] = val.lower() == "true"
            elif key == "repo": meta["repo"] = val
            elif key == "category": meta["category"] = val
    if "name" not in meta:
        meta["name"] = path.stem
    meta.setdefault("description", "")
    meta.setdefault("allowed_tools", [])
    meta.setdefault("user_invocable", False)
    return meta


def extract_hook_scripts():
    scripts = []
    if HOOKS_DIR.exists():
        for f in HOOKS_DIR.iterdir():
            if f.is_file():
                scripts.append({"name": f.name, "size_bytes": f.stat().st_size})
    return scripts


def extract_custom_agents():
    """Read custom agent definitions (names and model only)."""
    agents = []
    if AGENTS_DIR.exists():
        for f in AGENTS_DIR.iterdir():
            if f.is_file() and f.suffix == ".md":
                agents.append({"name": f.stem})
    return agents


def extract_harness_files():
    """Check for harness ecosystem files across projects."""
    files_found = {"global_claude_md": False, "global_claude_md_lines": 0}
    gcm = CLAUDE_DIR / "CLAUDE.md"
    if gcm.exists():
        files_found["global_claude_md"] = True
        try:
            files_found["global_claude_md_lines"] = len(gcm.read_text().splitlines())
        except IOError:
            pass
    # Count project-level files
    project_claude_mds = 0
    project_agents_mds = 0
    project_handoffs = 0
    project_workflows = 0
    for pd in PROJECTS_DIR.iterdir():
        if not pd.is_dir():
            continue
    # Check actual project dirs on disk
    coding_dir = Path.home() / "Coding"
    if coding_dir.exists():
        for proj in coding_dir.iterdir():
            if not proj.is_dir():
                continue
            if (proj / "CLAUDE.md").exists():
                project_claude_mds += 1
            if (proj / "AGENTS.md").exists():
                project_agents_mds += 1
            if (proj / "agent" / "HANDOFF.md").exists():
                project_handoffs += 1
            if (proj / "agent" / "WORKFLOWS.md").exists():
                project_workflows += 1
    files_found["project_claude_mds"] = project_claude_mds
    files_found["project_agents_mds"] = project_agents_mds
    files_found["project_handoffs"] = project_handoffs
    files_found["project_workflows"] = project_workflows
    return files_found


# ── Session Meta ───────────────────────────────────────────────────────────

def extract_session_meta(cutoff):
    sessions = []
    if not SESSION_META_DIR.exists():
        return sessions
    for mf in SESSION_META_DIR.glob("*.json"):
        data = safe_json_load(mf)
        if not data:
            continue
        start = data.get("start_time", "")
        try:
            ts = datetime.fromisoformat(start.replace("Z", "+00:00"))
            if ts < cutoff:
                continue
        except (ValueError, TypeError):
            continue
        sessions.append({
            "session_id": data.get("session_id", mf.stem),
            "tool_counts": data.get("tool_counts", {}),
            "languages": data.get("languages", {}),
            "duration_minutes": data.get("duration_minutes", 0),
            "input_tokens": data.get("input_tokens", 0),
            "output_tokens": data.get("output_tokens", 0),
            "uses_task_agent": data.get("uses_task_agent", False),
            "uses_mcp": data.get("uses_mcp", False),
            "uses_web_search": data.get("uses_web_search", False),
            "uses_web_fetch": data.get("uses_web_fetch", False),
            "git_commits": data.get("git_commits", 0),
            "git_pushes": data.get("git_pushes", 0),
            "lines_added": data.get("lines_added", 0),
            "lines_removed": data.get("lines_removed", 0),
            "user_message_count": data.get("user_message_count", 0),
            "assistant_message_count": data.get("assistant_message_count", 0),
        })
    return sessions


# ── JSONL Scan ─────────────────────────────────────────────────────────────

def _classify_tool_phase(tool_name, cmd_name=None):
    """Classify a tool call into a workflow phase.

    PRIVACY: Only read tool_use.name — never read tool_use.input
    except for Bash commands (first token only via extract_safe_command_name)

    Phases:
    - exploration: Read, Grep, Glob, WebSearch, WebFetch, curl, wget
    - implementation: Edit, Write, NotebookEdit, npm/npx/node/bun/pnpm/docker (non-test)
    - testing: Bash with test commands (pytest, jest, vitest, etc.) or npm test/npx jest etc.
    - shipping: Bash with git/gh commands
    - orchestration: Agent, Skill, TaskCreate, TaskUpdate
    - other: everything else (Bash with non-classified commands, etc.)

    Note: if "other" phase exceeds 30% of total calls, consider filtering
    it from the diagram to reduce noise.
    """
    EXPLORATION_TOOLS = {"Read", "Grep", "Glob", "WebSearch", "WebFetch", "ToolSearch"}
    IMPLEMENTATION_TOOLS = {"Edit", "Write", "NotebookEdit"}
    ORCHESTRATION_TOOLS = {"Agent", "Skill", "TaskCreate", "TaskUpdate", "EnterPlanMode"}
    # Single-token test runners
    TEST_COMMANDS = {"pytest", "jest", "vitest", "mocha", "rspec", "test", "cargo"}
    # Two-token Node runners, e.g. `npm test`, `npx jest`, `pnpm test:unit`
    NODE_TEST_COMMANDS = {
        f"{runner} {sub}"
        for runner in ("npm", "npx", "pnpm", "bun", "yarn")
        for sub in ("test", "jest", "vitest", "mocha", "ava", "cypress",
                    "playwright", "test:unit", "test:integration", "test:e2e")
    }
    SHIP_COMMANDS = {"git", "gh"}
    IMPL_COMMANDS = {"npm", "npx", "node", "bun", "pnpm", "yarn", "docker", "docker-compose"}
    EXPLORE_COMMANDS = {"curl", "wget"}

    if tool_name in EXPLORATION_TOOLS:
        return "exploration"
    if tool_name in IMPLEMENTATION_TOOLS:
        return "implementation"
    if tool_name in ORCHESTRATION_TOOLS:
        return "orchestration"
    if tool_name == "Bash" and cmd_name:
        # Check two-token Node test commands FIRST before falling through
        # to single-token classification
        if cmd_name in NODE_TEST_COMMANDS:
            return "testing"
        if cmd_name in TEST_COMMANDS:
            return "testing"
        if cmd_name in SHIP_COMMANDS:
            return "shipping"
        if cmd_name in EXPLORE_COMMANDS:
            return "exploration"
        if cmd_name in IMPL_COMMANDS:
            return "implementation"
    return "other"


def compute_workflow_patterns(sequences, min_length=2, max_length=4, top_n=10):
    """Find common subsequences of length 2-4 across sessions."""
    pattern_counts = Counter()
    for seq in sequences:
        for length in range(min_length, min(len(seq) + 1, max_length + 1)):
            for i in range(len(seq) - length + 1):
                subseq = tuple(seq[i : i + length])
                pattern_counts[subseq] += 1
    return [
        {"sequence": list(p), "count": c}
        for p, c in pattern_counts.most_common(top_n)
        if c >= 2
    ]


def extract_jsonl_metadata(cutoff):
    skill_invocations = Counter()
    session_skill_sequences = []  # list of per-session skill sequences
    slash_commands = Counter()
    hook_events = Counter()
    tool_usage = Counter()
    mcp_servers = Counter()
    permission_modes = Counter()
    entrypoints = Counter()
    models = Counter()
    versions = Counter()
    cli_tools = Counter()
    pr_count = 0
    session_count = 0
    total_sessions_scanned = 0
    total_input_tokens_jsonl = 0
    total_output_tokens_jsonl = 0
    total_cache_read_tokens_jsonl = 0
    total_cache_create_tokens_jsonl = 0
    pr_urls = set()

    # Agent patterns
    agent_count = 0
    agent_types = Counter()
    agent_models = Counter()
    agent_background = 0

    # Session behavior
    user_messages = 0
    assistant_messages = 0
    turn_durations = []
    compaction_events = 0
    tool_errors = 0
    tool_error_tools = Counter()
    total_tool_calls = 0
    task_creates = 0
    task_updates = 0
    plan_mode_enters = 0

    # Git
    branch_prefixes = Counter()

    # Tool transition tracking (tool A -> tool B within a turn)
    tool_transitions = Counter()
    prev_tool_in_turn = None  # reset on user message boundaries

    # Phase transition tracking
    phase_transitions = Counter()  # "exploration->implementation": 23
    prev_phase_in_turn = None
    phase_call_counts = Counter()  # total tool calls per phase

    # Per-session phase sequences for aggregate stats
    session_phase_sequences = []  # list of per-session phase lists

    cmd_pattern = re.compile(r"<command-name>(.*?)</command-name>")

    for project_dir in PROJECTS_DIR.iterdir():
        if not project_dir.is_dir():
            continue
        for jsonl_file in project_dir.glob("*.jsonl"):
            try:
                mtime = datetime.fromtimestamp(jsonl_file.stat().st_mtime, tz=timezone.utc)
                if mtime < cutoff:
                    continue
            except OSError:
                continue

            total_sessions_scanned += 1
            session_had_data = False
            session_branches = set()
            session_phases_seen = []  # ordered list of phases for this session
            session_skills_seen = []  # ordered skill invocations for this session

            try:
                with open(jsonl_file, "r", errors="replace") as f:
                    for line in f:
                        try:
                            d = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        entry_type = d.get("type")

                        # Git branch from envelope
                        gb = d.get("gitBranch", "")
                        if gb and gb not in session_branches:
                            session_branches.add(gb)
                            prefix = gb.split("/")[0] if "/" in gb else gb
                            branch_prefixes[prefix] += 1

                        if entry_type == "assistant":
                            assistant_messages += 1
                            msg = d.get("message", {})
                            model = msg.get("model", "")
                            usage_data = msg.get("usage", {})
                            # Accumulate 4-way token totals
                            total_input_tokens_jsonl += usage_data.get("input_tokens", 0)
                            total_output_tokens_jsonl += usage_data.get("output_tokens", 0)
                            total_cache_read_tokens_jsonl += usage_data.get("cache_read_input_tokens", 0)
                            total_cache_create_tokens_jsonl += usage_data.get("cache_creation_input_tokens", 0)
                            if model:
                                # Only count input + output for per-model breakdown.
                                # Cache tokens are tracked separately and billed at
                                # different rates — including them here inflates the
                                # models dict by 100-1000x, breaking cost estimates.
                                model_token_sum = (
                                    usage_data.get("input_tokens", 0) +
                                    usage_data.get("output_tokens", 0)
                                )
                                models[model] += model_token_sum
                            for item in msg.get("content", []):
                                if item.get("type") == "tool_use":
                                    session_had_data = True
                                    tool_name = item.get("name", "")
                                    tool_usage[tool_name] += 1
                                    total_tool_calls += 1

                                    if tool_name == "Skill":
                                        sn = item.get("input", {}).get("skill", "unknown")
                                        skill_invocations[sn] += 1
                                        session_skills_seen.append(sn)
                                    elif tool_name == "Agent":
                                        agent_count += 1
                                        inp = item.get("input", {})
                                        at = inp.get("subagent_type", "general-purpose")
                                        agent_types[at] += 1
                                        am = inp.get("model", "")
                                        if am:
                                            agent_models[am] += 1
                                        if inp.get("run_in_background"):
                                            agent_background += 1
                                        # PRIVACY: do NOT read input.description — it often
                                        # contains project names, feature details, or task
                                        # context that would leak into the public report.
                                    elif tool_name == "Bash":
                                        # Safe command name extraction
                                        cmd_str = item.get("input", {}).get("command", "")
                                        cmd_name = extract_safe_command_name(cmd_str)
                                        if cmd_name:
                                            cli_tools[cmd_name] += 1
                                    elif tool_name == "TaskCreate":
                                        task_creates += 1
                                    elif tool_name == "TaskUpdate":
                                        task_updates += 1
                                    elif tool_name == "EnterPlanMode":
                                        plan_mode_enters += 1

                                    # PRIVACY: Only read tool_use.name — never read tool_use.input
                                    # except for Bash commands (first token only via extract_safe_command_name)

                                    # Tool transition tracking
                                    if prev_tool_in_turn is not None:
                                        transition_key = f"{prev_tool_in_turn}->{tool_name}"
                                        tool_transitions[transition_key] += 1
                                    prev_tool_in_turn = tool_name

                                    # Phase classification
                                    _cmd_name_for_phase = None
                                    if tool_name == "Bash":
                                        _cmd_name_for_phase = extract_safe_command_name(
                                            item.get("input", {}).get("command", "")
                                        )
                                    current_phase = _classify_tool_phase(tool_name, _cmd_name_for_phase)
                                    phase_call_counts[current_phase] += 1

                                    # Phase transitions (within a turn)
                                    if prev_phase_in_turn is not None and prev_phase_in_turn != current_phase:
                                        phase_transitions[f"{prev_phase_in_turn}->{current_phase}"] += 1
                                    prev_phase_in_turn = current_phase

                                    # Record phase for session-level sequence
                                    if not session_phases_seen or session_phases_seen[-1] != current_phase:
                                        session_phases_seen.append(current_phase)

                                    if tool_name.startswith("mcp__"):
                                        parts = tool_name.split("__")
                                        if len(parts) >= 2:
                                            mcp_servers[parts[1]] += 1

                        elif entry_type == "user":
                            # Only count real human prompts, not tool_result envelopes
                            msg = d.get("message", {})
                            content = msg.get("content", "")
                            is_real_prompt = False
                            if isinstance(content, str):
                                is_real_prompt = True
                            elif isinstance(content, list):
                                non_tool_result = [i for i in content if not (isinstance(i, dict) and i.get("type") == "tool_result")]
                                if non_tool_result:
                                    is_real_prompt = True
                            if is_real_prompt:
                                user_messages += 1
                            # Reset tool transition tracking on new user turn
                            prev_tool_in_turn = None
                            prev_phase_in_turn = None
                            if isinstance(content, str):
                                for cmd in cmd_pattern.findall(content):
                                    slash_commands[cmd] += 1

                        elif entry_type == "progress":
                            data_inner = d.get("data", {})
                            if data_inner.get("type") == "hook_progress":
                                hook_events[data_inner.get("hookName", "unknown")] += 1

                        elif entry_type == "permission-mode":
                            permission_modes[d.get("permissionMode", "unknown")] += 1

                        elif entry_type == "pr-link":
                            pr_url = d.get("url", d.get("prUrl", ""))
                            if pr_url:
                                pr_urls.add(pr_url)
                            else:
                                pr_urls.add(f"__unknown_{len(pr_urls)}")

                        elif entry_type == "system":
                            st = d.get("subtype", "")
                            if st == "turn_duration":
                                dur = d.get("durationMs", 0)
                                if dur > 0:
                                    turn_durations.append(dur)
                            elif st == "compact_boundary":
                                compaction_events += 1

                        # Tool errors from tool_result
                        if entry_type == "user":
                            msg = d.get("message", {})
                            content = msg.get("content", [])
                            if isinstance(content, list):
                                for item in content:
                                    if isinstance(item, dict) and item.get("type") == "tool_result":
                                        if item.get("is_error"):
                                            tool_errors += 1

                        ep = d.get("entrypoint", "")
                        if ep:
                            entrypoints[ep] += 1
                        ver = d.get("version", "")
                        if ver:
                            versions[ver] += 1

            except IOError:
                continue

            if session_had_data:
                session_count += 1
            if session_phases_seen:
                session_phase_sequences.append(session_phases_seen)
            if session_skills_seen:
                # Deduplicate consecutive repeats (A, A, B -> A, B)
                deduped = [session_skills_seen[0]]
                for s in session_skills_seen[1:]:
                    if s != deduped[-1]:
                        deduped.append(s)
                session_skill_sequences.append(deduped)

    # Phase statistics
    total_phase_calls = sum(phase_call_counts.values()) or 1
    phase_pcts = {k: round(v / total_phase_calls * 100) for k, v in phase_call_counts.most_common()}

    # Session-level phase pattern stats
    sessions_that_test_before_ship = 0
    sessions_that_explore_before_implement = 0
    for seq in session_phase_sequences:
        if "testing" in seq and "shipping" in seq:
            if seq.index("testing") < seq.index("shipping"):
                sessions_that_test_before_ship += 1
        if "exploration" in seq and "implementation" in seq:
            if seq.index("exploration") < seq.index("implementation"):
                sessions_that_explore_before_implement += 1

    total_with_phases = len(session_phase_sequences) or 1
    test_before_ship_pct = round(sessions_that_test_before_ship / total_with_phases * 100)
    explore_before_impl_pct = round(sessions_that_explore_before_implement / total_with_phases * 100)

    # Autonomy metrics
    autonomy_ratio = round(user_messages / assistant_messages, 3) if assistant_messages > 0 else 0
    sorted_durations = sorted(turn_durations)
    median_turn_ms = sorted_durations[len(sorted_durations)//2] if sorted_durations else 0
    avg_turn_ms = sum(turn_durations) / len(turn_durations) if turn_durations else 0
    max_turn_ms = max(turn_durations) if turn_durations else 0
    error_rate = round(tool_errors / total_tool_calls * 100, 1) if total_tool_calls > 0 else 0

    return {
        "skill_invocations": dict(skill_invocations.most_common(50)),
        "workflow_patterns": compute_workflow_patterns(session_skill_sequences),
        "slash_commands": dict(slash_commands.most_common(30)),
        "hook_events": dict(hook_events.most_common(30)),
        "tool_usage": dict(tool_usage.most_common(30)),
        "mcp_servers": dict(mcp_servers.most_common(20)),
        "permission_modes": dict(permission_modes),
        "entrypoints": dict(entrypoints.most_common(10)),
        "models": dict(models.most_common(10)),
        "versions": dict(versions.most_common(10)),
        "cli_tools": dict(cli_tools.most_common(20)),
        "pr_count": len(pr_urls),
        "total_input_tokens": total_input_tokens_jsonl,
        "total_output_tokens": total_output_tokens_jsonl,
        "total_cache_read_tokens": total_cache_read_tokens_jsonl,
        "total_cache_create_tokens": total_cache_create_tokens_jsonl,
        "total_throughput_tokens": (total_input_tokens_jsonl + total_output_tokens_jsonl + total_cache_read_tokens_jsonl + total_cache_create_tokens_jsonl),
        "sessions_scanned": total_sessions_scanned,
        "sessions_with_data": session_count,
        # Agent patterns
        "agent_count": agent_count,
        "agent_types": dict(agent_types.most_common(10)),
        "agent_models": dict(agent_models.most_common(5)),
        "agent_background_pct": round(agent_background / agent_count * 100) if agent_count > 0 else 0,
        # Autonomy
        "user_messages": user_messages,
        "assistant_messages": assistant_messages,
        "autonomy_ratio": autonomy_ratio,
        "median_turn_ms": median_turn_ms,
        "avg_turn_ms": round(avg_turn_ms),
        "max_turn_ms": max_turn_ms,
        "turn_count": len(turn_durations),
        # Errors
        "tool_errors": tool_errors,
        "total_tool_calls": total_tool_calls,
        "error_rate_pct": error_rate,
        # Features
        "compaction_events": compaction_events,
        "task_creates": task_creates,
        "task_updates": task_updates,
        "plan_mode_enters": plan_mode_enters,
        # Git
        "branch_prefixes": dict(branch_prefixes.most_common(10)),
        # Tool transitions (top 30 most common A->B pairs)
        "tool_transitions": dict(tool_transitions.most_common(30)),
        # Phase transitions (top 20 most common phase->phase pairs)
        "phase_transitions": dict(phase_transitions.most_common(20)),
        # Phase call distribution (percentage per phase)
        "phase_distribution": phase_pcts,
        # Phase pattern stats
        "phase_stats": {
            "test_before_ship_pct": test_before_ship_pct,
            "explore_before_impl_pct": explore_before_impl_pct,
            "total_sessions_with_phases": len(session_phase_sequences),
        },
    }


def extract_permissions_profile():
    approved_skills = set()
    approved_mcp = set()
    bash_patterns = set()
    project_count = 0
    for sf in Path.home().rglob(".claude/settings.local.json"):
        # Limit depth to avoid traversing too deep
        if len(sf.parts) > 10:
            continue
        data = safe_json_load(sf)
        if not data:
            continue
        project_count += 1
        for perm in data.get("permissions", {}).get("allow", []):
            if isinstance(perm, str):
                if perm.startswith("Skill("):
                    approved_skills.add(perm[6:].rstrip(")"))
                elif perm.startswith("mcp__"):
                    parts = perm.split("__")
                    if len(parts) >= 2:
                        approved_mcp.add(parts[1])
                elif perm.startswith("Bash("):
                    p = perm[5:].rstrip(")")
                    cmd = p.split()[0] if p else p
                    # Scrub paths — only keep the command basename
                    if cmd and '/' in cmd:
                        cmd = os.path.basename(cmd.rstrip('*').rstrip('/')) or cmd
                    # Skip if it looks like a username or home path fragment
                    if cmd and not cmd.startswith('.') and cmd.lower() not in ('users',):
                        bash_patterns.add(cmd)
    return {
        "approved_skills": sorted(approved_skills),
        "approved_mcp_servers": sorted(approved_mcp),
        "bash_command_types": sorted(bash_patterns),
        "projects_with_local_settings": project_count,
    }


# ── /insights Report Embedding ─────────────────────────────────────────────

def extract_insights_report():
    """Read the /insights report.html if it exists and extract its content sections."""
    report_path = CLAUDE_DIR / "usage-data" / "report.html"
    if not report_path.exists():
        return None

    try:
        html = report_path.read_text()
    except IOError:
        return None

    # Extract the body content between <body> and </body>
    import re
    body_match = re.search(r'<body[^>]*>(.*?)</body>', html, re.DOTALL)
    if not body_match:
        return None

    body = body_match.group(1)

    # Extract the subtitle (stats line)
    subtitle_match = re.search(r'<p[^>]*class="subtitle"[^>]*>(.*?)</p>', body, re.DOTALL)
    subtitle = re.sub(r'<[^>]+>', '', subtitle_match.group(1)).strip() if subtitle_match else ""

    # Extract all sections (h2 + content until next h2)
    sections = []
    h2_splits = re.split(r'(<h2[^>]*>.*?</h2>)', body, flags=re.DOTALL)
    current_title = None
    current_content = []

    for part in h2_splits:
        h2_match = re.match(r'<h2[^>]*>(.*?)</h2>', part, re.DOTALL)
        if h2_match:
            if current_title:
                sections.append({"title": current_title, "content": "".join(current_content)})
            current_title = re.sub(r'<[^>]+>', '', h2_match.group(1)).strip()
            current_content = []
        else:
            current_content.append(part)

    if current_title:
        sections.append({"title": current_title, "content": "".join(current_content)})

    # Extract style blocks to preserve formatting
    styles = re.findall(r'<style[^>]*>(.*?)</style>', html, re.DOTALL)

    return {
        "subtitle": subtitle,
        "sections": sections,
        "styles": "\n".join(styles),
        "source_path": str(report_path),
        "modified": datetime.fromtimestamp(report_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
    }


# ── New Config Layer Extractors ────────────────────────────────────────────

def extract_safety_posture():
    """Dangermode, custom safety hooks, universal denies."""
    settings = safe_json_load(CLAUDE_DIR / "settings.json") or {}
    skip_danger = settings.get("skipDangerousModePermissionPrompt", False)
    has_custom_safety = False
    safety_hooks = []
    for event, matchers in settings.get("hooks", {}).items():
        for mb in matchers:
            for h in mb.get("hooks", []):
                cmd = h.get("command", "")
                if "auto_approve" in cmd or "dcg" in cmd or "validate_file" in cmd:
                    has_custom_safety = True
                    name = "dcg" if "dcg" in cmd else re.search(r'(\w+\.py)', cmd)
                    safety_hooks.append(name.group(1) if hasattr(name, 'group') else name)

    # Universal denies across projects
    deny_rules = Counter()
    coding_dir = Path.home() / "Coding"
    if coding_dir.exists():
        for sf in coding_dir.rglob(".claude/settings.json"):
            if len(sf.parts) > 10:
                continue
            data = safe_json_load(sf)
            if data:
                for d in data.get("permissions", {}).get("deny", []):
                    if isinstance(d, str):
                        deny_rules[d] += 1

    return {
        "skip_danger_prompt": skip_danger,
        "has_custom_safety": has_custom_safety,
        "safety_hooks": list(set(safety_hooks)),
        "custom_safety_label": "Custom Safety Gate" if has_custom_safety else "Stock Permissions",
        "universal_denies": [r for r, c in deny_rules.most_common(10) if c >= 2],
    }


def extract_experimental_features():
    """Env vars matching CLAUDE_CODE_EXPERIMENTAL_*."""
    settings = safe_json_load(CLAUDE_DIR / "settings.json") or {}
    env = settings.get("env", {})
    experimental = {k: v for k, v in env.items() if "EXPERIMENTAL" in k.upper()}
    other_env = {k: v for k, v in env.items() if "EXPERIMENTAL" not in k.upper()}
    return {"experimental_flags": experimental, "other_env_flags": other_env}


def extract_stats_cache():
    """Peak usage, model timeline, per-model token breakdown from stats-cache.json."""
    data = safe_json_load(CLAUDE_DIR / "stats-cache.json")
    if not data:
        return {}

    daily = data.get("dailyActivity", [])
    model_usage = data.get("modelUsage", {})

    # Peak day
    peak_day = max(daily, key=lambda d: d.get("messageCount", 0)) if daily else {}
    total_messages = sum(d.get("messageCount", 0) for d in daily)
    total_sessions_cache = sum(d.get("sessionCount", 0) for d in daily)
    avg_daily = total_messages // len(daily) if daily else 0

    # Model timeline (first/last seen)
    model_timeline = {}
    for d in daily:
        date = d.get("date", "")
        # Check if model info is in the daily entry
        for key in d:
            if key.startswith("model_") or "model" in key.lower():
                pass  # stats-cache doesn't have per-day model split

    # Per-model token breakdown
    model_tokens = {}
    for model, usage in model_usage.items():
        if isinstance(usage, dict):
            model_tokens[model] = {
                "input": usage.get("inputTokens", 0),
                "output": usage.get("outputTokens", 0),
                "cache_read": usage.get("cacheReadInputTokens", usage.get("cacheReadTokens", 0)),
                "cache_create": usage.get("cacheCreationInputTokens", usage.get("cacheCreationTokens", 0)),
            }

    # Cache efficiency
    total_cache_read = sum(m.get("cache_read", 0) for m in model_tokens.values())
    total_direct_input = sum(m.get("input", 0) for m in model_tokens.values())
    cache_ratio = round(total_cache_read / total_direct_input) if total_direct_input > 0 else 0

    lifetime_input = sum(m.get("input", 0) for m in model_tokens.values())
    lifetime_output = sum(m.get("output", 0) for m in model_tokens.values())
    lifetime_tokens_inout = lifetime_input + lifetime_output

    return {
        "peak_day_messages": peak_day.get("messageCount", 0),
        "peak_day_sessions": peak_day.get("sessionCount", 0),
        "peak_day_date": peak_day.get("date", ""),
        "total_messages_all_time": total_messages,
        "total_sessions_all_time": total_sessions_cache,
        "avg_daily_messages": avg_daily,
        "days_tracked": len(daily),
        "model_tokens": model_tokens,
        "cache_read_ratio": cache_ratio,
        "lifetime_tokens": lifetime_tokens_inout,
    }


def extract_instruction_maturity():
    """Gen 1 vs Gen 2 project instruction patterns, CLAUDE.md headings."""
    coding_dir = Path.home() / "Coding"
    projects = {"gen1": 0, "gen2": 0, "none": 0, "total": 0}
    claude_md_headings = []
    handoff_sizes = []

    # Global CLAUDE.md headings
    global_cmd = CLAUDE_DIR / "CLAUDE.md"
    global_headings = []
    if global_cmd.exists():
        try:
            for line in global_cmd.read_text().splitlines():
                if line.startswith("#"):
                    global_headings.append(line.strip())
        except IOError:
            pass

    if not coding_dir.exists():
        return {"projects": projects, "global_headings": global_headings, "claude_md_headings": [], "handoff_sizes": []}

    for proj in coding_dir.iterdir():
        if not proj.is_dir() or proj.name.startswith('.'):
            continue
        projects["total"] += 1

        has_claude_md = (proj / "CLAUDE.md").exists()
        has_agents_md = (proj / "AGENTS.md").exists()
        has_agent_bundle = (proj / "agent" / "WORKFLOWS.md").exists() or (proj / "agent" / "CONSTITUTION.md").exists()

        if has_agent_bundle or has_agents_md:
            projects["gen2"] += 1
        elif has_claude_md:
            projects["gen1"] += 1
        else:
            projects["none"] += 1

        # CLAUDE.md headings (structure only)
        if has_claude_md:
            try:
                lines = (proj / "CLAUDE.md").read_text().splitlines()
                headings = [l.strip() for l in lines if l.startswith("#")]
                claude_md_headings.append({
                    "line_count": len(lines),
                    "headings": headings,
                })
            except IOError:
                pass

        # HANDOFF.md sizes
        handoff = proj / "agent" / "HANDOFF.md"
        if handoff.exists():
            try:
                handoff_sizes.append(len(handoff.read_text().splitlines()))
            except IOError:
                pass

    return {
        "projects": projects,
        "global_headings": global_headings,
        "claude_md_headings": claude_md_headings,
        "handoff_sizes": handoff_sizes,
        "avg_handoff_lines": round(sum(handoff_sizes) / len(handoff_sizes)) if handoff_sizes else 0,
    }


def extract_memory_architecture():
    """Dual-layer memory detection and atom type counts."""
    in_repo_count = 0
    claude_managed_count = 0
    atom_types = Counter()

    # In-repo agent/MEMORY.md
    coding_dir = Path.home() / "Coding"
    if coding_dir.exists():
        for proj in coding_dir.iterdir():
            if (proj / "agent" / "MEMORY.md").exists():
                in_repo_count += 1

    # Claude-managed memory
    for proj_dir in PROJECTS_DIR.iterdir():
        if not proj_dir.is_dir():
            continue
        mem_dir = proj_dir / "memory"
        if mem_dir.exists():
            claude_managed_count += 1
            for f in mem_dir.glob("*.md"):
                if f.name == "MEMORY.md":
                    continue
                # Classify by prefix
                name = f.stem
                if name.startswith("feedback"):
                    atom_types["feedback"] += 1
                elif name.startswith("project"):
                    atom_types["project"] += 1
                elif name.startswith("reference"):
                    atom_types["reference"] += 1
                elif name.startswith("user"):
                    atom_types["user"] += 1
                else:
                    atom_types["other"] += 1

    return {
        "in_repo_memory": in_repo_count,
        "claude_managed_memory": claude_managed_count,
        "atom_types": dict(atom_types),
        "total_atoms": sum(atom_types.values()),
        "is_dual_layer": in_repo_count > 0 and claude_managed_count > 0,
    }


def extract_agent_details():
    """Enhanced agent extraction: model tiering, roles, from .md files."""
    agents = []
    if AGENTS_DIR.exists():
        for f in AGENTS_DIR.iterdir():
            if f.is_file() and f.suffix == ".md":
                agent = {"name": f.stem, "model": "inherit", "description": ""}
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    # Parse frontmatter-style or inline model/description
                    for line in text.splitlines()[:20]:
                        if line.strip().startswith("model:"):
                            agent["model"] = line.split(":", 1)[1].strip().strip('"')
                        elif "description:" in line.lower():
                            agent["description"] = line.split(":", 1)[1].strip()[:100]
                except IOError:
                    pass
                agents.append(agent)

    # Tiering summary
    tiers = {"opus": [], "sonnet": [], "haiku": [], "inherit": []}
    for a in agents:
        m = a["model"].lower()
        if "opus" in m:
            tiers["opus"].append(a["name"])
        elif "haiku" in m:
            tiers["haiku"].append(a["name"])
        elif "sonnet" in m:
            tiers["sonnet"].append(a["name"])
        else:
            tiers["inherit"].append(a["name"])

    return {"agents": agents, "tiers": tiers}


def extract_team_configs():
    """Team configurations from ~/.claude/teams/."""
    teams_dir = CLAUDE_DIR / "teams"
    teams = []
    if teams_dir.exists():
        for td in teams_dir.iterdir():
            if td.is_dir():
                config = safe_json_load(td / "config.json")
                team = {"name_hash": hashlib.sha256(td.name.encode()).hexdigest()[:8], "has_config": config is not None}
                if config:
                    members = config.get("agents", config.get("members", []))
                    team["member_count"] = len(members) if isinstance(members, list) else 0
                    # Check for team lead
                    lead = config.get("lead", config.get("teamLead", {}))
                    if isinstance(lead, dict):
                        team["lead_model"] = lead.get("model", "unknown")
                teams.append(team)
    return {"teams": teams, "team_count": len(teams)}


def extract_marketplace_diversity():
    """Which plugin marketplaces are configured."""
    data = safe_json_load(PLUGINS_DIR / "known_marketplaces.json")
    marketplaces = []
    if isinstance(data, dict):
        for name, info in data.items():
            if isinstance(info, dict):
                marketplaces.append({"name": name, "url": info.get("url", info.get("git", ""))})
            elif isinstance(info, str):
                marketplaces.append({"name": name, "url": info})
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                marketplaces.append({"name": item.get("name", "unknown"), "url": item.get("url", item.get("git", ""))})
    return {"marketplaces": marketplaces, "count": len(marketplaces)}


def extract_statusline():
    """Statusline plugin details."""
    sh_path = CLAUDE_DIR / "statusline.sh"
    if not sh_path.exists():
        return {"configured": False}
    try:
        text = sh_path.read_text(encoding="utf-8", errors="replace")
        lines = len(text.splitlines())
        # Try to find package name/version
        pkg_name = ""
        version = ""
        for line in text.splitlines()[:30]:
            if "cc-statusline" in line or "@" in line:
                pkg_name = line.strip().lstrip("# ").strip()
                break
            if "VERSION" in line or "version" in line:
                version = line.strip()
        return {"configured": True, "lines": lines, "package_hint": pkg_name[:80], "version_hint": version[:40]}
    except IOError:
        return {"configured": False}


def extract_ide_integration():
    """Check for IDE integration (VS Code WebSocket)."""
    ide_dir = CLAUDE_DIR / "ide"
    if not ide_dir.exists():
        return {"mode": "terminal-only"}
    lock_files = list(ide_dir.glob("*.lock"))
    if lock_files:
        return {"mode": "vs-code", "connections": len(lock_files)}
    return {"mode": "terminal-only"}


def extract_hybrid_tools():
    """Detect cross-tool patterns (Gemini CLI, Codex, etc.)."""
    tools_found = set()

    # Check CLAUDE.md for tool references
    for md_path in [CLAUDE_DIR / "CLAUDE.md"]:
        if md_path.exists():
            try:
                text = md_path.read_text(encoding="utf-8", errors="replace").lower()
                if "gemini" in text:
                    tools_found.add("Gemini CLI")
                if "codex" in text:
                    tools_found.add("OpenAI Codex")
                if "copilot" in text:
                    tools_found.add("GitHub Copilot")
                if "cursor" in text:
                    tools_found.add("Cursor")
            except IOError:
                pass

    # Check for other AI tool directories
    if (Path.home() / ".codex").exists():
        tools_found.add("OpenAI Codex")
    if (Path.home() / ".factory").exists():
        tools_found.add("Factory")

    return {"tools": sorted(tools_found)}


def extract_blocklist_issues():
    """Check for blocklist contradictions with enabled plugins."""
    settings = safe_json_load(CLAUDE_DIR / "settings.json") or {}
    blocklist = safe_json_load(PLUGINS_DIR / "blocklist.json") or {}
    enabled = settings.get("enabledPlugins", {})

    blocked_names = set()
    if isinstance(blocklist, dict):
        for key in blocklist:
            if key not in ("version",):
                blocked_names.add(key.split("@")[0] if "@" in key else key)
    elif isinstance(blocklist, list):
        for item in blocklist:
            if isinstance(item, str):
                blocked_names.add(item.split("@")[0] if "@" in item else item)

    enabled_names = {k.split("@")[0] for k, v in enabled.items() if v}
    contradictions = blocked_names & enabled_names

    return {"blocked_count": len(blocked_names), "contradictions": sorted(contradictions)}


def extract_permission_accumulation():
    """Count permission grants per project, categorize them."""
    projects = []
    coding_dir = Path.home() / "Coding"
    if not coding_dir.exists():
        return {"projects": []}

    for sf in coding_dir.rglob(".claude/settings.local.json"):
        if len(sf.parts) > 10:
            continue
        data = safe_json_load(sf)
        if not data:
            continue
        allows = data.get("permissions", {}).get("allow", [])
        categories = Counter()
        for perm in allows:
            if isinstance(perm, str):
                if perm.startswith("Bash("):
                    categories["bash"] += 1
                elif perm.startswith("Skill("):
                    categories["skill"] += 1
                elif perm.startswith("mcp__"):
                    categories["mcp"] += 1
                elif perm.startswith("Read") or perm.startswith("Write") or perm.startswith("Edit"):
                    categories["file"] += 1
                else:
                    categories["other"] += 1
        projects.append({
            "total_grants": len(allows),
            "categories": dict(categories),
        })

    return {
        "projects": projects,
        "total_projects": len(projects),
        "avg_grants": round(sum(p["total_grants"] for p in projects) / len(projects)) if projects else 0,
        "max_grants": max((p["total_grants"] for p in projects), default=0),
    }


# ── Aggregation ────────────────────────────────────────────────────────────

MAX_SESSION_MINUTES = 480

def aggregate_session_meta(sessions):
    if not sessions:
        return {}
    total_tokens_in = sum(s["input_tokens"] for s in sessions)
    total_tokens_out = sum(s["output_tokens"] for s in sessions)
    total_duration = sum(min(s["duration_minutes"], MAX_SESSION_MINUTES) for s in sessions)
    all_tools = Counter()
    for s in sessions:
        for t, c in s["tool_counts"].items():
            all_tools[t] += c
    all_langs = Counter()
    for s in sessions:
        for l, c in s["languages"].items():
            all_langs[l] += c
    uses_task = sum(1 for s in sessions if s["uses_task_agent"])
    uses_mcp = sum(1 for s in sessions if s["uses_mcp"])
    uses_web = sum(1 for s in sessions if s["uses_web_search"])
    durations = [min(s["duration_minutes"], MAX_SESSION_MINUTES) for s in sessions if s["duration_minutes"] > 0]
    avg_dur = sum(durations) / len(durations) if durations else 0
    return {
        "session_count": len(sessions),
        "total_input_tokens": total_tokens_in,
        "total_output_tokens": total_tokens_out,
        "total_tokens": total_tokens_in + total_tokens_out,
        "total_duration_hours": round(total_duration / 60, 1),
        "avg_duration_minutes": round(avg_dur, 1),
        "total_git_commits": sum(s["git_commits"] for s in sessions),
        "total_lines_added": sum(s["lines_added"] for s in sessions),
        "total_lines_removed": sum(s["lines_removed"] for s in sessions),
        "tool_counts": dict(all_tools.most_common(30)),
        "languages": dict(all_langs.most_common(20)),
        "uses_task_agent_pct": round(uses_task / len(sessions) * 100) if sessions else 0,
        "uses_mcp_pct": round(uses_mcp / len(sessions) * 100) if sessions else 0,
        "uses_web_search_pct": round(uses_web / len(sessions) * 100) if sessions else 0,
        "total_user_messages": sum(s["user_message_count"] for s in sessions),
        "total_assistant_messages": sum(s["assistant_message_count"] for s in sessions),
    }


# ── HTML Generation ────────────────────────────────────────────────────────

def generate_writeup(data):
    """Generate a narrative writeup explaining the harness setup for other developers."""
    meta = data["session_meta_summary"]
    jsonl = data["jsonl_metadata"]
    settings = data["settings"]
    skills = data["skill_inventory"]
    plugins = data["installed_plugins"]
    perms = data["permissions_profile"]
    harness_files = data["harness_files"]
    custom_agents = data["custom_agents"]
    # New config layer data
    safety = data.get("safety_posture", {})
    experimental = data.get("experimental", {})
    stats_cache = data.get("stats_cache", {})
    instr_maturity = data.get("instruction_maturity", {})
    memory_arch = data.get("memory_arch", {})
    agent_det = data.get("agent_details", {})
    team_cfg = data.get("team_configs", {})
    mkt = data.get("marketplace", {})
    statusline_info = data.get("statusline", {})
    ide_info = data.get("ide", {})
    hybrid = data.get("hybrid_tools", {})
    blocklist_info = data.get("blocklist", {})
    perm_accum = data.get("perm_accumulation", {})

    def he(s):
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    total_sessions = jsonl.get("sessions_with_data", meta.get("session_count", 0))
    skill_invocations = jsonl.get("skill_invocations", {})
    hook_defs = settings.get("hooks", [])
    cli_tools = jsonl.get("cli_tools", {})
    enabled_plugins = settings.get("enabled_plugins", {})
    tool_counts = Counter(jsonl.get("tool_usage", {}))
    for t, c in meta.get("tool_counts", {}).items():
        if t not in tool_counts:
            tool_counts[t] = c

    reads = tool_counts.get("Read", 0)
    edits = tool_counts.get("Edit", 0)
    writes = tool_counts.get("Write", 0)
    ar = jsonl.get("autonomy_ratio", 0)

    sections = []

    # ── Overview ──
    if ar > 0 and ar < 0.15:
        style_desc = "a fire-and-forget style, issuing high-level directives and letting Claude run long autonomous loops with minimal intervention"
        style_tip = "This works best with well-structured CLAUDE.md files and strong hook guardrails. The upfront investment in project instructions pays for itself in longer, more productive sessions."
    elif ar < 0.4:
        style_desc = "a directive style, giving Claude clear tasks and stepping in occasionally to redirect"
        style_tip = "This balances oversight with autonomy. Consider adding more hooks to catch common mistakes, which would let you intervene even less."
    else:
        style_desc = "a collaborative style, actively guiding Claude through tasks with frequent interaction"
        style_tip = "This gives maximum control. If sessions feel slow, try writing more detailed upfront prompts and using skills that structure multi-step work."

    sections.append(f'''<div class="writeup-section">
        <h2>How This Harness Works</h2>
        <p>This developer uses Claude Code with <strong>{style_desc}</strong>. Over the last 30 days, they've run {total_sessions} sessions
        averaging about {meta.get("avg_duration_minutes", 0):.0f} minutes each, with roughly 1 human message for every
        {round(1/ar) if ar > 0 else "?"} Claude messages.</p>
        <p class="tip">{style_tip}</p>
    </div>''')

    # ── Skills & Workflows ──
    custom_skills_used = [(n, c) for n, c in sorted(skill_invocations.items(), key=lambda x: x[1], reverse=True)
                          if not any(n.startswith(p) for p in ("superpowers:", "compound-engineering:", "code-review:", "commit-commands:", "pr-review-toolkit:"))]
    plugin_skills_used = [(n, c) for n, c in sorted(skill_invocations.items(), key=lambda x: x[1], reverse=True)
                          if any(n.startswith(p) for p in ("superpowers:", "compound-engineering:", "code-review:", "commit-commands:", "pr-review-toolkit:"))]

    skill_lines = []
    if custom_skills_used:
        top_custom = custom_skills_used[:5]
        names = ", ".join(f"<strong>{he(n)}</strong> ({c}x)" for n, c in top_custom)
        skill_lines.append(f"<p>The most-used custom skills are {names}. These are skills this developer wrote or installed themselves — they represent the unique part of this harness that you can't get from a default Claude Code setup.</p>")

        # Look up descriptions for the top custom skills
        skill_meta = {s["name"]: s for s in skills}
        descs = []
        for n, c in top_custom[:3]:
            sm = skill_meta.get(n, {})
            d = sm.get("description", "")
            if d:
                descs.append(f"<li><strong>{he(n)}</strong> — {he(d)}</li>")
        if descs:
            skill_lines.append("<p>What the top custom skills do:</p><ul>" + "".join(descs) + "</ul>")

    if plugin_skills_used:
        top_plugin = plugin_skills_used[:5]
        names = ", ".join(f"<strong>{he(n)}</strong> ({c}x)" for n, c in top_plugin)
        skill_lines.append(f"<p>From plugins, the most-used are {names}. These come from installed plugin packages and handle structured workflows like planning, brainstorming, and code review.</p>")

    if not skill_invocations:
        skill_lines.append("<p>No skills were invoked in the last 30 days. Skills are the main way to add structured workflows to Claude Code — this is a significant opportunity.</p>")

    sections.append(f'''<div class="writeup-section">
        <h2>Skills & Workflows</h2>
        {"".join(skill_lines)}
    </div>''')

    # ── Hooks & Safety ──
    hook_lines = []
    if hook_defs:
        hook_events_list = list({h["event"] for h in hook_defs})
        hook_scripts_list = list({h["script"] for h in hook_defs if h["script"] not in ("inline-bash", "unknown")})

        hook_lines.append(f"<p>This harness has <strong>{len(hook_defs)} hooks</strong> configured across {len(hook_events_list)} lifecycle events ({', '.join(he(e) for e in sorted(hook_events_list))}). These hooks fired <strong>{sum(jsonl.get('hook_events', {}).values()):,}</strong> times in the last 30 days — that's roughly {sum(jsonl.get('hook_events', {}).values()) // max(total_sessions, 1)} times per session.</p>")

        # Describe what the hooks do
        script_descs = {
            "dcg": "blocks destructive shell commands (rm -rf, git push --force, etc.) before they execute",
            "validate_file_write.py": "prevents writes to sensitive files (.env, credentials) and paths outside the project",
            "format_and_lint.py": "automatically runs Prettier and ESLint on every file Claude writes or edits",
            "auto_approve.py": "auto-approves low-risk tool calls (web fetch, MCP tools, task management) to reduce permission fatigue",
            "save_session.py": "ensures session state is saved at the end of every conversation for cross-session continuity",
        }
        described = []
        for s in hook_scripts_list:
            desc = script_descs.get(s, "")
            if desc:
                described.append(f"<li><strong>{he(s)}</strong> — {desc}</li>")
            else:
                described.append(f"<li><strong>{he(s)}</strong></li>")
        if described:
            hook_lines.append("<p>The hook scripts and what they do:</p><ul>" + "".join(described) + "</ul>")

        hook_lines.append('<p class="tip">This is a mature safety setup. The combination of destructive command guarding + file write validation + auto-formatting means Claude can work fast with guardrails. If you\'re setting up your own harness, these four hooks cover the most important safety/quality bases.</p>')
    else:
        hook_lines.append("<p>No hooks are configured. Hooks are one of the highest-leverage harness features — they let you add safety guardrails, auto-formatting, and auto-approval without changing how you interact with Claude. Start with a PreToolUse hook on Bash to block destructive commands.</p>")

    sections.append(f'''<div class="writeup-section">
        <h2>Hooks & Safety</h2>
        {"".join(hook_lines)}
    </div>''')

    # ── Plugins ──
    active_plugins = [p["name"] for p in plugins if enabled_plugins.get(p["name"], {}).get("enabled")]
    inactive_plugins = [p["name"] for p in plugins if not enabled_plugins.get(p["name"], {}).get("enabled")]

    plugin_lines = []
    if active_plugins:
        plugin_lines.append(f"<p><strong>{len(active_plugins)} plugins are active</strong>: {', '.join(he(p) for p in active_plugins)}. These add skills, commands, and agent definitions to the harness.</p>")
    if inactive_plugins:
        plugin_lines.append(f"<p>{len(inactive_plugins)} plugins are installed but disabled: {', '.join(he(p) for p in inactive_plugins)}. These were tried and turned off — which is itself useful signal about what didn't stick.</p>")

    sections.append(f'''<div class="writeup-section">
        <h2>Plugins</h2>
        {"".join(plugin_lines)}
    </div>''')

    # ── Project Structure ──
    hf = harness_files
    structure_lines = []
    file_items = []
    if hf.get("global_claude_md"):
        file_items.append(f"a {hf['global_claude_md_lines']}-line global CLAUDE.md with universal rules")
    if hf.get("project_claude_mds"):
        file_items.append(f"{hf['project_claude_mds']} project-level CLAUDE.md files with project-specific instructions")
    if hf.get("project_agents_mds"):
        file_items.append(f"{hf['project_agents_mds']} AGENTS.md files that route agent behavior")
    if hf.get("project_handoffs"):
        file_items.append(f"{hf['project_handoffs']} HANDOFF.md files for cross-session continuity")
    if hf.get("project_workflows"):
        file_items.append(f"{hf['project_workflows']} WORKFLOWS.md files defining step-by-step processes")

    if file_items:
        structure_lines.append(f"<p>This harness uses a layered documentation system: {', '.join(file_items)}.</p>")
        structure_lines.append('<p class="tip">The two-layer CLAUDE.md pattern (global rules + project-specific instructions) is one of the most impactful things you can copy. The global file handles universal preferences (git workflow, code style, response format) while project files handle architecture, commands, and conventions. HANDOFF.md files enable cross-session memory — Claude reads them at session start to pick up where the last session left off.</p>')
    else:
        structure_lines.append("<p>No harness documentation files were found. Adding a CLAUDE.md to your home directory (~/.claude/CLAUDE.md) with your preferences is the single easiest way to improve Claude Code's behavior.</p>")

    sections.append(f'''<div class="writeup-section">
        <h2>Project Structure & Documentation</h2>
        {"".join(structure_lines)}
    </div>''')

    # ── Agent Strategy ──
    agent_count = jsonl.get("agent_count", 0)
    agent_lines = []
    if agent_count > 0:
        agent_types = jsonl.get("agent_types", {})
        agent_models = jsonl.get("agent_models", {})
        bg_pct = jsonl.get("agent_background_pct", 0)

        agent_lines.append(f"<p>This developer spawned <strong>{agent_count} sub-agents</strong> in the last 30 days — that's about {agent_count // max(total_sessions, 1)} per session. {bg_pct}% ran in the background (parallel dispatch).</p>")

        if agent_models:
            model_desc = ", ".join(f"{he(m)} ({c}x)" for m, c in sorted(agent_models.items(), key=lambda x: x[1], reverse=True))
            agent_lines.append(f"<p><strong>Model tiering</strong>: {model_desc}. This is intentional cost/quality optimization — cheaper models for worker tasks, the most capable model for synthesis and judgment calls.</p>")

        if custom_agents:
            names = ", ".join(he(a["name"]) for a in custom_agents)
            agent_lines.append(f"<p><strong>Custom agent definitions</strong>: {names}. These are reusable agent personas defined in ~/.claude/agents/ — each has a specific role, model assignment, and behavioral instructions.</p>")

        agent_lines.append('<p class="tip">Sub-agents are the main way to parallelize work in Claude Code. The pattern of launching 5-10 background agents for research, then synthesizing in the foreground, is particularly effective. Model tiering (sonnet for workers, opus for synthesis) can cut costs significantly without quality loss on the worker tasks.</p>')
    else:
        agent_lines.append("<p>No sub-agents were spawned. Sub-agents let Claude parallelize work — launching multiple research or implementation tasks simultaneously. This is one of the most powerful features in Claude Code and a significant upgrade opportunity.</p>")

    sections.append(f'''<div class="writeup-section">
        <h2>Agent Strategy</h2>
        {"".join(agent_lines)}
    </div>''')

    # ── CLI & Tech Stack ──
    cli_lines = []
    if cli_tools:
        top_tools = sorted(cli_tools.items(), key=lambda x: x[1], reverse=True)[:8]
        tool_names = [t[0] for t in top_tools]

        # Infer stack
        stack_signals = []
        if "vercel" in cli_tools: stack_signals.append("Vercel (deployment)")
        if "npx" in cli_tools or "npm" in cli_tools: stack_signals.append("Node.js/npm ecosystem")
        if "supabase" in cli_tools: stack_signals.append("Supabase (database/auth)")
        if "gh" in cli_tools: stack_signals.append("GitHub CLI")
        if "python3" in cli_tools: stack_signals.append("Python scripting")
        if "codex" in cli_tools: stack_signals.append("OpenAI Codex CLI (multi-AI usage)")
        if "docker" in cli_tools: stack_signals.append("Docker")
        if "brew" in cli_tools: stack_signals.append("Homebrew")

        if stack_signals:
            cli_lines.append(f"<p><strong>Tech stack</strong> (inferred from CLI usage): {', '.join(stack_signals)}.</p>")

        cli_lines.append(f"<p>The most-run CLI commands are: {', '.join(f'<strong>{he(t)}</strong>' for t in tool_names)}. Git dominates at {cli_tools.get('git', 0)} invocations, indicating a commit-heavy, version-control-driven workflow.</p>")

        if "codex" in cli_tools:
            cli_lines.append('<p class="tip">Notably, this developer uses multiple AI coding tools (Claude Code + OpenAI Codex CLI). This multi-tool approach suggests they\'re comparing outputs or using different tools for different strengths.</p>')

    sections.append(f'''<div class="writeup-section">
        <h2>CLI & Tech Stack</h2>
        {"".join(cli_lines)}
    </div>''')

    # ── File Operations ──
    file_lines = []
    if reads + edits + writes > 0:
        total_fops = reads + edits + writes
        r_pct = round(reads / total_fops * 100)
        e_pct = round(edits / total_fops * 100)
        w_pct = round(writes / total_fops * 100)

        if edits > writes * 1.5:
            file_lines.append(f"<p>File operations split {r_pct}% Read / {e_pct}% Edit / {w_pct}% Write — a <strong>surgical editing</strong> style where Claude modifies specific parts of files rather than rewriting them entirely. Edit is used {edits // max(writes, 1)}x more than Write.</p>")
            file_lines.append('<p class="tip">The surgical editing pattern produces cleaner diffs, uses fewer tokens, and causes fewer merge conflicts. You can encourage this by adding "Prefer Edit over Write for existing files" to your CLAUDE.md.</p>')
        else:
            file_lines.append(f"<p>File operations split {r_pct}% Read / {e_pct}% Edit / {w_pct}% Write. This is a write-heavy style, often rewriting entire files.</p>")

    sections.append(f'''<div class="writeup-section">
        <h2>File Operations</h2>
        {"".join(file_lines)}
    </div>''')

    # ── What's Not Being Used ──
    unused_lines = []
    unused_features = []
    if jsonl.get("plan_mode_enters", 0) <= 1:
        unused_features.append(("<strong>Plan Mode</strong>", "lets you review Claude's approach before it starts coding — useful for complex tasks where you want to align on strategy first"))
    if jsonl.get("compaction_events", 0) == 0 and total_sessions > 20:
        unused_features.append(("<strong>Long sessions</strong>", "no context compactions detected, suggesting sessions are kept short. Longer sessions with compaction can maintain complex context across many steps"))
    if not jsonl.get("mcp_servers", {}):
        unused_features.append(("<strong>MCP servers</strong>", "Model Context Protocol lets Claude interact with external tools — browsers, databases, APIs. Playwright for browser testing is a common starting point"))
    task_total = jsonl.get("task_creates", 0)
    if task_total == 0:
        unused_features.append(("<strong>Task tracking</strong>", "TaskCreate/TaskUpdate lets Claude break work into tracked steps — useful for multi-phase implementations where you want visibility into progress"))

    if unused_features:
        items = "".join(f"<li>{name} — {desc}</li>" for name, desc in unused_features)
        unused_lines.append(f"<p>These Claude Code features are available but rarely or never used in this harness:</p><ul>{items}</ul>")
        unused_lines.append('<p class="tip">Not using a feature isn\'t necessarily a problem — sometimes it means the workflow doesn\'t need it. But these are worth knowing about in case your workflow evolves.</p>')

    if unused_lines:
        sections.append(f'''<div class="writeup-section">
            <h2>Opportunities</h2>
            {"".join(unused_lines)}
        </div>''')

    # ── Error Resilience ──
    error_rate = jsonl.get("error_rate_pct", 0)
    error_lines = []
    if error_rate > 0:
        if error_rate < 5:
            error_lines.append(f"<p>Tool error rate is <strong>{error_rate}%</strong> — low. The harness is well-tuned and Claude rarely hits dead ends.</p>")
        elif error_rate < 15:
            error_lines.append(f"<p>Tool error rate is <strong>{error_rate}%</strong> — moderate. This is typical for workflows that include deployment, API calls, or shell commands where failures are expected. Claude retries aggressively, so most errors self-resolve.</p>")
        else:
            error_lines.append(f"<p>Tool error rate is <strong>{error_rate}%</strong> — above average. This may indicate Claude is attempting operations without sufficient context, or the project has complex setup requirements.</p>")

    if error_lines:
        sections.append(f'''<div class="writeup-section">
            <h2>Error Resilience</h2>
            {"".join(error_lines)}
        </div>''')

    return "\n".join(sections)


def _render_insights_tab(insights_report):
    """Render the /insights report content as a tab, or empty string if not available."""
    if not insights_report:
        return ""

    sections_html = []
    for section in insights_report.get("sections", []):
        title = section["title"]
        content = section["content"]
        sections_html.append(f'''
<div class="writeup-section">
    <h2>{title}</h2>
    {content}
</div>''')

    subtitle = insights_report.get("subtitle", "")
    modified = insights_report.get("modified", "")

    return f'''
<!-- Insights Report tab -->
<div id="tab-insights" class="tab-content">
    <div class="writeup-section">
        <p style="font-size:0.85rem; color:var(--ink-muted); margin-bottom:1.5rem;">
            From /insights report &middot; {subtitle} &middot; Generated {modified}
        </p>
    </div>
    {"".join(sections_html)}
</div>'''


def generate_html(data):
    now = datetime.now()
    period_start = now - timedelta(days=DAYS)
    meta = data["session_meta_summary"]
    jsonl = data["jsonl_metadata"]
    settings = data["settings"]
    skills = data["skill_inventory"]
    plugins = data["installed_plugins"]
    perms = data["permissions_profile"]
    harness_files = data["harness_files"]
    integrity_block = json.dumps(data.get("_integrity", {}))  # pre-computed for f-string safety
    custom_agents = data["custom_agents"]
    # New config layer data
    safety = data.get("safety_posture", {})
    experimental = data.get("experimental", {})
    stats_cache = data.get("stats_cache", {})
    instr_maturity = data.get("instruction_maturity", {})
    memory_arch = data.get("memory_arch", {})
    agent_det = data.get("agent_details", {})
    team_cfg = data.get("team_configs", {})
    mkt = data.get("marketplace", {})
    statusline_info = data.get("statusline", {})
    ide_info = data.get("ide", {})
    hybrid = data.get("hybrid_tools", {})
    blocklist_info = data.get("blocklist", {})
    perm_accum = data.get("perm_accumulation", {})

    total_sessions = jsonl.get("sessions_with_data", meta.get("session_count", 0))
    total_tokens = (jsonl.get("total_input_tokens", 0) + jsonl.get("total_output_tokens", 0)) or meta.get("total_tokens", 0)
    lifetime_tokens = stats_cache.get("lifetime_tokens", 0)
    total_hours = meta.get("total_duration_hours", 0)
    avg_duration = meta.get("avg_duration_minutes", 0)

    tool_counts = Counter(jsonl.get("tool_usage", {}))
    for t, c in meta.get("tool_counts", {}).items():
        if t not in tool_counts:
            tool_counts[t] = c

    # Privacy: skill_invocations is already filtered against the private/none
    # deny-set in main() before being placed in jsonl_metadata, so every
    # consumer (writeup, HTML, JSON, workflowData) sees the filtered counter.
    skill_invocations = jsonl.get("skill_invocations", {})
    hook_defs = settings.get("hooks", [])
    hook_events = jsonl.get("hook_events", {})
    total_hook_fires = sum(hook_events.values())
    languages = meta.get("languages", {})
    models = jsonl.get("models", {})
    perm_modes = jsonl.get("permission_modes", {})
    mcp_servers = jsonl.get("mcp_servers", {})
    enabled_plugins = settings.get("enabled_plugins", {})
    cli_tools = jsonl.get("cli_tools", {})
    branch_prefixes = jsonl.get("branch_prefixes", {})
    tool_transitions = jsonl.get("tool_transitions", {})
    workflow_patterns = jsonl.get("workflow_patterns", [])
    phase_transitions = jsonl.get("phase_transitions", {})
    phase_distribution = jsonl.get("phase_distribution", {})
    phase_stats = jsonl.get("phase_stats", {})

    # File operation ratios
    reads = tool_counts.get("Read", 0)
    edits = tool_counts.get("Edit", 0)
    writes = tool_counts.get("Write", 0)
    total_file_ops = reads + edits + writes
    greps = tool_counts.get("Grep", 0)
    globs = tool_counts.get("Glob", 0)

    # Autonomy
    ar = jsonl.get("autonomy_ratio", 0)
    median_turn_s = round(jsonl.get("median_turn_ms", 0) / 1000)
    avg_turn_s = round(jsonl.get("avg_turn_ms", 0) / 1000)
    max_turn_m = round(jsonl.get("max_turn_ms", 0) / 60000, 1)
    if ar > 0 and ar < 0.15:
        autonomy_label = "Fire-and-Forget"
    elif ar < 0.4:
        autonomy_label = "Directive"
    else:
        autonomy_label = "Collaborative"

    def fmt(n):
        if isinstance(n, float):
            if n >= 1_000_000_000: return f"{n/1_000_000_000:.1f}B"
            if n >= 1_000_000: return f"{n/1_000_000:.1f}M"
            if n >= 1_000: return f"{n/1_000:.1f}K"
            return f"{n:.1f}"
        if n >= 1_000_000_000: return f"{n/1_000_000_000:.1f}B"
        if n >= 1_000_000: return f"{n/1_000_000:.1f}M"
        if n >= 1_000: return f"{n/1_000:.1f}K"
        return str(n)

    def bar_width(val, max_val):
        return f"{max(3, int(val / max_val * 100))}%" if max_val > 0 else "3%"

    def make_bar_chart(items, color="#1e3a5f", max_items=12):
        if not items:
            return '<p class="empty">No data</p>'
        si = sorted(items.items(), key=lambda x: x[1], reverse=True)[:max_items]
        mx = si[0][1] if si else 1
        rows = []
        for name, count in si:
            w = bar_width(count, mx)
            rows.append(f'<div class="bar-row"><div class="bar-label">{he(name)}</div>'
                       f'<div class="bar-track"><div class="bar-fill" style="width:{w};background:{color}"></div></div>'
                       f'<div class="bar-value">{fmt(count)}</div></div>')
        return "\n".join(rows)

    def he(s):
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

    def pct(part, total):
        return round(part / total * 100) if total > 0 else 0

    # Build skill metadata lookup from inventory
    skill_meta = {}
    for s in skills:
        skill_meta[s["name"]] = s
        # Also index by full name for plugin skills like "compound-engineering:git-commit"
        if ":" in s.get("name", ""):
            skill_meta[s["name"]] = s

    # Skill rows with source badge and description
    skill_rows_list = []
    for n, c in sorted(skill_invocations.items(), key=lambda x: x[1], reverse=True)[:20]:
        sm = skill_meta.get(n, {})
        # Determine source type
        src = sm.get("source", "")
        if src == "user":
            badge = '<span class="badge custom">custom</span>'
        elif src == "command":
            badge = '<span class="badge custom">command</span>'
        elif src.startswith("plugin:"):
            badge = f'<span class="badge plugin">plugin</span>'
        else:
            # Try to infer from name
            if ":" in n:
                badge = '<span class="badge plugin">plugin</span>'
            else:
                badge = '<span class="badge custom">custom</span>'
        desc = sm.get("description", "")
        desc_html = f'<div class="meta" style="margin-top:0.15rem">{he(desc)}</div>' if desc else ""
        skill_rows_list.append(
            f'<tr><td><span class="mono accent">{he(n)}</span> {badge}{desc_html}</td><td class="r">{c}</td></tr>'
        )
    skill_rows = "".join(skill_rows_list) or '<tr><td colspan="2" class="empty">No skill invocations</td></tr>'

    # Hook rows
    hook_rows = "".join(
        f'<tr><td class="mono amber">{he(h["event"])}</td><td>{he(h["matcher"])}</td><td class="mono">{he(h["script"])}</td></tr>'
        for h in hook_defs
    ) or '<tr><td colspan="3" class="empty">No hooks defined</td></tr>'

    # Plugin cards
    plugin_cards = "".join(
        f'<div class="plugin-card"><div class="plugin-header"><span class="plugin-name">{he(p["name"])}</span>'
        f'<span class="badge {"active" if enabled_plugins.get(p["name"],{}).get("enabled") else "inactive"}">'
        f'{"on" if enabled_plugins.get(p["name"],{}).get("enabled") else "off"}</span></div>'
        f'<div class="meta">v{he(p["version"])} &middot; {he(p["marketplace"])}</div></div>'
        for p in plugins
    ) or '<p class="empty">No plugins</p>'

    # Permission mode rows
    total_perm = sum(perm_modes.values()) or 1
    perm_items = "".join(
        f'<div class="kv-row"><span class="mono purple">{he(m)}</span><span class="meta">{round(c/total_perm*100)}%</span></div>'
        for m, c in sorted(perm_modes.items(), key=lambda x: x[1], reverse=True)
    )

    # MCP rows
    mcp_items = "".join(
        f'<div class="kv-row"><span class="mono accent">{he(s)}</span><span class="meta">{fmt(c)} calls</span></div>'
        for s, c in sorted(mcp_servers.items(), key=lambda x: x[1], reverse=True)[:10]
    )

    # Agent types
    agent_type_items = "".join(
        f'<div class="kv-row"><span class="mono">{he(t)}</span><span class="meta">{c}</span></div>'
        for t, c in sorted(jsonl.get("agent_types", {}).items(), key=lambda x: x[1], reverse=True)
    )

    # Agent model tiering
    agent_model_items = "".join(
        f'<div class="kv-row"><span class="mono">{he(m)}</span><span class="meta">{c}</span></div>'
        for m, c in sorted(jsonl.get("agent_models", {}).items(), key=lambda x: x[1], reverse=True)
    )

    # Branch prefix items
    branch_items = "".join(
        f'<span class="tag">{he(p)}/ ({c})</span>' for p, c in sorted(branch_prefixes.items(), key=lambda x: x[1], reverse=True)[:6]
    )

    # Workflow Phases HTML
    phase_dist_items = "".join(
        f'<div class="kv-row"><span class="mono">{he(phase)}</span><span class="meta">{pct_val}%</span></div>'
        for phase, pct_val in sorted(phase_distribution.items(), key=lambda x: x[1], reverse=True)
    ) if phase_distribution else ""

    phase_trans_items = "".join(
        f'<div class="bar-row"><div class="bar-label">{he(k)}</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{bar_width(v, max(phase_transitions.values()) if phase_transitions else 1)};background:var(--purple)"></div></div>'
        f'<div class="bar-value">{v}</div></div>'
        for k, v in sorted(phase_transitions.items(), key=lambda x: x[1], reverse=True)[:12]
    ) if phase_transitions else ""

    # Skill Workflow HTML — 2 sub-groups separated by footnote divs
    _skill_max = max(skill_invocations.values()) if skill_invocations else 1
    skill_inv_items = "".join(
        f'<div class="bar-row"><div class="bar-label">{he(k)}</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{bar_width(v, _skill_max)};background:var(--accent)"></div></div>'
        f'<div class="bar-value">{v}</div></div>'
        for k, v in sorted(skill_invocations.items(), key=lambda x: x[1], reverse=True)[:20]
    ) if skill_invocations else ""

    _pattern_max = max((p["count"] for p in workflow_patterns), default=1)
    workflow_pat_items = "".join(
        f'<div class="bar-row"><div class="bar-label">{he(" → ".join(p["sequence"]))}</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{bar_width(p["count"], _pattern_max)};background:var(--teal)"></div></div>'
        f'<div class="bar-value">{p["count"]}</div></div>'
        for p in workflow_patterns[:10]
    ) if workflow_patterns else ""

    # Custom agent list
    agent_list = "".join(f'<span class="tag">{he(a["name"])}</span>' for a in custom_agents)

    # Version tags
    version_tags = "".join(
        f'<span class="tag">{he(v)}</span>' for v, _ in sorted(jsonl.get("versions", {}).items(), key=lambda x: x[1], reverse=True)[:5]
    )

    # Harness files
    hf = harness_files
    hf_items = []
    if hf.get("global_claude_md"): hf_items.append(f'~/.claude/CLAUDE.md ({hf["global_claude_md_lines"]} lines)')
    if hf.get("project_claude_mds"): hf_items.append(f'{hf["project_claude_mds"]} project CLAUDE.md files')
    if hf.get("project_agents_mds"): hf_items.append(f'{hf["project_agents_mds"]} project AGENTS.md files')
    if hf.get("project_handoffs"): hf_items.append(f'{hf["project_handoffs"]} HANDOFF.md files')
    if hf.get("project_workflows"): hf_items.append(f'{hf["project_workflows"]} WORKFLOWS.md files')
    hf_html = "".join(f'<div class="file-item">{he(f)}</div>' for f in hf_items)

    # ── Build embedded JSON data blob (matches HarnessData TS interface) ────
    # Parse writeup sections from generate_writeup() output
    _writeup_html = generate_writeup(data)
    _writeup_sections_json = []
    for _m in re.finditer(
        r'<div class="writeup-section">\s*<h2>(.*?)</h2>(.*?)</div>\s*(?=<div class="writeup-section">|$)',
        _writeup_html,
        re.DOTALL,
    ):
        _writeup_sections_json.append({
            "title": _m.group(1).strip(),
            "contentHtml": _m.group(2).strip(),
        })

    # Feature pills array
    _feature_pills = [
        {"name": "Status Line", "active": bool(settings.get("has_statusline")), "value": ""},
        {"name": "Task Agents", "active": meta.get("uses_task_agent_pct", 0) > 0, "value": f'{meta.get("uses_task_agent_pct", 0)}%'},
        {"name": "MCP", "active": meta.get("uses_mcp_pct", 0) > 0, "value": f'{meta.get("uses_mcp_pct", 0)}%'},
        {"name": "Web Search", "active": meta.get("uses_web_search_pct", 0) > 0, "value": f'{meta.get("uses_web_search_pct", 0)}%'},
        {"name": "Sub-Agents", "active": jsonl.get("agent_count", 0) > 0, "value": str(jsonl.get("agent_count", 0))},
        {"name": "Tasks", "active": jsonl.get("task_creates", 0) > 0, "value": str(jsonl.get("task_creates", 0))},
        {"name": "Plan Mode", "active": jsonl.get("plan_mode_enters", 0) > 0, "value": str(jsonl.get("plan_mode_enters", 0))},
        {"name": "Compactions", "active": jsonl.get("compaction_events", 0) > 0, "value": str(jsonl.get("compaction_events", 0))},
    ]

    # Skill inventory array. skill_invocations is already filtered against the
    # private/none deny-set at the top of generate_html, so iterating it here
    # is enough to keep private skills out of the public payload.
    _skill_inventory_json = []
    for n, c in sorted(skill_invocations.items(), key=lambda x: x[1], reverse=True)[:20]:
        sm = skill_meta.get(n, {})
        src = sm.get("source", "")
        if not src:
            src = "plugin" if ":" in n else "custom"
        entry = {
            "name": n,
            "calls": c,
            "source": src,
            "description": sm.get("description", ""),
        }
        # Showcase fields — present only when extract was run with --include-skills
        # AND the skill survived the repo: private/none filter. _stage() in
        # extract_skill_inventory always sets all four when include_showcase=True,
        # so presence of any one signals the rest are intentional (possibly None).
        if "readme_markdown" in sm:
            entry["readme_markdown"] = sm.get("readme_markdown")
            entry["hero_base64"] = sm.get("hero_base64")
            entry["hero_mime_type"] = sm.get("hero_mime_type")
            entry["category"] = sm.get("category")
        _skill_inventory_json.append(entry)

    # Hook definitions array
    _hook_defs_json = [
        {"event": h.get("event", ""), "matcher": h.get("matcher", ""), "script": h.get("script", "")}
        for h in hook_defs
    ]

    # Plugins array
    _plugins_json = [
        {
            "name": p["name"],
            "version": p.get("version", ""),
            "marketplace": p.get("marketplace", ""),
            "active": bool(enabled_plugins.get(p["name"], {}).get("enabled")),
        }
        for p in plugins
    ]

    # Harness files as string array
    _harness_files_json = hf_items  # already built as string list

    # File operation style
    _file_op_style = {
        "readPct": pct(reads, total_file_ops),
        "editPct": pct(edits, total_file_ops),
        "writePct": pct(writes, total_file_ops),
        "grepCount": greps,
        "globCount": globs,
        "style": "Surgical Editor" if edits > writes * 1.5 else "Full-File Writer",
    }

    # Agent dispatch (or null)
    _agent_dispatch = None
    if jsonl.get("agent_count", 0) > 0:
        _agent_dispatch = {
            "totalAgents": jsonl.get("agent_count", 0),
            "types": dict(jsonl.get("agent_types", {})),
            "models": dict(jsonl.get("agent_models", {})),
            "backgroundPct": jsonl.get("agent_background_pct", 0),
            "customAgents": [a["name"] for a in custom_agents],
        }

    # Git patterns
    _git_patterns = {
        "prCount": jsonl.get("pr_count", 0),
        "commitCount": meta.get("total_git_commits", 0),
        "linesAdded": fmt(meta.get("total_lines_added", 0)),
        "branchPrefixes": dict(branch_prefixes),
    }

    # Workflow data (or null)
    _workflow_data = None
    if skill_invocations or workflow_patterns or phase_transitions or phase_distribution:
        _workflow_data = {
            "skillInvocations": dict(skill_invocations),
            "agentDispatches": dict(jsonl.get("agent_dispatches", {})) if jsonl.get("agent_dispatches") else {},
            "workflowPatterns": [{"sequence": p["sequence"], "count": p["count"]} for p in workflow_patterns],
            "phaseTransitions": dict(phase_transitions),
            "phaseDistribution": dict(phase_distribution),
            "phaseStats": {
                "testBeforeShipPct": phase_stats.get("test_before_ship_pct", 0),
                "exploreBeforeImplPct": phase_stats.get("explore_before_impl_pct", 0),
                "totalSessionsWithPhases": phase_stats.get("total_sessions_with_phases", 0),
            },
        }

    # Autonomy description
    _autonomy_desc = f"1 human turn per {round(1/ar) if ar > 0 else '?'} Claude turns"

    # Versions
    _versions = list(jsonl.get("versions", {}).keys()) if isinstance(jsonl.get("versions"), dict) else []

    # Integrity hash from pre-computed data
    _integrity = data.get("_integrity", {})
    _integrity_hash = _integrity.get("hash", "")

    # Enhanced stats (fields the upload route currently scrapes from HTML)
    _enhanced_stats = {
        "linesAdded": meta.get("total_lines_added", None),
        "linesRemoved": meta.get("total_lines_removed", None),
        "fileCount": None,  # not tracked by extract.py currently
        "dayCount": DAYS,
        "msgsPerDay": stats_cache.get("avg_daily_messages", None),
    }

    harness_json = {
        "stats": {
            "totalTokens": total_tokens,
            "lifetimeTokens": lifetime_tokens,
            "durationHours": total_hours,
            "avgSessionMinutes": round(avg_duration, 1),
            "skillsUsedCount": len(skill_invocations),
            "hooksCount": len(hook_defs),
            "prCount": jsonl.get("pr_count", 0),
            "sessionCount": total_sessions,
            "commitCount": meta.get("total_git_commits", 0),
        },
        "autonomy": {
            "label": autonomy_label,
            "description": _autonomy_desc,
            "userMessages": jsonl.get("user_messages", 0),
            "assistantMessages": jsonl.get("assistant_messages", 0),
            "turnCount": jsonl.get("turn_count", 0),
            "errorRate": f'{jsonl.get("error_rate_pct", 0)}%',
        },
        "featurePills": _feature_pills,
        "toolUsage": dict(tool_counts),
        "skillInventory": _skill_inventory_json,
        "hookDefinitions": _hook_defs_json,
        "hookFrequency": dict(hook_events),
        "plugins": _plugins_json,
        "harnessFiles": _harness_files_json,
        "fileOpStyle": _file_op_style,
        "agentDispatch": _agent_dispatch,
        "cliTools": dict(cli_tools),
        "languages": dict(languages),
        "models": dict(models),
        "permissionModes": dict(perm_modes),
        "mcpServers": dict(mcp_servers),
        "gitPatterns": _git_patterns,
        "versions": _versions,
        "writeupSections": _writeup_sections_json,
        "workflowData": _workflow_data,
        "integrityHash": _integrity_hash,
        "skillVersion": VERSION,
        "enhancedStats": _enhanced_stats,
        "perModelTokens": stats_cache.get("model_tokens", {}),
    }

    # Global showcase budget — enforced ONCE here at assembly time, not in
    # extract_skill_inventory(), because the real harness_json is built here
    # and the budget needs to account for non-showcase fields, JSON escaping,
    # and the HTML wrapper. See plan docs/plans/2026-04-12-002 → "Storage Decision".
    _enforce_showcase_budget(harness_json, MAX_HARNESS_JSON_BYTES)

    _harness_json_str = json.dumps(harness_json)
    # Mandatory: escape </script> to prevent breaking the script tag
    _harness_json_str = _harness_json_str.replace("</script>", r"<\/script>")

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Harness Profile</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Sans:wght@300;400;500;600;700&family=Source+Code+Pro:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {{
  --serif: "DM Serif Display", Georgia, serif;
  --sans: "DM Sans", -apple-system, sans-serif;
  --mono: "Source Code Pro", monospace;
  --ink: #1a1a1a;
  --ink-light: #3a3a3a;
  --ink-muted: #666;
  --bg: #f8f7f4;
  --bg-card: #fff;
  --bg-alt: #eef2f5;
  --accent: #1e3a5f;
  --accent-light: #eaf2f8;
  --teal: #4a90a4;
  --amber: #b45309;
  --amber-light: #fef3c7;
  --green: #2d6a4f;
  --green-light: #ecfdf5;
  --purple: #6b21a8;
  --purple-light: #f5f0ff;
  --red: #c0392b;
  --red-light: #fef2f2;
  --border: #d1d5db;
  --border-light: #e5e7eb;
  --sand: #d4a574;
}}
*,*::before,*::after {{ box-sizing:border-box; margin:0; padding:0; }}
html {{ font-size:19px; }}
body {{ font-family:var(--sans); color:var(--ink); background:var(--bg); line-height:1.6; padding:3rem 1.5rem; -webkit-font-smoothing:antialiased; }}
.container {{ max-width:820px; margin:0 auto; }}
.masthead {{ margin-bottom:2.5rem; padding-bottom:1.5rem; border-bottom:2px solid var(--ink); }}
.masthead-label {{ font-size:0.62rem; font-weight:600; letter-spacing:0.14em; text-transform:uppercase; color:var(--teal); margin-bottom:0.4rem; }}
.masthead h1 {{ font-family:var(--serif); font-size:2.6rem; color:var(--ink); font-weight:400; margin-bottom:0.5rem; line-height:1.1; }}
.masthead .subtitle {{ font-size:0.82rem; color:var(--ink-muted); }}
.stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(100px,1fr)); gap:1px; background:var(--border-light); border:1px solid var(--border-light); border-radius:8px; overflow:hidden; margin:1.5rem 0; }}
.stat {{ background:var(--bg-card); padding:1rem 0.8rem; text-align:center; }}
.stat-value {{ font-family:var(--serif); font-size:1.5rem; color:var(--ink); line-height:1; }}
.stat-label {{ font-size:0.65rem; font-weight:600; color:var(--ink-muted); letter-spacing:0.08em; text-transform:uppercase; margin-top:0.3rem; }}
section {{ margin-bottom:2.5rem; }}
.section-header {{ display:flex; align-items:baseline; gap:0.6rem; margin-bottom:1rem; padding-bottom:0.6rem; border-bottom:1px solid var(--border-light); }}
.section-header h2 {{ font-family:var(--serif); font-size:1.25rem; color:var(--ink); font-weight:400; }}
.section-header .count {{ font-family:var(--mono); font-size:0.72rem; color:var(--ink-muted); }}
.bar-row {{ display:grid; grid-template-columns:150px 1fr 50px; gap:0.5rem; align-items:center; padding:0.25rem 0; }}
.bar-label {{ font-family:var(--mono); font-size:0.78rem; color:var(--ink-light); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.bar-track {{ height:8px; background:var(--border-light); border-radius:4px; overflow:hidden; }}
.bar-fill {{ height:100%; border-radius:4px; }}
.bar-value {{ font-family:var(--mono); font-size:0.75rem; color:var(--ink-muted); text-align:right; }}
table {{ width:100%; border-collapse:collapse; font-size:0.85rem; }}
th {{ text-align:left; font-weight:600; color:var(--ink-muted); font-size:0.68rem; letter-spacing:0.08em; text-transform:uppercase; padding:0.5rem 0.7rem; border-bottom:2px solid var(--border-light); }}
td {{ padding:0.5rem 0.7rem; border-bottom:1px solid var(--border-light); color:var(--ink-light); }}
td.r {{ text-align:right; }}
.mono {{ font-family:var(--mono); font-size:0.82rem; }}
.accent {{ color:var(--accent); }}
.amber {{ color:var(--amber); }}
.purple {{ color:var(--purple); }}
.card-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:0.6rem; }}
.plugin-card {{ background:var(--bg-card); border:1px solid var(--border-light); border-radius:6px; padding:0.7rem 0.9rem; }}
.plugin-header {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:0.2rem; }}
.plugin-name {{ font-family:var(--mono); font-size:0.75rem; font-weight:600; color:var(--ink); }}
.badge {{ font-size:0.62rem; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; padding:0.15rem 0.5rem; border-radius:3px; }}
.badge.active {{ background:var(--green-light); color:var(--green); }}
.badge.inactive {{ background:var(--bg-alt); color:var(--ink-muted); }}
.badge.custom {{ background:var(--purple-light); color:var(--purple); }}
.badge.plugin {{ background:var(--accent-light); color:var(--accent); }}
.meta {{ font-size:0.75rem; color:var(--ink-muted); }}
.two-col {{ display:grid; grid-template-columns:1fr 1fr; gap:1.5rem; }}
@media(max-width:600px) {{ .two-col {{ grid-template-columns:1fr; }} .bar-row {{ grid-template-columns:90px 1fr 35px; }} }}
.kv-row {{ display:flex; justify-content:space-between; padding:0.4rem 0; border-bottom:1px solid var(--border-light); font-size:0.85rem; }}
.tag {{ font-family:var(--mono); font-size:0.75rem; color:var(--ink-light); background:var(--bg-alt); border:1px solid var(--border-light); padding:0.2rem 0.6rem; border-radius:4px; display:inline-block; margin:0.15rem; }}
.tags {{ display:flex; flex-wrap:wrap; gap:0.35rem; }}
.empty {{ font-size:0.82rem; color:var(--ink-muted); font-style:italic; }}
.footnote {{ font-size:0.7rem; font-weight:600; text-transform:uppercase; letter-spacing:0.06em; color:var(--ink-muted); margin:1rem 0 0.4rem; padding-bottom:0.25rem; border-bottom:1px solid var(--border-light); }}
.footnote:first-child {{ margin-top:0; }}
.pills {{ display:flex; flex-wrap:wrap; gap:0.4rem; margin:1rem 0 1.5rem; }}
.pill {{ font-size:0.72rem; font-weight:600; padding:0.3rem 0.7rem; border-radius:20px; letter-spacing:0.03em; border:1px solid transparent; }}
.pill.on {{ background:var(--green-light); color:var(--green); border-color:rgba(45,106,79,0.2); }}
.pill.off {{ background:transparent; color:var(--ink-muted); border-color:var(--border-light); }}
.autonomy-box {{ background:var(--accent); color:#fff; border-radius:10px; padding:1.8rem 2rem; margin-bottom:2rem; position:relative; overflow:hidden; }}
.autonomy-box::after {{ content:''; position:absolute; top:-40px; right:-40px; width:200px; height:200px; background:rgba(255,255,255,0.06); border-radius:50%; pointer-events:none; }}
.autonomy-label {{ font-family:var(--serif); font-size:1.8rem; color:#fff; }}
.autonomy-desc {{ font-size:0.82rem; color:rgba(255,255,255,0.75); margin-top:0.4rem; }}
.autonomy-stats {{ display:flex; gap:1.8rem; margin-top:1rem; flex-wrap:wrap; padding-top:0.8rem; border-top:1px solid rgba(255,255,255,0.15); }}
.autonomy-stat {{ font-size:0.72rem; color:rgba(255,255,255,0.6); }}
.autonomy-stat strong {{ color:#fff; font-size:0.88rem; }}
.donut-row {{ display:flex; gap:2rem; align-items:center; flex-wrap:wrap; }}
.donut-item {{ text-align:center; }}
.donut-item .label {{ font-size:0.75rem; color:var(--ink-muted); margin-top:0.3rem; }}
.donut-item .ratio {{ font-family:var(--mono); font-size:1rem; font-weight:600; color:var(--ink); }}
.file-item {{ font-family:var(--mono); font-size:0.82rem; color:var(--ink-light); padding:0.35rem 0; border-bottom:1px solid var(--border-light); }}
.table-wrapper {{ overflow-x:auto; }}
footer {{ border-top:1px solid var(--border-light); padding-top:1.2rem; margin-top:2rem; text-align:center; font-size:0.6rem; color:var(--ink-muted); }}
h3 {{ font-size:0.8rem; font-weight:600; color:var(--ink); margin:1rem 0 0.5rem; }}
.tabs {{ display:flex; gap:0; border-bottom:2px solid var(--border-light); margin:2rem 0 0; }}
.tab {{ font-family:var(--sans); font-size:0.85rem; font-weight:600; padding:0.7rem 1.5rem; cursor:pointer; color:var(--ink-muted); border:none; background:none; border-bottom:2px solid transparent; margin-bottom:-2px; transition:all 0.15s; }}
.tab:hover {{ color:var(--ink-light); }}
.tab.active {{ color:var(--accent); border-bottom-color:var(--accent); }}
.tab-content {{ display:none; padding-top:2rem; }}
.tab-content.active {{ display:block; }}
.writeup-section {{ margin-bottom:2.5rem; }}
.writeup-section h2 {{ font-family:var(--serif); font-size:1.3rem; color:var(--ink); font-weight:400; margin-bottom:0.8rem; padding-bottom:0.4rem; border-bottom:1px solid var(--border-light); }}
.writeup-section p {{ font-size:0.92rem; color:var(--ink-light); line-height:1.7; margin-bottom:0.8rem; }}
.writeup-section ul {{ margin:0.5rem 0 1rem 1.2rem; }}
.writeup-section li {{ font-size:0.88rem; color:var(--ink-light); line-height:1.65; margin-bottom:0.5rem; }}
.writeup-section strong {{ color:var(--ink); }}
.writeup-section .tip {{ background:var(--accent-light); border-left:3px solid var(--accent); padding:0.8rem 1rem; border-radius:0 6px 6px 0; font-size:0.85rem; color:var(--accent); margin:1rem 0; }}
</style>
</head>
<body>
<div class="container">

<header class="masthead">
    <div class="masthead-label">Harness Profile</div>
    <h1>Your Claude Code Setup</h1>
    <div class="subtitle">{period_start.strftime("%b %d")} &ndash; {now.strftime("%b %d, %Y")} &middot; {total_sessions} sessions &middot; {DAYS} days</div>
</header>

<div class="stats-grid">
    <div class="stat"><div class="stat-value">{total_sessions}</div><div class="stat-label">Sessions</div></div>
    <div class="stat"><div class="stat-value">{fmt(total_tokens)}</div><div class="stat-label">Tokens</div></div>
    <div class="stat"><div class="stat-value">{fmt(lifetime_tokens)}</div><div class="stat-label">Lifetime Tokens</div></div>
    <div class="stat"><div class="stat-value">{total_hours}h</div><div class="stat-label">Duration</div></div>
    <div class="stat"><div class="stat-value">{avg_duration:.0f}m</div><div class="stat-label">Avg Session</div></div>
    <div class="stat"><div class="stat-value">{len(skill_invocations)}</div><div class="stat-label">Skills Used</div></div>
    <div class="stat"><div class="stat-value">{len(hook_defs)}</div><div class="stat-label">Hooks</div></div>
    <div class="stat"><div class="stat-value">{meta.get("total_git_commits", 0)}</div><div class="stat-label">Commits</div></div>
    <div class="stat"><div class="stat-value">{jsonl.get("pr_count", 0)}</div><div class="stat-label">PRs</div></div>
</div>

<!-- Autonomy Style -->
<div class="autonomy-box">
    <div class="autonomy-label">{autonomy_label}</div>
    <div class="autonomy-desc">1 human turn per {round(1/ar) if ar > 0 else '?'} Claude turns &middot; Median turn {median_turn_s}s &middot; Longest run {max_turn_m}m</div>
    <div class="autonomy-stats">
        <div class="autonomy-stat"><strong>{jsonl.get("user_messages", 0)}</strong> user msgs</div>
        <div class="autonomy-stat"><strong>{jsonl.get("assistant_messages", 0)}</strong> assistant msgs</div>
        <div class="autonomy-stat"><strong>{jsonl.get("turn_count", 0)}</strong> turns measured</div>
        <div class="autonomy-stat"><strong>{jsonl.get("error_rate_pct", 0)}%</strong> error rate ({jsonl.get("tool_errors", 0)}/{jsonl.get("total_tool_calls", 0)})</div>
    </div>
</div>

<!-- Tabs -->
<div class="tabs">
    <button class="tab active" onclick="switchTab('dashboard')">Dashboard</button>
    <button class="tab" onclick="switchTab('writeup')">Writeup</button>
    {"<button class='tab' onclick=\"switchTab('insights')\">Insights Report</button>" if data.get("insights_report") else ""}
</div>

<div id="tab-dashboard" class="tab-content active">

<!-- Feature Pills -->
<div class="pills">
    <span class="pill {"on" if settings.get("has_statusline") else "off"}">Status Line</span>
    <span class="pill {"on" if meta.get("uses_task_agent_pct", 0) > 0 else "off"}">Task Agents ({meta.get("uses_task_agent_pct", 0)}%)</span>
    <span class="pill {"on" if meta.get("uses_mcp_pct", 0) > 0 else "off"}">MCP ({meta.get("uses_mcp_pct", 0)}%)</span>
    <span class="pill {"on" if meta.get("uses_web_search_pct", 0) > 0 else "off"}">Web Search ({meta.get("uses_web_search_pct", 0)}%)</span>
    <span class="pill {"on" if jsonl.get("agent_count", 0) > 0 else "off"}">Sub-Agents ({jsonl.get("agent_count", 0)})</span>
    <span class="pill {"on" if jsonl.get("task_creates", 0) > 0 else "off"}">Tasks ({jsonl.get("task_creates", 0)})</span>
    <span class="pill {"on" if jsonl.get("plan_mode_enters", 0) > 0 else "off"}">Plan Mode ({jsonl.get("plan_mode_enters", 0)})</span>
    <span class="pill {"on" if jsonl.get("compaction_events", 0) > 0 else "off"}">Compactions ({jsonl.get("compaction_events", 0)})</span>
</div>

<!-- TIER 1: Directly Copyable -->

<!-- Skills -->
<section style="margin-top:1.5rem">
    <div class="section-header"><h2>Skills &amp; Commands</h2><span class="count">{sum(skill_invocations.values())} invocations</span></div>
    <div class="table-wrapper"><table>
        <thead><tr><th>Skill</th><th style="text-align:right">Calls</th></tr></thead>
        <tbody>{skill_rows}</tbody>
    </table></div>
    <div style="display:flex;gap:1.5rem;margin-top:0.8rem;flex-wrap:wrap">
        <div class="meta"><strong style="color:var(--ink)">{len([s for s in skills if s["source"]=="user"])}</strong> user skills</div>
        <div class="meta"><strong style="color:var(--ink)">{len([s for s in skills if s["source"].startswith("plugin:")])}</strong> plugin skills</div>
        <div class="meta"><strong style="color:var(--ink)">{len([s for s in skills if s["source"]=="command"])}</strong> commands</div>
    </div>
</section>

<!-- Hooks -->
<section>
    <div class="section-header"><h2>Hooks</h2><span class="count">{len(hook_defs)} defs &middot; {fmt(total_hook_fires)} fires</span></div>
    <div class="table-wrapper"><table>
        <thead><tr><th>Event</th><th>Matcher</th><th>Script</th></tr></thead>
        <tbody>{hook_rows}</tbody>
    </table></div>
    {"<h3>Hook Execution Frequency</h3>" + make_bar_chart(hook_events, "var(--amber)", 10) if hook_events else ""}
</section>

<!-- Plugins -->
<section>
    <div class="section-header"><h2>Plugins</h2><span class="count">{len(plugins)} installed</span></div>
    <div class="card-grid">{plugin_cards}</div>
</section>

<!-- Harness Files -->
<section>
    <div class="section-header"><h2>Harness File Ecosystem</h2></div>
    {hf_html or '<p class="empty">No harness files found</p>'}
</section>

<!-- TIER 2: Workflow Philosophy -->

<!-- File Operation Style -->
<section>
    <div class="section-header"><h2>File Operation Style</h2></div>
    <div class="donut-row">
        <div class="donut-item">
            <div class="ratio">{pct(reads, total_file_ops)}:{pct(edits, total_file_ops)}:{pct(writes, total_file_ops)}</div>
            <div class="label">Read : Edit : Write</div>
        </div>
        <div class="donut-item">
            <div class="ratio">{greps}:{globs}</div>
            <div class="label">Grep : Glob</div>
        </div>
        <div class="donut-item">
            <div class="ratio">{"Surgical Editor" if edits > writes * 1.5 else "Full-File Writer"}</div>
            <div class="label">{"Edit &gt;&gt; Write" if edits > writes * 1.5 else "Write-heavy"}</div>
        </div>
    </div>
</section>

<!-- Agent Dispatch -->
{"<section>" + '<div class="section-header"><h2>Agent Dispatch</h2><span class="count">' + str(jsonl.get("agent_count",0)) + " agents spawned</span></div>" +
'<div class="two-col"><div>' +
"<h3>Agent Types</h3>" + (agent_type_items or '<p class="empty">None</p>') +
"</div><div>" +
"<h3>Model Tiering</h3>" + (agent_model_items or '<p class="empty">None</p>') +
f'<div class="meta" style="margin-top:0.5rem">{jsonl.get("agent_background_pct",0)}% run in background</div>' +
"</div></div>" +
(f'<h3>Custom Agent Definitions</h3><div class="tags">{agent_list}</div>' if agent_list else '') +
"</section>" if jsonl.get("agent_count", 0) > 0 else ""}

<!-- CLI Tools -->
<section>
    <div class="section-header"><h2>CLI Tools (Bash)</h2><span class="count">{sum(cli_tools.values())} commands</span></div>
    {make_bar_chart(cli_tools, "var(--teal)", 15)}
</section>

<!-- Workflow Phases -->
<section>
  <div class="section-header">
    <h2>Workflow Phases</h2>
    <span class="count">{phase_stats.get("total_sessions_with_phases", 0)} sessions analyzed</span>
  </div>
  <div class="two-col">
    <div>
      <h3>Phase Distribution</h3>
      {phase_dist_items or '<p class="empty">No data</p>'}
    </div>
    <div>
      <h3>Phase Transitions</h3>
      {phase_trans_items or '<p class="empty">No data</p>'}
    </div>
  </div>
  <div style="display:flex;gap:1.5rem;flex-wrap:wrap;margin-top:1rem">
    <div class="meta">
      <strong style="color:var(--ink)">{phase_stats.get("explore_before_impl_pct", 0)}%</strong>
      explore before implementing
    </div>
    <div class="meta">
      <strong style="color:var(--ink)">{phase_stats.get("test_before_ship_pct", 0)}%</strong>
      test before shipping
    </div>
  </div>
</section>

<!-- Skill Workflow -->
<section>
  <div class="section-header">
    <h2>Skill Workflow</h2>
    <span class="count">{sum(skill_invocations.values())} skill invocations</span>
  </div>
  <div class="footnote">Skill invocations</div>
  {skill_inv_items or '<p class="empty">No skill invocations</p>'}
  <div class="footnote">Common workflow patterns</div>
  {workflow_pat_items or '<p class="empty">No repeating patterns detected</p>'}
</section>

<!-- TIER 3: Context & Background -->

<!-- Tool Usage -->
<section>
    <div class="section-header"><h2>Tool Usage</h2><span class="count">{fmt(sum(tool_counts.values()))} calls</span></div>
    {make_bar_chart(dict(tool_counts.most_common(15)), "var(--accent)")}
</section>

<div class="two-col">
<section>
    <div class="section-header"><h2>Languages</h2></div>
    {make_bar_chart(languages, "var(--green)", 10)}
</section>
<section>
    <div class="section-header"><h2>Models</h2></div>
    {make_bar_chart(models, "var(--purple)", 6)}
</section>
</div>

<div class="two-col">
<section>
    <div class="section-header"><h2>Permission Modes</h2></div>
    {perm_items or '<p class="empty">No data</p>'}
</section>
<section>
    <div class="section-header"><h2>MCP Servers</h2></div>
    {mcp_items or '<p class="empty">No MCP servers</p>'}
</section>
</div>

<!-- Git Patterns -->
<section>
    <div class="section-header"><h2>Git Patterns</h2></div>
    <div style="display:flex;gap:1.5rem;flex-wrap:wrap;margin-bottom:0.8rem">
        <div class="meta"><strong style="color:var(--ink)">{jsonl.get("pr_count",0)}</strong> PRs &middot; <strong style="color:var(--ink)">{meta.get("total_git_commits",0)}</strong> commits &middot; <strong style="color:var(--ink)">{fmt(meta.get("total_lines_added",0))}</strong> lines added</div>
    </div>
    <h3>Branch Conventions</h3>
    <div class="tags">{branch_items or '<span class="empty">No data</span>'}</div>
</section>

<!-- Versions -->
<section>
    <div class="section-header"><h2>Claude Code Versions</h2></div>
    <div class="tags">{version_tags}</div>
</section>

<!-- Approved Permissions -->
<section>
    <div class="section-header"><h2>Approved Permissions</h2><span class="count">{perms.get("projects_with_local_settings",0)} projects</span></div>
    <div class="two-col">
        <div>
            <h3>Approved Skills ({len(perms.get("approved_skills",[]))})</h3>
            {"".join(f'<div class="mono accent" style="padding:0.2rem 0">{he(s)}</div>' for s in perms.get("approved_skills",[])[:15]) or '<p class="empty">None</p>'}
        </div>
        <div>
            <h3>Bash Commands ({len(perms.get("bash_command_types",[]))})</h3>
            {"".join(f'<div class="mono amber" style="padding:0.2rem 0">{he(c)}</div>' for c in perms.get("bash_command_types",[])[:15]) or '<p class="empty">None</p>'}
        </div>
    </div>
</section>

<!-- Configuration & Safety Posture -->
<section>
    <div class="section-header"><h2>Safety &amp; Configuration</h2></div>
    <div class="pills">
        <span class="pill {"on" if safety.get("skip_danger_prompt") else "off"}">{safety.get("custom_safety_label", "Stock")}</span>
        <span class="pill {"on" if safety.get("has_custom_safety") else "off"}">Custom Hooks: {", ".join(safety.get("safety_hooks", [])) or "none"}</span>
        <span class="pill {"on" if ide_info.get("mode") == "vs-code" else "off"}">IDE: {ide_info.get("mode", "terminal-only")}</span>
        <span class="pill {"on" if statusline_info.get("configured") else "off"}">Statusline{" (" + statusline_info.get("package_hint", "")[:40] + ")" if statusline_info.get("package_hint") else ""}</span>
    </div>
    {"<h3>Universal Deny Rules</h3><div class='tags'>" + "".join(f'<span class=\"tag\">{he(d)}</span>' for d in safety.get("universal_denies", [])) + "</div>" if safety.get("universal_denies") else ""}
    {"<h3>Experimental Features</h3><div class='tags'>" + "".join(f'<span class=\"tag\">{he(k)}: {he(v)}</span>' for k, v in experimental.get("experimental_flags", {}).items()) + "</div>" if experimental.get("experimental_flags") else ""}
    {"<h3>Other AI Tools Detected</h3><div class='tags'>" + "".join(f'<span class=\"tag\">{he(t)}</span>' for t in hybrid.get("tools", [])) + "</div>" if hybrid.get("tools") else ""}
    {"<h3>Plugin Marketplaces (" + str(mkt.get("count", 0)) + ")</h3><div class='tags'>" + "".join(f'<span class=\"tag\">{he(m["name"])}</span>' for m in mkt.get("marketplaces", [])) + "</div>" if mkt.get("marketplaces") else ""}
</section>

<!-- Agent Model Tiering -->
{"<section>" +
'<div class="section-header"><h2>Agent Model Tiering</h2></div>' +
'<div class="two-col"><div>' +
"<h3>Opus (Judgment)</h3>" +
("".join(f'<div class="mono" style="padding:0.15rem 0;color:var(--accent)">{he(n)}</div>' for n in agent_det.get("tiers",{}).get("opus",[])) or '<p class="empty">None</p>') +
"</div><div>" +
"<h3>Sonnet (Domain)</h3>" +
("".join(f'<div class="mono" style="padding:0.15rem 0;color:var(--teal)">{he(n)}</div>' for n in agent_det.get("tiers",{}).get("sonnet",[])) or '<p class="empty">None</p>') +
"<h3>Haiku (Utility)</h3>" +
("".join(f'<div class="mono" style="padding:0.15rem 0;color:var(--green)">{he(n)}</div>' for n in agent_det.get("tiers",{}).get("haiku",[])) or '<p class="empty">None</p>') +
"</div></div></section>" if any(agent_det.get("tiers",{}).get(t) for t in ("opus","sonnet","haiku")) else ""}

<!-- Teams -->
{"<section><div class='section-header'><h2>Agent Teams</h2><span class='count'>" + str(team_cfg.get("team_count",0)) + " teams</span></div>" +
"".join(f'<div class=\"kv-row\"><span class=\"mono\">team-{t["name_hash"]}</span><span class=\"meta\">{str(t.get("member_count","?")) + " members" if t.get("has_config") else "no config"}</span></div>' for t in team_cfg.get("teams",[])) +
"</section>" if team_cfg.get("team_count", 0) > 0 else ""}

<!-- Instruction Maturity -->
<section>
    <div class="section-header"><h2>Instruction Maturity</h2><span class="count">{instr_maturity.get("projects",{}).get("total",0)} projects</span></div>
    <div class="pills">
        <span class="pill on">Gen 2 Bundle: {instr_maturity.get("projects",{}).get("gen2",0)}</span>
        <span class="pill {"on" if instr_maturity.get("projects",{}).get("gen1",0) > 0 else "off"}">Gen 1 (CLAUDE.md only): {instr_maturity.get("projects",{}).get("gen1",0)}</span>
        <span class="pill off">No Instructions: {instr_maturity.get("projects",{}).get("none",0)}</span>
    </div>
    {"<h3>Global CLAUDE.md Structure</h3><div class='tags'>" + "".join(f'<span class=\"tag\">{he(h)}</span>' for h in instr_maturity.get("global_headings",[])) + "</div>" if instr_maturity.get("global_headings") else ""}
    {"<h3>HANDOFF.md Sizes</h3><div class='meta'>Average: " + str(instr_maturity.get("avg_handoff_lines",0)) + " lines across " + str(len(instr_maturity.get("handoff_sizes",[]))) + " projects</div>" if instr_maturity.get("handoff_sizes") else ""}
</section>

<!-- Memory Architecture -->
<section>
    <div class="section-header"><h2>Memory Architecture</h2></div>
    <div class="pills">
        <span class="pill {"on" if memory_arch.get("is_dual_layer") else "off"}">{"Dual-Layer" if memory_arch.get("is_dual_layer") else "Single-Layer"}</span>
        <span class="pill on">In-Repo: {memory_arch.get("in_repo_memory",0)} projects</span>
        <span class="pill on">Claude-Managed: {memory_arch.get("claude_managed_memory",0)} projects</span>
    </div>
    {"<h3>Memory Atoms (" + str(memory_arch.get("total_atoms",0)) + " total)</h3>" +
    "".join(f'<div class=\"kv-row\"><span class=\"mono\">{he(t)}</span><span class=\"meta\">{c}</span></div>' for t, c in sorted(memory_arch.get("atom_types",{}).items(), key=lambda x: x[1], reverse=True)) if memory_arch.get("atom_types") else ""}
</section>

<!-- Permission Accumulation -->
<section>
    <div class="section-header"><h2>Permission Accumulation</h2><span class="count">{perm_accum.get("total_projects",0)} projects</span></div>
    <div style="display:flex;gap:1.5rem;flex-wrap:wrap;margin-bottom:0.5rem">
        <div class="meta"><strong style="color:var(--ink)">{perm_accum.get("avg_grants",0)}</strong> avg grants/project</div>
        <div class="meta"><strong style="color:var(--ink)">{perm_accum.get("max_grants",0)}</strong> max grants</div>
    </div>
</section>

<!-- Peak Usage -->
{"<section><div class='section-header'><h2>Usage Intensity</h2><span class='count'>" + str(stats_cache.get("days_tracked",0)) + " days tracked</span></div>" +
"<div style='display:flex;gap:1.5rem;flex-wrap:wrap'>" +
"<div class='meta'><strong style='color:var(--ink)'>" + str(stats_cache.get("peak_day_messages",0)) + "</strong> peak day messages</div>" +
"<div class='meta'><strong style='color:var(--ink)'>" + str(stats_cache.get("peak_day_sessions",0)) + "</strong> peak day sessions</div>" +
"<div class='meta'><strong style='color:var(--ink)'>" + str(stats_cache.get("avg_daily_messages",0)) + "</strong> avg daily messages</div>" +
"<div class='meta'><strong style='color:var(--ink)'>" + str(stats_cache.get("total_sessions_all_time",0)) + "</strong> all-time sessions</div>" +
"<div class='meta'><strong style='color:var(--ink)'>" + str(stats_cache.get("cache_read_ratio",0)) + ":1</strong> cache-read ratio</div>" +
"</div></section>" if stats_cache.get("peak_day_messages") else ""}

<!-- end dashboard tab -->
</div>

<!-- Writeup tab -->
<div id="tab-writeup" class="tab-content">
{generate_writeup(data)}
</div>

{_render_insights_tab(data.get("insights_report"))}

<footer>
    Generated by /insight-harness &middot; {now.strftime("%Y-%m-%d %H:%M")} &middot; {DAYS}-day window &middot; Privacy: tool names only, no content
</footer>

</div>

<script>
function switchTab(tab) {{
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + tab).classList.add('active');
    document.querySelector('[onclick="switchTab(\\'' + tab + '\\')"]').classList.add('active');
}}
</script>

<!-- Embedded JSON data blob: complete structured data for website ingestion.
     The site reads this directly instead of scraping the HTML. -->
<script type="application/json" id="harness-data">{_harness_json_str}</script>

<!-- Integrity manifest: server can extract this JSON block, recompute the SHA-256,
     and verify the hash matches. Catches casual edits to visible stats. -->
<script type="application/json" id="insight-harness-integrity">{integrity_block}</script>

</body>
</html>'''
    return html


# ── Version Check & Self-Update ───────────────────────────────────────────

def check_for_updates():
    """Auto-update DISABLED (v2.3.0) — local fixes were being wiped by remote pulls."""
    pass  # Intentionally disabled to preserve local bug fixes


def self_update():
    """Auto-update DISABLED (v2.3.0) — local fixes were being wiped by remote pulls."""
    print("Auto-update is disabled in v2.3.0 to preserve local bug fixes.", file=sys.stderr)
    print("To update manually, re-run the install curl command from SKILL.md.", file=sys.stderr)
    sys.exit(1)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    # Accept --update in any argv position, not just argv[1]. Matches the
    # ergonomics of --include-skills / --no-include-skills being positional-
    # agnostic.
    if "--update" in sys.argv[1:]:
        self_update()
        sys.exit(0)

    # Showcase data (per-skill README + hero) is default-on as of 2.6.0.
    # `--include-skills` remains as an explicit no-op for backward compat;
    # `--no-include-skills` opts out for users who want the smaller payload.
    include_showcase = "--no-include-skills" not in sys.argv[1:]

    cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS)

    print("Extracting settings...", file=sys.stderr)
    settings = extract_settings()

    print("Reading plugins...", file=sys.stderr)
    plugins = extract_installed_plugins()

    if include_showcase:
        print("Scanning skills (with showcase content)...", file=sys.stderr)
    else:
        print("Scanning skills...", file=sys.stderr)
    skill_inventory = extract_skill_inventory(include_showcase=include_showcase)

    print("Reading hooks...", file=sys.stderr)
    hook_scripts = extract_hook_scripts()

    print("Reading custom agents...", file=sys.stderr)
    custom_agents = extract_custom_agents()

    print("Checking harness files...", file=sys.stderr)
    harness_files = extract_harness_files()

    print("Reading session metadata...", file=sys.stderr)
    session_meta = extract_session_meta(cutoff)
    session_meta_summary = aggregate_session_meta(session_meta)

    print("Scanning JSONL (field-whitelisted)...", file=sys.stderr)
    jsonl_metadata = extract_jsonl_metadata(cutoff)

    # Privacy: drop call counts for skills marked repo: private/none. Filtering
    # at the data-source level (jsonl_metadata) — not just inside generate_html
    # — ensures generate_writeup() and any other downstream consumer also sees
    # the filtered counter. Without this, the writeup paragraph would still
    # name and quantify private skills.
    private_names = getattr(skill_inventory, "private_skill_names", set()) or set()
    if private_names and "skill_invocations" in jsonl_metadata:
        jsonl_metadata["skill_invocations"] = {
            n: c
            for n, c in jsonl_metadata["skill_invocations"].items()
            if n not in private_names
        }

    print("Reading permissions...", file=sys.stderr)
    permissions_profile = extract_permissions_profile()

    print("Reading /insights report...", file=sys.stderr)
    insights_report = extract_insights_report()
    if insights_report:
        print(f"  Found /insights report ({insights_report['modified']})", file=sys.stderr)
    else:
        print("  No /insights report found — run /insights first for narrative sections", file=sys.stderr)

    # New config layer extractors
    print("Analyzing safety posture...", file=sys.stderr)
    safety_posture = extract_safety_posture()

    print("Reading experimental features...", file=sys.stderr)
    experimental = extract_experimental_features()

    print("Reading stats cache...", file=sys.stderr)
    stats_cache = extract_stats_cache()

    print("Analyzing instruction maturity...", file=sys.stderr)
    instruction_maturity = extract_instruction_maturity()

    print("Analyzing memory architecture...", file=sys.stderr)
    memory_arch = extract_memory_architecture()

    print("Reading agent details...", file=sys.stderr)
    agent_details = extract_agent_details()

    print("Reading team configs...", file=sys.stderr)
    team_configs = extract_team_configs()

    print("Reading marketplace diversity...", file=sys.stderr)
    marketplace = extract_marketplace_diversity()

    print("Reading statusline...", file=sys.stderr)
    statusline = extract_statusline()

    print("Checking IDE integration...", file=sys.stderr)
    ide = extract_ide_integration()

    print("Detecting hybrid tools...", file=sys.stderr)
    hybrid_tools = extract_hybrid_tools()

    print("Checking blocklist...", file=sys.stderr)
    blocklist = extract_blocklist_issues()

    print("Analyzing permission accumulation...", file=sys.stderr)
    perm_accumulation = extract_permission_accumulation()

    data = {
        "settings": settings,
        "installed_plugins": plugins,
        "skill_inventory": skill_inventory,
        "hook_scripts": hook_scripts,
        "custom_agents": custom_agents,
        "harness_files": harness_files,
        "session_meta_summary": session_meta_summary,
        "jsonl_metadata": jsonl_metadata,
        "permissions_profile": permissions_profile,
        "insights_report": insights_report,
        # New config layer
        "safety_posture": safety_posture,
        "experimental": experimental,
        "stats_cache": stats_cache,
        "instruction_maturity": instruction_maturity,
        "memory_arch": memory_arch,
        "agent_details": agent_details,
        "team_configs": team_configs,
        "marketplace": marketplace,
        "statusline": statusline,
        "ide": ide,
        "hybrid_tools": hybrid_tools,
        "blocklist": blocklist,
        "perm_accumulation": perm_accumulation,
    }

    # Build integrity manifest — key stats that the server can verify
    meta = data.get("session_meta_summary", {})
    jsonl = data.get("jsonl_metadata", {})
    integrity_payload = {
        "v": 2, "skill_version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sessions": meta.get("session_count", 0),
        "total_tokens": meta.get("total_tokens", 0),
        "total_input_tokens": meta.get("total_input_tokens", 0),
        "total_output_tokens": meta.get("total_output_tokens", 0),
        "total_duration_minutes": meta.get("total_duration_minutes", 0),
        "total_tool_calls": jsonl.get("total_tool_calls", 0),
        "skill_count": len(data.get("skill_inventory", [])),
        "hook_count": len(data.get("settings", {}).get("hooks", [])),
        "plugin_count": len(data.get("installed_plugins", [])),
        "commit_count": jsonl.get("commit_count", 0),
        "pr_count": jsonl.get("pr_count", 0),
        "days": DAYS,
    }
    integrity_json = json.dumps(integrity_payload, sort_keys=True, separators=(",", ":"))
    integrity_hash = hashlib.sha256(integrity_json.encode()).hexdigest()
    data["_integrity"] = {
        "payload": integrity_json,
        "hash": integrity_hash,
    }

    print("Generating HTML...", file=sys.stderr)
    html = generate_html(data)

    # Save alongside /insights report in ~/.claude/usage-data/
    usage_dir = CLAUDE_DIR / "usage-data"
    usage_dir.mkdir(parents=True, exist_ok=True)
    primary_path = usage_dir / "insight-harness.html"
    primary_path.write_text(html)

    # Also save a dated copy in ~/Documents/Claude Reports/ if it exists
    reports_dir = Path.home() / "Documents" / "Claude Reports"
    if reports_dir.exists():
        date_str = datetime.now().strftime("%Y-%m-%d")
        dated_path = reports_dir / f"insight-harness-{date_str}.html"
        counter = 2
        while dated_path.exists():
            dated_path = reports_dir / f"insight-harness-{date_str}-{counter}.html"
            counter += 1
        dated_path.write_text(html)

    print(str(primary_path))

    # Check for updates (non-blocking, silent on failure)
    check_for_updates()


if __name__ == "__main__":
    main()
