#!/usr/bin/env python3
"""insight-harness learn mode — fetch a published profile or group's agent payload.

Given a published report (a full insightharness.com URL or a bare "<user>/<slug>")
or a group (``insightharness.com/g/<slug>``, bare ``g/<slug>``, or the API URL),
fetch the lean, machine-readable agent payload via HTTP content negotiation and
print it to stdout for the host agent (Claude Code / Codex) to reason over.

This script does NOT call any LLM and needs no API key for public reports. The
agent that invoked the skill IS the consumer: it reads this output and produces
the learnings (see the "Learn from another harness" section of SKILL.md). Runs
fast (one HTTP GET), so it is invoked in the foreground, unlike the extractor.

Non-public reports and groups require auth: if a publish token (``ih_…``) is
stored under ~/.claude/insight-harness/config.json (or the Codex path), it is
sent as ``Authorization: Bearer <token>`` on every fetch. Public reports work
with no token. The token is never printed.

Contract consumed here is documented in the insightful repo at
docs/agent-payload.md and the group-sharing plan
(docs/plans/2026-06-10-001-feat-group-sharing-plan.md, "Group agent payload").
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# Reuse the publish flow's base-URL resolution so the INSIGHT_HARNESS_BASE_URL
# dev override behaves identically for learn mode and publish. is_valid_token
# and PUBLISH_CONFIG_PATH give us the exact same ih_<12hex><64hex> shape check
# and Claude-side token location the publish flow uses.
from extract import (  # noqa: E402
    PUBLISH_CONFIG_PATH,
    PUBLISH_DEFAULT_BASE_URL,
    is_valid_token,
    publish_base_url,
)

AGENT_MEDIA_TYPE = "application/vnd.insight-harness.agent.v1+json"

# Group slugs are lowercase alnum + hyphen, 3–40 chars (mirrors the server's
# slug validation in the group-sharing plan).
GROUP_SLUG_RE = re.compile(r"^[a-z0-9-]{3,40}$")

# Token config locations, in precedence order: the Claude path first, then the
# Codex path. PUBLISH_CONFIG_PATH is imported from extract (~/.claude/...); the
# Codex equivalent (~/.codex/...) is derived from the same home so a monkeypatch
# of Path.home in tests moves both. First valid ih_ token wins.
CODEX_CONFIG_PATH = Path.home() / ".codex" / "insight-harness" / "config.json"


def _allowed_origins(base_url: str) -> set[str]:
    """Origins learn mode will fetch from: the canonical site + the dev override.

    SECURITY: the fetched JSON (including consumer_guidance) is handed to the
    host agent for reasoning, so only fetch from trusted origins. Match the full
    origin (scheme + host), not just the host — this requires https for the
    canonical site and reserves http for an explicit dev override
    (INSIGHT_HARNESS_BASE_URL).
    """
    return {
        PUBLISH_DEFAULT_BASE_URL.rstrip("/"),
        base_url.rstrip("/"),
    }


def _check_origin(origin: str, base_url: str, arg: str) -> None:
    if origin not in _allowed_origins(base_url):
        raise ValueError(
            f"refusing to fetch from untrusted origin {origin!r}; learn mode "
            f"only consumes {sorted(_allowed_origins(base_url))} "
            "(set INSIGHT_HARNESS_BASE_URL to allow a dev origin)"
        )


def parse_group_target(arg: str, base_url: str) -> str | None:
    """Resolve a group API URL from a group target, or None if not a group.

    Accepts ``https://insightharness.com/g/<slug>`` (trailing slash tolerated),
    a bare ``g/<slug>``, or the API URL ``.../api/groups/<slug>``. Returns the
    resolved ``{base}/api/groups/<slug>``. Returns ``None`` when the argument is
    not group-shaped at all (so the caller can fall through to the report path).
    Raises ValueError when the argument IS group-shaped but invalid — an
    off-domain origin, a ``/join/<token>`` invite link (an invite, not a
    profile), or a slug that doesn't match ``[a-z0-9-]{3,40}``.
    """
    cleaned = arg.strip().strip("<>").rstrip("/")

    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        parts = [p for p in parsed.path.split("/") if p]
        # Group-shaped iff the path leads with a "g" segment or an "api/groups"
        # pair. Anything else is not our concern — return None to fall through.
        is_g = bool(parts) and parts[0] == "g"
        is_api_groups = len(parts) >= 2 and parts[0] == "api" and parts[1] == "groups"
        if not (is_g or is_api_groups):
            return None
        origin = f"{parsed.scheme}://{parsed.netloc}"
        _check_origin(origin, base_url, arg)
        rest = parts[1:] if is_g else parts[2:]
    else:
        parts = [p for p in cleaned.split("/") if p]
        if not parts or parts[0] != "g":
            return None
        origin = base_url.rstrip("/")
        rest = parts[1:]

    if not rest:
        raise ValueError(f"Group URL is missing a slug: {arg!r}")
    # A /join/<token> path is an invite link, not a profile. Reject explicitly
    # so the user gets a clear "that's an invite" message instead of a slug error.
    if rest[0] == "join":
        raise ValueError(
            "That's a group invite link (/g/join/<token>), not a group profile. "
            "Open it in a browser to join, then point me at the group itself "
            "(insightharness.com/g/<slug>)."
        )
    slug = rest[0]
    if not GROUP_SLUG_RE.match(slug):
        raise ValueError(
            f"{slug!r} is not a valid group slug (expected [a-z0-9-], 3–40 chars)."
        )
    return f"{origin}/api/groups/{slug}"


def parse_target(arg: str, base_url: str) -> tuple[str, str, str]:
    """Resolve (api_url, user, slug) from a URL or a bare ``<user>/<slug>``.

    Accepts the human report URL (``/insights/<u>/<s>`` or ``.../edit``), the API
    URL (``/api/insights/<u>/<s>``), or a bare ``<user>/<slug>``. For a bare pair
    the origin comes from ``base_url`` (honors the dev override); for a full URL
    the origin is taken from the URL itself. Raises ValueError on anything it
    cannot confidently resolve to a user + slug.
    """
    cleaned = arg.strip().strip("<>").rstrip("/")
    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        # An off-domain host, or a plaintext http://insightharness.com that a
        # MITM could tamper with, is rejected.
        origin = f"{parsed.scheme}://{parsed.netloc}"
        _check_origin(origin, base_url, arg)
        parts = [p for p in parsed.path.split("/") if p]
        # Tolerate a leading "api"; the anchor is the "insights" segment.
        if "insights" not in parts:
            raise ValueError(f"URL does not look like a report URL: {arg}")
        rest = parts[parts.index("insights") + 1 :]
        if len(rest) < 2:
            raise ValueError(f"Could not find <user>/<slug> in URL: {arg}")
        user, slug = rest[0], rest[1]
    else:
        origin = base_url.rstrip("/")
        parts = [p for p in cleaned.split("/") if p]
        if len(parts) != 2:
            raise ValueError(
                f"Expected a report URL or '<user>/<slug>', got: {arg!r}"
            )
        user, slug = parts
    return f"{origin}/api/insights/{user}/{slug}", user, slug


def load_bearer_token() -> str | None:
    """Return the first valid ``ih_`` publish token, or None.

    Checks the Claude config (~/.claude/insight-harness/config.json) first, then
    the Codex config (~/.codex/insight-harness/config.json). Uses the same shape
    check as the publish flow (``is_valid_token``: ``ih_<12hex><64hex>``). A
    malformed token in either file is ignored, not surfaced. The token is never
    printed or returned in any error message — callers attach it only as an
    Authorization header.
    """
    for config_path in (PUBLISH_CONFIG_PATH, CODEX_CONFIG_PATH):
        try:
            if not config_path.exists():
                continue
            with open(config_path, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        token = data.get("token") if isinstance(data, dict) else None
        if is_valid_token(token):
            return token
    return None


def _strip_hero(harness_data: object) -> object:
    """Defensively drop hero image blobs from a harnessData-ish object.

    Only used on the legacy fallback path (an older server returned the human
    payload instead of the agent envelope). The current server already strips
    these. Preserves the stored shape — bare HarnessData or a multi-tool
    ``{primaryTool, tools}`` envelope.
    """

    # Both casings: the Claude extractor emits snake_case hero_base64; the Codex
    # extractor emits camelCase heroBase64 (codex_extract.py). Cover both so a
    # legacy Codex or multi-tool fallback payload can't slip an image blob to
    # stdout.
    hero_keys = ("hero_base64", "hero_mime_type", "heroBase64", "heroMimeType")

    def strip_inventory(holder: object) -> object:
        if not isinstance(holder, dict) or not isinstance(
            holder.get("skillInventory"), list
        ):
            return holder
        out = dict(holder)
        out["skillInventory"] = [
            {**s, **{k: None for k in hero_keys if k in s}}
            if isinstance(s, dict) and any(s.get(k) for k in hero_keys)
            else s
            for s in holder["skillInventory"]
        ]
        return out

    if not isinstance(harness_data, dict):
        return harness_data
    if isinstance(harness_data.get("tools"), dict):
        out = dict(harness_data)
        out["tools"] = {k: strip_inventory(v) for k, v in harness_data["tools"].items()}
        return out
    return strip_inventory(harness_data)


def _strip_group_heroes(body: dict) -> dict:
    """Defensively drop hero blobs from every member profile in a group envelope.

    The server already strips hero images, but we mirror the single-report
    defensive strip so a member's base64 image can never reach stdout and blow
    the host agent's context. Mutates a shallow copy; member ``profile`` objects
    are rewritten via ``_strip_hero`` (which itself returns copies).
    """
    members = body.get("members")
    if not isinstance(members, list):
        return body
    out = dict(body)
    out["members"] = [
        {**m, "profile": _strip_hero(m["profile"])}
        if isinstance(m, dict) and "profile" in m
        else m
        for m in members
    ]
    return out


def normalize_payload(body: object) -> tuple[dict, str]:
    """Return ``(envelope, mode)`` where mode is ``"agent"``, ``"group"``, or ``"fallback"``.

    - ``group``    — the server returned a group envelope (``kind == "group"``);
      hero images are defensively stripped from every member profile, then it is
      passed through.
    - ``agent``    — the server returned the versioned per-report agent envelope
      (recognized by a top-level ``schema_version`` and no group ``kind``);
      passed through verbatim. A ``kind``-absent body is treated as single-report
      for back-compat.
    - ``fallback`` — an older server returned the human ``{data: {harnessData}}``
      shape; wrap harnessData in a minimal envelope and strip hero images
      client-side so the host agent's context isn't blown by base64 blobs.

    Raises ValueError on any other shape.
    """
    if isinstance(body, dict) and body.get("kind") == "group":
        return _strip_group_heroes(body), "group"
    if isinstance(body, dict) and "schema_version" in body:
        return body, "agent"
    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        harness_data = body["data"].get("harnessData")
        if harness_data is not None:
            return (
                {
                    "schema_version": None,
                    "profile": _strip_hero(harness_data),
                    "_note": (
                        "This server did not return the agent payload; using the "
                        "human report payload (hero images stripped client-side). "
                        "Agent-contract fields (consumer_guidance, _privacy) are absent."
                    ),
                },
                "fallback",
            )
    raise ValueError(
        "Unrecognized response shape (no schema_version and no data.harnessData)"
    )


def fetch(api_url: str, opener=urllib.request.urlopen, token: str | None = None) -> object:
    """GET a report or group, negotiating the agent media type. Returns parsed JSON.

    When ``token`` is a valid ``ih_`` publish token it is attached as
    ``Authorization: Bearer <token>`` — this is what unlocks group payloads and
    group-visible single reports. With no token the request is anonymous and
    public reports still work. The token is never logged.
    """
    headers = {"Accept": AGENT_MEDIA_TYPE}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(api_url, headers=headers, method="GET")
    with opener(request, timeout=30) as response:
        raw = response.read()
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="learn.py",
        description="Fetch a published harness profile or group agent payload for learning.",
    )
    parser.add_argument(
        "target",
        help="A published report URL "
        "(https://insightharness.com/insights/<user>/<slug>), a bare '<user>/<slug>', "
        "or a group (https://insightharness.com/g/<slug> or bare 'g/<slug>').",
    )
    args = parser.parse_args(argv)

    base_url = publish_base_url()

    # Group targets are tried first; a non-group argument returns None and we
    # fall through to the report parser. A group-shaped but invalid argument
    # (off-domain, /join invite, bad slug) raises and exits 2.
    try:
        group_url = parse_group_target(args.target, base_url)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if group_url is not None:
        api_url, label, is_group = group_url, group_url, True
    else:
        try:
            api_url, user, slug = parse_target(args.target, base_url)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        label, is_group = f"{user}/{slug}", False

    # A stored ih_ token unlocks groups and group-visible single reports; absent,
    # the request is anonymous and public reports still work. Never printed.
    token = load_bearer_token()

    print(
        f"Fetching agent payload for {label} from {api_url} "
        f"({'authenticated' if token else 'anonymous'}) ...",
        file=sys.stderr,
    )
    try:
        body = fetch(api_url, token=token)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403) and is_group:
            print(
                "ERROR: This group requires membership — publish a report first to "
                "store your token (extract.py --token=...) or check you're a member.",
                file=sys.stderr,
            )
        elif exc.code in (401, 403):
            print(
                f"ERROR: not authorized to read {label} ({exc.code}). It may be a "
                "group-visible or private report; publish a report first to store "
                "your token (extract.py --token=...) or check you have access.",
                file=sys.stderr,
            )
        elif exc.code == 404 and is_group:
            print("ERROR: no such group or not a member.", file=sys.stderr)
        elif exc.code == 404:
            print(
                f"ERROR: no published report at {label} (404). Check the URL, "
                "or the report may be a private draft.",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: server returned HTTP {exc.code} for {api_url}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"ERROR: could not reach {api_url}: {exc.reason}", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print(f"ERROR: response from {api_url} was not valid JSON", file=sys.stderr)
        return 1

    try:
        envelope, mode = normalize_payload(body)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if mode == "fallback":
        print(
            "WARNING: server returned the legacy human payload, not the agent "
            "envelope. Proceeding with a best-effort profile.",
            file=sys.stderr,
        )

    print(json.dumps(envelope, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
