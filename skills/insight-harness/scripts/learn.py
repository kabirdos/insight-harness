#!/usr/bin/env python3
"""insight-harness learn mode — fetch a published profile's agent payload.

Given a published report (a full insightharness.com URL or a bare "<user>/<slug>"),
fetch the lean, machine-readable agent payload via HTTP content negotiation and
print it to stdout for the host agent (Claude Code / Codex) to reason over.

This script does NOT call any LLM and needs no API key. The agent that invoked
the skill IS the consumer: it reads this output and produces the learnings (see
the "Learn from another harness" section of SKILL.md). Runs fast (one HTTP GET),
so it is invoked in the foreground, unlike the extractor.

Contract consumed here is documented in the insightful repo at
docs/agent-payload.md.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# Reuse the publish flow's base-URL resolution so the INSIGHT_HARNESS_BASE_URL
# dev override behaves identically for learn mode and publish.
from extract import publish_base_url, PUBLISH_DEFAULT_BASE_URL  # noqa: E402

AGENT_MEDIA_TYPE = "application/vnd.insight-harness.agent.v1+json"


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
        # SECURITY: the fetched JSON (including consumer_guidance) is handed to
        # the host agent for reasoning, so only fetch from trusted origins. Match
        # the full origin (scheme + host), not just the host — this requires
        # https for the canonical site and reserves http for an explicit dev
        # override (INSIGHT_HARNESS_BASE_URL). An off-domain host, or a plaintext
        # http://insightharness.com that a MITM could tamper with, is rejected.
        origin = f"{parsed.scheme}://{parsed.netloc}"
        allowed_origins = {
            PUBLISH_DEFAULT_BASE_URL.rstrip("/"),
            base_url.rstrip("/"),
        }
        if origin not in allowed_origins:
            raise ValueError(
                f"refusing to fetch from untrusted origin {origin!r}; learn mode "
                f"only consumes {sorted(allowed_origins)} "
                "(set INSIGHT_HARNESS_BASE_URL to allow a dev origin)"
            )
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


def normalize_payload(body: object) -> tuple[dict, str]:
    """Return ``(envelope, mode)`` where mode is ``"agent"`` or ``"fallback"``.

    - ``agent``    — the server returned the versioned agent envelope
      (recognized by a top-level ``schema_version``); passed through verbatim.
    - ``fallback`` — an older server returned the human ``{data: {harnessData}}``
      shape; wrap harnessData in a minimal envelope and strip hero images
      client-side so the host agent's context isn't blown by base64 blobs.

    Raises ValueError on any other shape.
    """
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


def fetch(api_url: str, opener=urllib.request.urlopen) -> object:
    """GET the report, negotiating the agent media type. Returns parsed JSON."""
    request = urllib.request.Request(
        api_url, headers={"Accept": AGENT_MEDIA_TYPE}, method="GET"
    )
    with opener(request, timeout=30) as response:
        raw = response.read()
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="learn.py",
        description="Fetch a published harness profile's agent payload for learning.",
    )
    parser.add_argument(
        "target",
        help="A published report URL "
        "(https://insightharness.com/insights/<user>/<slug>) or a bare '<user>/<slug>'.",
    )
    args = parser.parse_args(argv)

    try:
        api_url, user, slug = parse_target(args.target, publish_base_url())
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(
        f"Fetching agent payload for {user}/{slug} from {api_url} ...",
        file=sys.stderr,
    )
    try:
        body = fetch(api_url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print(
                f"ERROR: no published report at {user}/{slug} (404). Check the URL, "
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
