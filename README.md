# insight-harness

A shareable harness-profile skill for **Claude Code** and **OpenAI Codex CLI**.
It generates a single-file HTML report of your local agent setup: skills, tools,
workflow patterns, token/session stats, plugin inventory, safety posture, and
other harness signals.

For Claude Code, it is a **superset of `/insights`** — everything `/insights`
provides, plus token breakdowns, tool usage stats, skill inventory, hooks, agent
patterns, and cost. For Codex, it profiles the locally visible CLI data under
`~/.codex/` and emits a Codex-shaped report that can be uploaded to
[insightharness.com](https://insightharness.com).

## What it captures

- **Tokens** — input/output/cache usage over the last 30 days
- **Tools** — which built-in and MCP tools you invoke most
- **Skills** — inventory of skills you have installed and which ones you actually use
- **Hooks** — Claude Code hook configuration from `settings.json`
- **Agents** — Claude Code subagent usage patterns where available
- **Cost** — Claude Code dollar breakdown by model and by day
- **Plugins** — installed Claude plugins and Codex plugin configuration
- **Codex CLI posture** — local Codex tools, CLI commands, skills, plugins,
  safety/rules settings, workflow phase signal, and work surfaces

## How it runs (and what it doesn't do) 🧘

One Python script and an HTML template. No npm installs, no pip installs, no native binaries, no background daemons.

🐍 **Runs on your machine:**

- One `python3` invocation using the standard library only (`json`, `re`, `pathlib`, `subprocess`, `base64`, etc.). Nothing to `pip install`.
- One optional `gh api user` call to read your own GitHub login for the filename — skipped if `gh` isn't installed. No data transmitted.
- Exits when the report is written. Nothing stays resident.

📂 **Reads (locally, read-only):**

- `~/.claude/settings.json`, `~/.claude/plugins/installed_plugins.json`, and every `SKILL.md` frontmatter under `~/.claude/skills/`
- `~/.claude/projects/*/*.jsonl` — **field-whitelisted**: only tool names, skill names, hook events, tool-transition sequences, and workflow-phase classifications. Never tool arguments, message text, tool results, or project file paths.
- Per shareable skill: `README.md` and `assets/hero.{png,jpg}` (see scrubbing below).

🚫 **Doesn't do:**

- **No network calls** from the script itself. `urllib` is imported but never invoked; the only outbound traffic is the optional `gh` call above.
- **No uploads.** Output is written locally to `~/.claude/insight-harness/report.html`. You choose whether to share it at [insightharness.com](https://insightharness.com).
- **No telemetry, analytics, cookies, or service workers.** The HTML is a single static file with inlined images — open it offline, email it, host it yourself.

🛡️ **PII scrubbing before anything ships:** git name/email, OS username paths (`/Users/<you>`, `/home/<you>`), GitHub URLs with your username, and `@<you>` mentions are redacted. Hero images are text-scrubbed only — pixels are out of scope, so review screenshots before uploading. SVG heroes are rejected outright.

## Install For Claude Code

### Plugin marketplace

Run these two commands inside Claude Code:

```
/plugin marketplace add kabirdos/insight-harness
/plugin install insight-harness@kabirdos-insight-harness
```

Then in any Claude Code session:

```
/insight-harness:insight-harness
```

…or just ask: _"run insight harness"_, _"show my harness"_, _"what skills do I use"_.

### Curl fallback

If you'd rather not use the plugin system, you can drop the skill directly into your skills directory:

```bash
mkdir -p ~/.claude/skills/insight-harness
curl -sSL https://raw.githubusercontent.com/kabirdos/insight-harness/main/skills/insight-harness/SKILL.md \
  -o ~/.claude/skills/insight-harness/SKILL.md
curl -sSL https://raw.githubusercontent.com/kabirdos/insight-harness/main/skills/insight-harness/scripts/extract.py \
  --create-dirs -o ~/.claude/skills/insight-harness/scripts/extract.py
curl -sSL https://raw.githubusercontent.com/kabirdos/insight-harness/main/skills/insight-harness/scripts/pii_scrub.py \
  -o ~/.claude/skills/insight-harness/scripts/pii_scrub.py
```

Or clone the whole repo and symlink:

```bash
git clone https://github.com/kabirdos/insight-harness.git
ln -s "$(pwd)/insight-harness/skills/insight-harness" ~/.claude/skills/insight-harness
```

## Install For Codex

Codex does not use the Claude plugin marketplace. Install the same skill folder
under `~/.codex/skills/insight-harness`:

```bash
mkdir -p ~/.codex/skills/insight-harness/scripts
curl -sSL https://raw.githubusercontent.com/kabirdos/insight-harness/main/skills/insight-harness/SKILL.md \
  -o ~/.codex/skills/insight-harness/SKILL.md
curl -sSL https://raw.githubusercontent.com/kabirdos/insight-harness/main/skills/insight-harness/scripts/codex_extract.py \
  -o ~/.codex/skills/insight-harness/scripts/codex_extract.py
curl -sSL https://raw.githubusercontent.com/kabirdos/insight-harness/main/skills/insight-harness/scripts/pii_scrub.py \
  -o ~/.codex/skills/insight-harness/scripts/pii_scrub.py
curl -sSL https://raw.githubusercontent.com/kabirdos/insight-harness/main/skills/insight-harness/scripts/extract.py \
  -o ~/.codex/skills/insight-harness/scripts/extract.py
```

Then run:

```bash
python3 ~/.codex/skills/insight-harness/scripts/codex_extract.py --include-skills
```

The Codex report is written under `~/.codex/usage-data/`. Upload the generated
HTML file at [insightharness.com/upload](https://insightharness.com/upload).
Direct `--publish` is currently Claude-only.

## Output

The Claude Code path writes a single-file HTML report to
`~/.claude/insight-harness/report.html` and opens it in your browser. The Codex
path writes a single-file HTML report to `~/.codex/usage-data/`. Read reports
locally, or upload them to [insightharness.com/upload](https://insightharness.com/upload)
to share as a public profile.

## License

MIT — see [LICENSE](./LICENSE).
