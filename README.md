# insight-harness

A Claude Code skill that generates a comprehensive profile of your Claude Code harness — skills, hooks, workflow patterns, tool usage, token consumption, and plugin inventory across the last 30 days.

It's a **superset of `/insights`** — everything `/insights` provides, plus token breakdowns, tool usage stats, skill inventory, hooks, agent patterns, and cost.

## What it captures

- **Tokens** — input/output/cache usage over the last 30 days
- **Tools** — which built-in and MCP tools you invoke most
- **Skills** — inventory of skills you have installed and which ones you actually use
- **Hooks** — your configured hooks from `settings.json`
- **Agents** — subagent usage patterns
- **Cost** — dollar breakdown by model and by day
- **Plugins** — installed plugin marketplaces and plugins

## How it runs (and what it doesn't do)

Insight-harness is a single Python script and an HTML template. No npm installs. No pip installs. No native binaries. No background daemons.

**What runs on your machine:**

- One invocation of `python3` — uses the Python 3 standard library only (`json`, `re`, `pathlib`, `subprocess`, `base64`, etc.). Nothing to `pip install`.
- One optional subprocess call: `gh api user --jq .login` to read your own GitHub login name for the report filename. Skipped if `gh` isn't installed or authenticated; no data is transmitted.
- The process exits when the report is written. Nothing stays resident.

**What it reads (locally, read-only):**

- `~/.claude/settings.json` (hooks, permissions, plugin configs)
- `~/.claude/plugins/installed_plugins.json` (plugin inventory)
- `~/.claude/skills/**/SKILL.md` frontmatter for every skill
- `~/.claude/projects/*/*.jsonl` — **field-whitelisted**: only tool names, skill names, hook events, tool-transition sequences, and workflow-phase classifications. The script never reads tool arguments, message text, tool results, or project file paths.
- Per shareable skill: `README.md` and `assets/hero.{png,jpg}` — see PII scrubbing below.

**What it does not do:**

- **No network calls** from the Python script itself. `urllib` is imported but never invoked. The only outbound traffic is the optional `gh` call above.
- **No uploads.** The output is written locally to `~/.claude/insight-harness/report.html`. You choose whether to upload the HTML file to [insightharness.com](https://insightharness.com) to share — the extract never does.
- **No telemetry, no analytics, no cookies, no service workers.** The output HTML is a single static file with inlined images — open it offline, email it, host it yourself.

**PII scrubbing before anything ships:** git name/email, OS username paths (`/Users/<you>`, `/home/<you>`), GitHub URLs containing your username, and `@<you>` mentions are redacted from shared content. Hero images are text-scrubbed only (pixel content is out of scope — review your screenshots before uploading). SVG heroes are rejected because PII inside SVG text/CDATA can't be reliably redacted.

## Install (plugin marketplace)

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

## Install (curl fallback, for power users)

If you'd rather not use the plugin system, you can drop the skill directly into your skills directory:

```bash
mkdir -p ~/.claude/skills/insight-harness
curl -sSL https://raw.githubusercontent.com/kabirdos/insight-harness/main/skills/insight-harness/SKILL.md \
  -o ~/.claude/skills/insight-harness/SKILL.md
curl -sSL https://raw.githubusercontent.com/kabirdos/insight-harness/main/skills/insight-harness/scripts/extract.py \
  --create-dirs -o ~/.claude/skills/insight-harness/scripts/extract.py
```

Or clone the whole repo and symlink:

```bash
git clone https://github.com/kabirdos/insight-harness.git
ln -s "$(pwd)/insight-harness/skills/insight-harness" ~/.claude/skills/insight-harness
```

## Output

The skill writes a single-file HTML report to `~/.claude/insight-harness/report.html` and opens it in your browser. Read it locally, or upload it to [insightharness.com](https://insightharness.com) to share as a public profile.

## License

MIT — see [LICENSE](./LICENSE).
