---
version: 2.7.0
name: insight-harness
description: Generate a comprehensive profile of your Claude Code harness — skills, hooks, workflow patterns, tool usage, token consumption, and plugin inventory across the last 30 days. A superset of /insights — adds token breakdowns, tool usage stats, skill inventory, and more. Upload to insightharness.com to share. Triggers on "insight harness", "harness profile", "my setup", "what skills do I use", "show my harness", or "harness report".
user-invocable: true
argument-hint: "insight-harness"
allowed-tools: Bash, Read, Monitor
---

# Insight Harness

Generate a comprehensive profile of your Claude Code harness configuration and usage patterns over the last 30 days. This is a **superset of /insights** — it includes everything /insights provides, plus token usage, tool breakdowns, skill inventory, hooks, agent patterns, and more.

## What This Does

Runs a Python extraction script that reads harness metadata from:

- `~/.claude/settings.json` (hooks, plugins, permissions)
- `~/.claude/plugins/installed_plugins.json` (plugin inventory)
- `~/.claude/skills/` (skill frontmatter for every skill; plus README.md + `assets/hero.{png,jpg}` by default for skills you've marked as shareable — see the "Skill showcase" section below)
- `~/.claude/usage-data/session-meta/` (pre-computed session stats)
- `~/.claude/projects/*/*.jsonl` (field-whitelisted: tool names, skill names, hook events, tool transition sequences, workflow phase classifications only)
- `~/.claude/projects/*/settings.local.json` (approved permissions)

**Privacy guarantee:** The script uses a strict field whitelist. It NEVER reads tool arguments, message text, tool results, file paths inside your projects, or any project-specific content. Real credentials exist in JSONL files — the script never touches those fields.

**Skill showcase data (default-on):** By default, the script also reads each shareable skill's `README.md` and hero image, scrubs PII from the README text (git name/email, OS username paths, GitHub URLs with your username, `@<you>` mentions), and ships the results. Skills with `repo: private` or `repo: none` in their SKILL.md frontmatter are excluded entirely — they never appear in the output, not even in invocation counts. See the "Skipping showcase content" section if you want to opt out of shipping README + hero data.

## What You Get (vs /insights)

Everything from /insights, plus:

- **Token usage** — input, output, and total token consumption
- **Tool usage breakdown** — Read, Edit, Bash, Grep, etc. with counts
- **Skills & plugins inventory** — what's installed, invocation frequency
- **Hooks** — configured hooks and how often they fire
- **CLI commands** — which bash commands you run most
- **Agent dispatch patterns** — subagent types, models, background usage
- **File operation style** — Edit vs Write ratio
- **Models used** — Opus, Sonnet, Haiku distribution
- **Permission modes** — how you configure access
- **MCP servers** — connected servers
- **Workflow phases** — classifies tool usage into phases (exploration, implementation, testing, shipping, orchestration) and shows the distribution across sessions
- **Phase transitions** — tracks how you move between workflow phases (e.g., exploration -> implementation), with statistics on disciplined patterns like "test before ship"
- **Tool transitions** — tracks sequential tool usage patterns within turns (e.g., Read -> Edit), showing your most common tool flows

## How to Run

The extract walks thousands of JSONL files plus the user's home tree and can take anywhere from 30 seconds to several minutes depending on machine size. A blocking foreground Bash call will hit its 10-minute ceiling on heavy setups and abort mid-run with no report produced.

**Always run the script through the Monitor tool.** Do not call it as a blocking Bash command. Do not set a custom Bash `timeout` and hope it fits.

### Required invocation

1. Start the extract via the Monitor tool. Redirect stderr to stdout so the script's phase markers (`Extracting settings... / Reading plugins... / Scanning skills... / Reading hooks... / Reading permissions... / Scanning JSONL... / Generating HTML...`) stream as Monitor events in real time:
   - `command`: `python3 ~/.claude/skills/insight-harness/scripts/extract.py --include-skills 2>&1`
   - `description`: `insight-harness extract progress`
   - `timeout_ms`: `3600000` (1 hour — Monitor's max; accommodates even very heavy machines)
   - `persistent`: `false`

   `--include-skills` is the default behavior and ships per-skill README + hero data; see "Skipping showcase content" below if you need to opt out.

2. Relay each phase event to the user as it arrives so they see progress instead of a silent multi-minute hang.

3. When the script exits cleanly, Monitor stops. The **final Monitor event is the absolute path** to the generated HTML report (e.g. `/Users/you/.claude/insight-harness/report.html`) — that path is `extract.py`'s last stdout line.

4. Open that path in the user's browser via a plain Bash call:

   ```bash
   open <absolute-path-from-step-3>
   ```

This is the only supported invocation pattern. Do not start the script via `Bash` with `run_in_background`, and do not call it as a foreground blocking Bash command — both paths regress users who have large session histories or heavy home directories.

### What ships per skill

- README.md (or, if absent, the SKILL.md body) — PII-scrubbed: git name/email, OS username paths (`/Users/<you>`, `/home/<you>`), GitHub URLs containing your username, and `@<you>` mentions are replaced with placeholders.
- Hero image at `assets/hero.png` or `assets/hero.jpg` — PNG/JPEG only (SVG is rejected because PII inside SVG text/CDATA can't be reliably scrubbed). 300KB hard cap per image, 100KB cap on README, 400KB total per skill.

### What does not ship

- Skills with `repo: private` or `repo: none` in their SKILL.md frontmatter — these are skipped entirely (not even listed).
- Anything beyond the 6MB serialized payload budget — low-call skills lose their showcase content first if the budget is tight; their stats still appear.

**Review your hero images before uploading.** The PII scrubber operates on text only — it cannot read pixels. A screenshot showing your username, a path, or any visible identifier will ship as-is. Open `assets/hero.png` for each shareable skill and confirm there's nothing identifying in the image itself.

### Skipping showcase content (`--no-include-skills`)

If you want a smaller report without per-skill READMEs and heroes (original 2.3.0 behavior), pass `--no-include-skills`. Same background + Monitor invocation pattern as above:

```bash
python3 ~/.claude/skills/insight-harness/scripts/extract.py --no-include-skills
```

## Updating

The skill checks for updates automatically when you run it. To update manually:

```bash
python3 ~/.claude/skills/insight-harness/scripts/extract.py --update
```

Or re-run the install command:

```bash
curl -sL https://github.com/craigdossantos/claude-toolkit/archive/main.tar.gz | tar xz -C /tmp && cp -r /tmp/claude-toolkit-main/skills/insight-harness ~/.claude/skills/ && rm -rf /tmp/claude-toolkit-main
```

After running, tell the user:

1. Where the report was saved
2. That it's been opened in their browser
3. A brief summary of the top-level stats (sessions, tokens, skills used, hooks active)
4. They can upload the report to insightharness.com to share their profile publicly
