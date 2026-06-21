# web-exposure-mcp

> An **MCP server** that lets an AI agent point at a **live deployed URL** and confirm whether sensitive files are actually being served to the public — exposed `.git`, `.env` secrets, JavaScript source maps, backup/SQL dumps, directory listing, and dotfiles — by **fetching the bytes and validating the content**. Other tools give you a checklist of *maybes*; this reports only what is genuinely reachable, with evidence.

> ⚡ **Run it in one line, no install, no API key:**
> ```bash
> npx web-exposure-mcp        # MCP server (stdio) for your AI client
> npx -p web-exposure-mcp web-exposure-scan --url https://your-site.com   # one-shot CLI
> ```

> 🤝 **Want it done for you?** [Fixed-scope external-exposure audit — $99 / 24h](https://buy.stripe.com/3cIeVdgikfj47yx9LkcAo0m): I verify every finding live and send a written report with the exact fixes and which credentials to rotate.

[![npm](https://img.shields.io/npm/v/web-exposure-mcp?color=red)](https://www.npmjs.com/package/web-exposure-mcp) [![downloads](https://img.shields.io/npm/dw/web-exposure-mcp)](https://www.npmjs.com/package/web-exposure-mcp) ![license](https://img.shields.io/badge/license-MIT-green) ![node](https://img.shields.io/badge/node-%3E%3D18-blue) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

```
$ npx -p web-exposure-mcp web-exposure-scan --url https://demo.example.com
2 critical, 2 high, 1 medium — 5 CONFIRMED via anonymous fetch (39 requests)
  CRITICAL  /.git/config   valid .git served — full source history downloadable
  CRITICAL  /.env          5 env vars served — API_KEY, DATABASE_URL, JWT_SECRET…
  HIGH      /main.js.map   valid source map — 142 original sources reconstructable
  HIGH      /backup.sql    SQL dump content served
  MEDIUM    /uploads/      directory listing enabled (Index of /uploads)
```

## Why this exists

Publicly-served `.git` and `.env` files are routinely called *one of the most
common high-impact findings in external attack-surface management* — Acunetix,
Invicti and Legba all ship dedicated detections, and live HackerOne reports for
exposed `.git`/`.env` are filed continuously. June 2026 saw record
leaked-credential dumps, a large share sourced from **live, misconfigured
servers** rather than breached databases.

The MCP ecosystem already covers SSL, CORS, security-headers, SEO audits, and
**code/commit** secret scanning (GitHub MCP, GitGuardian) — but **no MCP server
probes a *deployed URL* for publicly-served secret files.** This fills that gap:
your agent can audit the live edge of any deployment, the way an attacker
actually sees it.

The hard part isn't requesting `/.env` — it's avoiding false positives. Most
modern sites answer `200 OK` with `index.html` for *every* unknown path (SPA
catch-all). `web-exposure-mcp` therefore **reads the bytes and fingerprints the
content** (e.g. `.git/config` must parse as a git config, `.env` must contain
`KEY=VALUE` secret lines, an archive must start with the real magic bytes) —
so it flags facts, not guesses.

## Tools (MCP)

| Tool | What it does |
|---|---|
| `scan_web_exposure` | Probe a live URL and return only the secret files genuinely served, with evidence. Args: `url` (required), `only` (optional check filter), `timeout_ms`. |
| `list_exposure_checks` | List every check id, severity and the paths it probes — feed ids into `only`. |

## What it confirms

| Check id | Severity | Confirmed by |
|---|---|---|
| `git_exposed` | critical | `/.git/config` parses as a git config, or `/.git/HEAD` is a valid ref/sha |
| `env_exposed` | critical | dotenv served with ≥2 `KEY=VALUE` secret lines (not HTML) |
| `source_map` | high | `.js.map` parses as a source map with a `sources[]` array |
| `backup_artifact` | high | SQL-dump fingerprints, or ZIP/gzip **magic bytes** in the body |
| `directory_listing` | medium | the autoindex signature (`Index of /…`) is returned |
| `dotfile_served` | high | `.htpasswd` hashes, `.npmrc`/`.netrc` tokens, `.aws/credentials`, `.ssh/id_rsa`, `.DS_Store`, docker auth |

Every check fires **at most once** and only when the served bytes prove it.
Read-only: the scanner never writes anything to the target, follows no
redirects into other hosts, and reads at most 64 KB per file (so it fingerprints
a multi-GB backup without downloading it).

## Add to your AI client

Claude Desktop / Cursor / any MCP client — add to your `mcpServers` config:

```json
{
  "mcpServers": {
    "web-exposure": {
      "command": "npx",
      "args": ["-y", "web-exposure-mcp"]
    }
  }
}
```

Then ask your agent: *“Scan https://staging.myapp.com for publicly exposed
secret files.”*

## CLI usage

```bash
# Probe a live deployment
npx -p web-exposure-mcp web-exposure-scan --url https://your-site.com

# Run only specific checks
npx -p web-exposure-mcp web-exposure-scan --url https://your-site.com --only git_exposed,env_exposed

# Tighter per-request timeout
npx -p web-exposure-mcp web-exposure-scan --url https://your-site.com --timeout 8000
```

Output is JSON on stdout (pipe into CI) and a one-line summary on stderr.

## Install (optional)

```bash
npm i -g web-exposure-mcp
web-exposure-mcp                       # start the MCP server (stdio)
web-exposure-scan --url https://site.com   # one-shot scan
```

Zero dependencies, pure Node ≥18. Every request goes straight from the tool to
the target you name — nothing leaves your machine.

## Sister tools

Same active-probe philosophy — confirm the real issue by fetching it, not by
trusting a checklist. All MIT:

[supabase-security](https://github.com/Perufitlife/supabase-security-skill) ·
[strapi-security](https://github.com/Perufitlife/strapi-security) ·
[pocketbase-security](https://github.com/Perufitlife/pocketbase-security-skill) ·
[firebase-security](https://github.com/Perufitlife/firebase-security-skill) ·
[appwrite-security](https://github.com/Perufitlife/appwrite-security-skill) ·
[nhost-security](https://github.com/Perufitlife/nhost-security-skill)

## License

MIT © [Renzo Madueno](https://github.com/Perufitlife)
