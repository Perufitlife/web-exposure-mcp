#!/usr/bin/env node
// web-exposure-mcp — public-secret-file exposure scanner. Pure Node.js, no deps.
//
// Points at a LIVE deployed URL and confirms whether sensitive files/dirs are
// actually reachable by an anonymous visitor — by FETCHING THE BYTES and
// validating the content, not by trusting a status code or a checklist.
//
// What it confirms (each only fires on real, served content):
//   - /.git/  exposed (config / HEAD / index) → full source history downloadable
//   - /.env and env variants → live secrets (API keys, DB creds) served as text
//   - JavaScript source maps (.js.map) → original source + comments reconstructable
//   - Backup / dump artifacts (.bak .sql .zip .tar.gz .old ~) → code & DB leaks
//   - Directory listing enabled ("Index of /") → browse the whole tree
//   - Served dotfiles (.htpasswd .npmrc .DS_Store .aws/credentials, etc.)
//
// Keyless and read-only: it issues the exact unauthenticated GET an attacker
// would, reads only the first bytes it needs to fingerprint, and reports.
// Nothing is written to the target. Nothing leaves your machine.

const UA = "web-exposure-mcp/0.1 (+https://github.com/Perufitlife/web-exposure-mcp)";
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// HTML/login bodies are the #1 false-positive source: a SPA / catch-all route
// returns 200 with index.html for everything. We treat any response whose body
// looks like an HTML document as "not the secret file" unless the check
// explicitly wants HTML (directory listing).
function looksLikeHtml(body) {
  const head = body.slice(0, 600).toLowerCase();
  return head.includes("<!doctype html") || head.includes("<html") ||
    head.includes("<head") || head.includes("<body") || head.includes("<title");
}

// --- the check catalog --------------------------------------------------------
// Each check: path(s) to fetch + a `confirm(body, res)` that returns a details
// object ONLY when the bytes prove the file is genuinely served.

const CHECKS = [
  {
    id: "git_exposed",
    severity: "critical",
    title: "Public .git directory — full source & history downloadable",
    paths: ["/.git/config", "/.git/HEAD"],
    explain:
      "Your version-control metadata is served to the public. Tools like git-dumper can reconstruct the entire repository — source code, deleted files, and any secrets ever committed. Block /.git at the web server / CDN and never deploy the .git folder.",
    confirm(body) {
      if (looksLikeHtml(body)) return null;
      if (/^\s*\[core\]/m.test(body) || /repositoryformatversion/.test(body)) {
        return { evidence: "valid .git/config served", snippet: body.slice(0, 120).trim() };
      }
      if (/^ref:\s+refs\//m.test(body) || /^[0-9a-f]{40}\s*$/m.test(body.trim())) {
        return { evidence: "valid .git/HEAD served", snippet: body.slice(0, 80).trim() };
      }
      return null;
    },
  },
  {
    id: "env_exposed",
    severity: "critical",
    title: "Environment file (.env) served publicly — live secrets exposed",
    paths: ["/.env", "/.env.local", "/.env.production", "/.env.prod", "/.env.development"],
    explain:
      "A dotenv file is being returned as plain text. These almost always contain database passwords, API keys, JWT secrets and third-party tokens — directly usable by anyone. Remove it from the web root and rotate every credential it contained.",
    confirm(body) {
      if (looksLikeHtml(body)) return null;
      // KEY=VALUE lines, common secret-y names, no HTML.
      const kv = body.match(/^[A-Z][A-Z0-9_]{2,}\s*=.*/gm) || [];
      const secrety = /(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|DB_|DATABASE_URL|PRIVATE_KEY|AWS_|STRIPE_)/i.test(body);
      if (kv.length >= 2 && secrety) {
        const keys = kv.slice(0, 6).map((l) => l.split("=")[0].trim());
        return { evidence: `${kv.length} env vars served`, leaked_keys: keys };
      }
      return null;
    },
  },
  {
    id: "source_map",
    severity: "high",
    title: "JavaScript source map served — original source reconstructable",
    paths: ["/main.js.map", "/app.js.map", "/bundle.js.map", "/index.js.map", "/static/js/main.js.map"],
    explain:
      "A .js.map file is public, letting anyone rebuild your unminified source — including comments, internal endpoints and sometimes embedded keys. Disable source-map emission in production builds, or restrict .map files at the edge.",
    confirm(body) {
      if (looksLikeHtml(body)) return null;
      try {
        const j = JSON.parse(body);
        if (j && typeof j.version === "number" && Array.isArray(j.sources)) {
          return { evidence: "valid source map", source_count: j.sources.length, sample: j.sources.slice(0, 3) };
        }
      } catch { /* not json */ }
      return null;
    },
  },
  {
    id: "backup_artifact",
    severity: "high",
    title: "Backup / dump artifact reachable — code or database leak",
    paths: [
      "/backup.zip", "/backup.sql", "/backup.tar.gz", "/db.sql", "/database.sql",
      "/dump.sql", "/site.zip", "/www.zip", "/index.php.bak", "/config.php.bak",
      "/.env.bak", "/wp-config.php.bak", "/app.zip",
    ],
    explain:
      "An archive or database dump is downloadable. Backups frequently contain the full codebase, configuration and production data. Move backups off the web root and serve nothing matching .bak/.sql/.zip/.tar.gz/.old/~ from public paths.",
    confirm(body, res) {
      if (looksLikeHtml(body)) return null;
      const path = res.__path || "";
      const ct = (res.contentType || "").toLowerCase();
      // SQL dumps: look for dump fingerprints in the bytes.
      if (/\.sql(\.bak)?$/.test(path) || path.endsWith(".bak")) {
        if (/(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|PostgreSQL database dump)/i.test(body)) {
          return { evidence: "SQL dump content served", content_type: ct || "(none)" };
        }
        // a .bak of PHP/config returning code
        if (/<\?php|define\(|DB_PASSWORD|password/i.test(body) && !looksLikeHtml(body)) {
          return { evidence: "source/config backup served", content_type: ct || "(none)" };
        }
      }
      // Archives: confirm by magic bytes, not extension.
      if (/\.(zip|tar\.gz|tgz)$/.test(path)) {
        const b0 = body.charCodeAt(0), b1 = body.charCodeAt(1);
        const isZip = b0 === 0x50 && b1 === 0x4b; // "PK"
        const isGz = b0 === 0x1f && b1 === 0x8b; // gzip
        if (isZip || isGz) {
          return { evidence: isZip ? "ZIP archive served (PK magic bytes)" : "gzip archive served", content_type: ct || "(none)" };
        }
      }
      return null;
    },
  },
  {
    id: "directory_listing",
    severity: "medium",
    title: "Directory listing enabled — the file tree is browsable",
    paths: ["/", "/uploads/", "/files/", "/backup/", "/.git/", "/assets/"],
    explain:
      "The server returns an auto-generated index instead of a page, exposing every file in the folder to enumeration. Disable autoindex (Apache: Options -Indexes; nginx: autoindex off) and add an index file.",
    confirm(body) {
      // Here HTML is expected — but it must be the autoindex signature.
      if (/<title>\s*Index of \//i.test(body) || /Directory listing for /i.test(body) ||
          (/<h1>\s*Index of \//i.test(body))) {
        const m = body.match(/Index of (\/[^<\n]*)/i);
        return { evidence: "autoindex page served", listing_of: m ? m[1].trim() : "/" };
      }
      return null;
    },
  },
  {
    id: "dotfile_served",
    severity: "high",
    title: "Sensitive dotfile served publicly",
    paths: [
      "/.htpasswd", "/.npmrc", "/.netrc", "/.DS_Store",
      "/.aws/credentials", "/.ssh/id_rsa", "/.dockercfg", "/.docker/config.json",
    ],
    explain:
      "A dotfile that should never be public is being served. These leak credential hashes (.htpasswd), registry/auth tokens (.npmrc, .netrc), cloud keys (.aws/credentials), private keys (.ssh/id_rsa) or local file paths (.DS_Store). Remove it and rotate anything it contained.",
    confirm(body, res) {
      if (looksLikeHtml(body)) return null;
      const path = res.__path || "";
      if (path.endsWith(".htpasswd") && /^[^:\s]+:\$?[\w./$]+/m.test(body)) return { evidence: "password hash file served" };
      if (path.endsWith(".npmrc") && /(_authToken|registry=|_auth=)/.test(body)) return { evidence: ".npmrc with auth served" };
      if (path.endsWith(".netrc") && /machine\s+\S+\s+login/.test(body)) return { evidence: ".netrc credentials served" };
      if (path.endsWith(".DS_Store") && /Bud1|   Bud1/.test(body.slice(0, 16))) return { evidence: ".DS_Store served (file names leak)" };
      if (path.endsWith("credentials") && /aws_access_key_id|aws_secret_access_key/i.test(body)) return { evidence: "AWS credentials served" };
      if (path.endsWith("id_rsa") && /BEGIN (?:RSA |OPENSSH )?PRIVATE KEY/.test(body)) return { evidence: "private SSH key served" };
      if ((path.endsWith(".dockercfg") || path.endsWith("config.json")) && /"auth"\s*:/.test(body)) return { evidence: "docker auth config served" };
      return null;
    },
  },
];

// --- HTTP probe ---------------------------------------------------------------

// Fetch with a hard timeout; read at most `maxBytes` of the body so we never
// download a multi-GB backup — a few KB is plenty to fingerprint.
async function probe(url, { timeoutMs = 10000, maxBytes = 65536 } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": UA, Accept: "*/*" },
      redirect: "manual",
      signal: ctrl.signal,
    });
    // Read a bounded slice of the body.
    let body = "";
    if (res.body && typeof res.body.getReader === "function") {
      const reader = res.body.getReader();
      const dec = new TextDecoder("latin1"); // byte-faithful for magic-byte checks
      let got = 0;
      while (got < maxBytes) {
        const { done, value } = await reader.read();
        if (done) break;
        got += value.length;
        body += dec.decode(value, { stream: true });
      }
      try { await reader.cancel(); } catch { /* ignore */ }
    } else {
      body = (await res.text()).slice(0, maxBytes);
    }
    return {
      ok: res.ok,
      status: res.status,
      contentType: res.headers.get("content-type") || "",
      contentLength: res.headers.get("content-length") || "",
      body,
    };
  } catch (e) {
    return { ok: false, status: 0, error: e.name === "AbortError" ? "timeout" : e.message, body: "" };
  } finally {
    clearTimeout(timer);
  }
}

// --- main scan ----------------------------------------------------------------

export async function scan({ url, only = null, timeoutMs = 10000, concurrency = 6 } = {}) {
  if (!url) throw new Error("scan() requires { url }");
  let base;
  try {
    const u = new URL(/^https?:\/\//.test(url) ? url : `https://${url}`);
    base = `${u.protocol}//${u.host}`;
  } catch {
    throw new Error(`invalid url: ${url}`);
  }

  const active = only && only.length ? CHECKS.filter((c) => only.includes(c.id)) : CHECKS;
  const findings = [];
  let requests = 0;
  let confirmed = 0;

  // Build the flat list of (check, path) probes.
  const jobs = [];
  for (const check of active) {
    for (const p of check.paths) jobs.push({ check, path: p });
  }

  // Simple bounded-concurrency runner.
  let cursor = 0;
  const firedChecks = new Set(); // report each check at most once
  async function worker() {
    while (cursor < jobs.length) {
      const { check, path } = jobs[cursor++];
      if (firedChecks.has(check.id)) continue; // already confirmed elsewhere
      const target = base + path;
      const res = await probe(target, { timeoutMs });
      requests++;
      res.__path = path;
      // Only 2xx (and a couple of telling statuses) can carry served content.
      if (res.status < 200 || res.status >= 300) continue;
      const details = check.confirm(res.body, res);
      if (details && !firedChecks.has(check.id)) {
        firedChecks.add(check.id);
        confirmed++;
        findings.push({
          check: check.id,
          severity: check.severity,
          title: check.title,
          target: path,
          url: target,
          status: res.status,
          content_type: res.contentType || "(none)",
          confirmed: true,
          details,
          explain: check.explain,
        });
      }
    }
  }

  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, worker));

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    target: base,
    scanned_by: "web-exposure-mcp v0.1",
    active_probe: { enabled: true, requests, confirmed },
    checks_run: active.map((c) => c.id),
    summary,
    findings,
  };
}

export const ALL_CHECKS = CHECKS.map((c) => ({ id: c.id, severity: c.severity, title: c.title, paths: c.paths }));

// --- CLI (handy for local runs; the primary interface is the MCP server) ------

function parseArgs(argv) {
  const a = argv.slice(2);
  const flag = (k) => { const i = a.indexOf(k); return i !== -1 ? a[i + 1] : null; };
  return {
    help: a.includes("--help") || a.includes("-h"),
    url: flag("--url") || a.find((x) => /^https?:\/\//.test(x)),
    only: (flag("--only") || "").split(",").map((s) => s.trim()).filter(Boolean),
    timeoutMs: Number(flag("--timeout")) || 10000,
  };
}

export async function runCli() {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.url) {
    console.error(`web-exposure-mcp — confirm publicly-served secret files on a live URL.

Usage:
  web-exposure-scan --url https://your-site.example.com
  web-exposure-scan --url https://site.com --only git_exposed,env_exposed
  web-exposure-scan --url https://site.com --timeout 8000

Flags:
  --url <url>         Target base URL (the live deployment to probe)
  --only a,b,c        Run only these checks (${ALL_CHECKS.map((c) => c.id).join(", ")})
  --timeout <ms>      Per-request timeout (default 10000)

Confirms by fetching the bytes: .git exposure, .env secrets, JS source maps,
backup/SQL dumps & archives, directory listing, and sensitive dotfiles.
Read-only — nothing is written to the target. Primary interface is the MCP
server: run \`web-exposure-mcp\` and add it to your AI client.`);
    process.exit(opts.url ? 0 : 1);
  }
  const result = await scan(opts);
  console.log(JSON.stringify(result, null, 2));
  const s = result.summary;
  console.error(`\n${s.critical} critical, ${s.high} high, ${s.medium} medium — ` +
    `${result.active_probe.confirmed} CONFIRMED via anonymous fetch (${result.active_probe.requests} requests)`);
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) runCli().catch((e) => { console.error(e.message); process.exit(1); });
