// Tests for web-exposure-mcp. Pure Node, no deps. Run: node test/scan.test.js
//
// We simulate a target server by monkeypatching global.fetch to return a
// minimal stream-capable Response, then assert:
//   1. a leaky site is flagged on each check (with confirmed evidence)
//   2. a clean/SPA site (200 + HTML for everything) yields ZERO findings
//      (the catch-all false-positive trap)
//   3. the MCP layer answers initialize / tools/list / tools/call correctly

import { scan, ALL_CHECKS } from "../scripts/scan.js";
import assert from "node:assert";

// Build a fake Response whose body is a ReadableStream of `bytes`.
function fakeResponse(status, body, contentType = "") {
  const bytes = typeof body === "string" ? Buffer.from(body, "latin1") : body;
  const headers = new Map([["content-type", contentType], ["content-length", String(bytes.length)]]);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers.get(k.toLowerCase()) ?? null },
    body: {
      getReader() {
        let sent = false;
        return {
          read: async () => (sent ? { done: true } : ((sent = true), { done: false, value: new Uint8Array(bytes) })),
          cancel: async () => {},
        };
      },
    },
  };
}

const LEAKY = {
  "/.git/config": fakeResponse(200, "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"),
  "/.env": fakeResponse(200, "API_KEY=sk_live_abc123\nDATABASE_URL=postgres://u:p@h/db\nJWT_SECRET=xyz\n"),
  "/main.js.map": fakeResponse(200, JSON.stringify({ version: 3, sources: ["src/index.ts", "src/secret.ts"], mappings: "" }), "application/json"),
  "/backup.sql": fakeResponse(200, "-- MySQL dump 10.13\nCREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);\n"),
  "/uploads/": fakeResponse(200, "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>", "text/html"),
  "/.htpasswd": fakeResponse(200, "admin:$apr1$abc$def123/\nuser:$2y$10$xyz\n"),
};

function mockFetch(map, { spaCatchAll = false } = {}) {
  return async (url) => {
    const path = new URL(url).pathname;
    if (map[path]) return map[path];
    if (spaCatchAll) {
      // The classic false-positive trap: every path returns 200 + index.html.
      return fakeResponse(200, "<!doctype html><html><head><title>My App</title></head><body><div id=root></div></body></html>", "text/html");
    }
    return fakeResponse(404, "not found");
  };
}

let pass = 0;
const ok = (cond, label) => { assert.ok(cond, label); console.log("PASS:", label); pass++; };

// --- 1. leaky site: every check confirms with evidence ----------------------
globalThis.fetch = mockFetch(LEAKY);
let r = await scan({ url: "https://leaky.test" });

ok(r.findings.find((f) => f.check === "git_exposed")?.confirmed, "flags exposed .git");
ok(r.findings.find((f) => f.check === "env_exposed")?.confirmed, "flags served .env");
const env = r.findings.find((f) => f.check === "env_exposed");
ok(env?.details?.leaked_keys?.includes("API_KEY"), ".env finding lists leaked key names");
ok(r.findings.find((f) => f.check === "source_map")?.confirmed, "flags JS source map");
ok(r.findings.find((f) => f.check === "backup_artifact")?.confirmed, "flags SQL backup dump");
ok(r.findings.find((f) => f.check === "directory_listing")?.confirmed, "flags directory listing");
ok(r.findings.find((f) => f.check === "dotfile_served")?.confirmed, "flags served .htpasswd dotfile");
ok(r.active_probe.confirmed >= 6, "confirms >=6 leaks via probe");
ok(r.summary.critical >= 2, "summary counts critical findings (.git + .env)");

// --- 2. SPA catch-all: 200 + HTML for EVERYTHING must be clean ---------------
globalThis.fetch = mockFetch({}, { spaCatchAll: true });
r = await scan({ url: "https://spa.test" });
ok(r.findings.length === 0, "SPA catch-all (200 HTML everywhere) yields ZERO false positives");

// --- 3. clean site: all 404 → clean -----------------------------------------
globalThis.fetch = mockFetch({});
r = await scan({ url: "https://clean.test" });
ok(r.findings.length === 0, "all-404 site is clean");

// --- 4. `only` filter narrows the checks ------------------------------------
globalThis.fetch = mockFetch(LEAKY);
r = await scan({ url: "https://leaky.test", only: ["env_exposed"] });
ok(r.checks_run.length === 1 && r.checks_run[0] === "env_exposed", "`only` filter restricts checks");
ok(r.findings.every((f) => f.check === "env_exposed"), "`only` filter restricts findings");

// --- 5. MCP layer: drive the real server over stdio (JSON-RPC handshake) -----
// This is the source of truth — it spawns scripts/mcp.js and exercises
// initialize, tools/list and tools/call exactly as a real MCP client would.
await mcpRoundtrip();

console.log(`\n${pass} tests passed`);

async function mcpRoundtrip() {
  const { spawn } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const { dirname, join } = await import("node:path");
  const here = dirname(fileURLToPath(import.meta.url));
  const mcpPath = join(here, "..", "scripts", "mcp.js");

  const child = spawn(process.execPath, [mcpPath], { stdio: ["pipe", "pipe", "ignore"] });
  const lines = [];
  let buf = "";
  child.stdout.on("data", (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const l = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (l) lines.push(JSON.parse(l));
    }
  });

  const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_exposure_checks", arguments: {} } });

  // Wait for 3 responses.
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("MCP roundtrip timed out")), 8000);
    const iv = setInterval(() => {
      if (lines.length >= 3) { clearInterval(iv); clearTimeout(t); resolve(); }
    }, 25);
  });
  child.kill();

  const init = lines.find((m) => m.id === 1);
  ok(init?.result?.serverInfo?.name === "web-exposure-mcp", "MCP initialize returns serverInfo");
  const list = lines.find((m) => m.id === 2);
  const toolNames = (list?.result?.tools || []).map((t) => t.name);
  ok(toolNames.length === 2, "MCP tools/list returns 2 tools over stdio");
  ok(toolNames.includes("scan_web_exposure"), "MCP exposes scan_web_exposure tool");
  ok(toolNames.includes("list_exposure_checks"), "MCP exposes list_exposure_checks tool");
  const scanTool = list.result.tools.find((t) => t.name === "scan_web_exposure");
  ok(scanTool.inputSchema.required.includes("url"), "scan_web_exposure requires url");
  const call = lines.find((m) => m.id === 3);
  const payload = JSON.parse(call.result.content[0].text);
  ok(payload.checks.length === ALL_CHECKS.length, "MCP tools/call list_exposure_checks returns all checks");
}
