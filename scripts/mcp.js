#!/usr/bin/env node
// web-exposure-mcp — Model Context Protocol server (stdio, JSON-RPC 2.0).
//
// Zero dependencies: implements the MCP handshake + tools/list + tools/call by
// hand over stdin/stdout, so it runs anywhere Node >=18 does with `npx`.
//
// Exposes two tools to the AI agent:
//   - scan_web_exposure   : probe a live URL, confirm publicly-served secret files
//   - list_exposure_checks: enumerate the checks the scanner can run
//
// Add to an MCP client (e.g. Claude Desktop) with:
//   { "mcpServers": { "web-exposure": { "command": "npx",
//       "args": ["-y", "web-exposure-mcp"] } } }

import { scan, ALL_CHECKS } from "./scan.js";
import { createInterface } from "node:readline";

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "web-exposure-mcp", version: "0.1.0" };

const TOOLS = [
  {
    name: "scan_web_exposure",
    description:
      "Probe a LIVE deployed URL and confirm which sensitive files/directories are actually publicly reachable — by fetching the bytes, not guessing. Detects exposed .git, .env secrets, JavaScript source maps, backup/SQL dumps & archives (.bak/.sql/.zip), directory listing, and sensitive dotfiles (.htpasswd/.npmrc/.aws/credentials/.ssh/id_rsa). Read-only: nothing is written to the target. Returns only findings that are genuinely served, with evidence.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The live base URL to scan, e.g. https://example.com (scheme optional, defaults to https).",
        },
        only: {
          type: "array",
          items: { type: "string", enum: ALL_CHECKS.map((c) => c.id) },
          description: "Optional: run only these check ids. Omit to run all.",
        },
        timeout_ms: {
          type: "number",
          description: "Optional per-request timeout in milliseconds (default 10000).",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "list_exposure_checks",
    description:
      "List every exposure check this server can run, with its id, severity, and the paths it probes. Use this to discover check ids for the `only` filter of scan_web_exposure.",
    inputSchema: { type: "object", properties: {} },
  },
];

function reply(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}
function replyError(id, code, message) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
}

async function handle(msg) {
  const { id, method, params } = msg;

  // Notifications (no id) — acknowledge silently.
  if (id === undefined || id === null) return;

  switch (method) {
    case "initialize":
      return reply(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
      });

    case "ping":
      return reply(id, {});

    case "tools/list":
      return reply(id, { tools: TOOLS });

    case "tools/call": {
      const name = params?.name;
      const args = params?.arguments || {};
      try {
        if (name === "scan_web_exposure") {
          if (!args.url) throw new Error("missing required argument: url");
          const result = await scan({
            url: args.url,
            only: Array.isArray(args.only) ? args.only : null,
            timeoutMs: typeof args.timeout_ms === "number" ? args.timeout_ms : 10000,
          });
          return reply(id, {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            isError: false,
          });
        }
        if (name === "list_exposure_checks") {
          return reply(id, {
            content: [{ type: "text", text: JSON.stringify({ checks: ALL_CHECKS }, null, 2) }],
            isError: false,
          });
        }
        return reply(id, {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        });
      } catch (e) {
        return reply(id, {
          content: [{ type: "text", text: `Error: ${e.message}` }],
          isError: true,
        });
      }
    }

    default:
      return replyError(id, -32601, `Method not found: ${method}`);
  }
}

export function start() {
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      return; // ignore non-JSON noise
    }
    handle(msg).catch((e) => {
      if (msg && msg.id != null) replyError(msg.id, -32603, e.message);
    });
  });
  console.error("web-exposure-mcp (stdio) ready — 2 tools, read-only live URL probing.");
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) start();
