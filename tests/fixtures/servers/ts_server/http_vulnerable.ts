/**
 * Vulnerable TypeScript HTTP MCP fixture server.
 *
 * Mirrors http_vulnerable.py but in TypeScript to satisfy the Milestone 2
 * CI matrix requirement (cross-language fixture servers).
 *
 * Vulnerabilities (deliberate):
 *   1. No Origin header validation.
 *   2. No MCP-Session-Id validation.
 *   3. No MCP-Protocol-Version validation.
 *   4. resources/read has no path sanitisation.
 *
 * Usage:
 *   node http_vulnerable.js [port]
 *   (prints the actual bound port to stdout on startup)
 */

import * as http from "http";
import * as fs from "fs";

const port = parseInt(process.argv[2] ?? "0", 10);

function dispatch(msg: Record<string, unknown>): Record<string, unknown> {
  const method = String(msg["method"] ?? "");
  const id = msg["id"] ?? null;

  if (method === "initialize") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2025-03-26",
        capabilities: { resources: {} },
        serverInfo: { name: "vulnerable-ts-http-server", version: "0.1.0" },
      },
    };
  }

  if (method === "notifications/initialized") {
    return {};
  }

  if (method === "resources/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        resources: [],
        resourceTemplates: [{ uriTemplate: "file://{path}", name: "file-reader" }],
      },
    };
  }

  if (method === "resources/read") {
    const params = (msg["params"] ?? {}) as Record<string, unknown>;
    const uri = String(params["uri"] ?? "");
    const pathStr = uri.replace(/^file:\/\//, "");
    try {
      const content = fs.readFileSync(pathStr, { encoding: "utf8" });
      return {
        jsonrpc: "2.0",
        id,
        result: { contents: [{ uri, text: content }] },
      };
    } catch (err) {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32001, message: String(err) },
      };
    }
  }

  if (id !== null) {
    return { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } };
  }
  return {};
}

const server = http.createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/mcp") {
    res.writeHead(404);
    res.end();
    return;
  }

  let body = "";
  req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
  req.on("end", () => {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(body) as Record<string, unknown>;
    } catch {
      res.writeHead(400);
      res.end();
      return;
    }

    const response = dispatch(msg);
    const raw = JSON.stringify(response);
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(raw),
      "MCP-Session-Id": "ts-session-abc123",
    });
    res.end(raw);
  });
});

server.listen(port, "127.0.0.1", () => {
  const addr = server.address() as { port: number };
  // Print bound port so the test harness can read it.
  process.stdout.write(String(addr.port) + "\n");
});
