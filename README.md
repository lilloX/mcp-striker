# ⚡ mcp-striker
**Deterministic exploit validation for Model Context Protocol (MCP) servers.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Active](https://img.shields.io/badge/Status-Active-green.svg)]()

`mcp-striker` is an offensive security tool that acts as a malicious-but-controlled MCP client. It connects to a target MCP server, enumerates its exposed capabilities, executes exploit probes against Resources and Tools, and produces replayable JSON-RPC evidence artifacts for confirmed vulnerabilities.

Dynamic MCP validators already exist, but most drive the target through a real LLM agent — useful for surfacing behavior, but the verdict rides on whatever that agent happened to do, and re-running it isn't guaranteed to reproduce the same result. `mcp-striker` takes a different approach: it speaks the JSON-RPC protocol directly, with no LLM in the loop, so every probe and every finding is **deterministic and replayable**.

**No LLM-dependent verdicts. No AI vibes. Just deterministic protocol interactions and replayable evidence.**

> ⚠️ **Disclaimer:** `mcp-striker` is designed for authorized red teaming and vulnerability assessment only. Do not use it against MCP servers or agentic workflows you do not have explicit permission to test.

---

## 💻 Installation

**Prerequisites:** Python 3.12+, Node.js 18+ (only if testing JavaScript MCP servers)

```bash
git clone <repo>
cd mcp-striker
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e .
```

This installs all dependencies declared in `pyproject.toml`:
`pydantic`, `typer`, `rich`, `httpx`, `httpx-sse`, `pyyaml`, `jsonpath-ng`, `jinja2`.

---

## 🚀 Engagement Walkthrough

A complete engagement from first connection to final report.

### Step 1 — Enumerate the attack surface

Connect to the target and save a capability snapshot.

```bash
# STDIO server
mcp-striker enum --cmd "python /absolute/path/to/server.py"

# HTTP server
mcp-striker enum --transport http --url http://target:8080

# Legacy SSE server
mcp-striker enum --transport sse --url http://target:9007
```

The snapshot is saved to `.mcp-striker/<server-name>/sessions/<server-name>.json`.
The output shows discovered resources, tools, and their parameter schemas.

---

### Step 2 — Generate YAML scaffolds

Generate pre-filled module skeletons for every tool and resource template.
Pass `--allow-mutating` to also probe each tool with empty values and embed
the real server response as a comment — useful for writing accurate regex matchers.

```bash
mcp-striker scaffold \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --allow-mutating
```

Files are written into two subdirectories under `modules/servers/<server-name>/`:

- `tool/` — one file per tool with injectable string parameters
- `template/` — one file per resource template (URI templates with `{placeholders}`)

Each file has payloads and matchers **commented out** — valid YAML but completely
inert until you edit it.

---

### Step 3 — Edit the scaffold

Open each generated file and make two changes:

1. **Uncomment the payloads** you want to test. Each file contains payload suggestions
   as comments inside the `payloads:` block, categorised by parameter/placeholder name:
   - `path`, `file`, `filepath` → path traversal
   - `url`, `uri`, `endpoint` → SSRF
   - `code`, `script`, `function`, `expression` → code eval
   - `command`, `cmd`, `args` → command injection
   - `id`, `user_id`, `account`, etc. → IDOR (numeric IDs + common names)

2. **Add a content-evidence matcher.** A step with only `jsonrpc_success` is rejected
   at parse time — it would match any successful call. You must add a `regex` or
   `json_path` matcher that confirms the response is anomalous. Use the
   `# SAMPLE RESPONSE` block (present when `--allow-mutating` was passed in Step 2)
   to see exactly what the server returns and calibrate your pattern.

**Tool scaffold — before and after:**

```yaml
# BEFORE (generated skeleton — completely inert)
    payloads:
      # - "/etc/passwd"
      # - "../../../etc/passwd"
    matchers:
      # - type: jsonrpc_success
      # - type: regex
      #   pattern: "root:x:0:0|Linux version|localhost|..."

# AFTER (ready to run)
    payloads:
      - "/etc/passwd"
      - "../../../etc/passwd"
    matchers:
      - type: jsonrpc_success
      - type: regex
        pattern: "root:x:0:0"
```

**Template scaffold — before and after:**

```yaml
# BEFORE (generated skeleton for secret://user/{id}/data)
    params:
      uri: "secret://user/${payload}/data"
    payloads:
      # - "0"
      # - "1"
      # - "admin"
    matchers:
      # - type: jsonrpc_success
      # - type: regex
      #   pattern: "secret|token|password|key|data|content"

# AFTER (ready to run)
    params:
      uri: "secret://user/${payload}/data"
    payloads:
      - "0"
      - "1"
      - "2"
      - "admin"
    matchers:
      - type: jsonrpc_success
      - type: regex
        pattern: '"secrets"\s*:|"apiKey"\s*:|"username"\s*:'
```

---

### Step 4 — Dry-run to validate matchers

Run the probe without writing any finding artifacts to disk.
Prints each request + response and a per-matcher `WOULD MATCH / would NOT match` verdict.

```bash
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --module modules/servers/<server>/<server>-<tool>.yaml \
  --dry-run \
  --allow-mutating
```

Iterate on the regex pattern until the verdict is correct, then proceed to the real run.

---

### Step 5 — Strike

Execute probes and write confirmed findings to disk.

```bash
# Single module
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --module modules/servers/<server>/<server>-<tool>.yaml \
  --allow-mutating

# Generic modules + server-specific modules
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --modules-dir modules/basic \
  --modules-dir modules/servers/<server> \
  --allow-mutating
```

Confirmed findings are written to `.mcp-striker/<server>/findings/MCPSTRIKE-NNN.json`.
Each artifact contains the full raw request/response pair and is self-contained and replayable.

> ⚠️ **Findings and session transcripts are raw evidence, not sanitized deliverables.**
> Write-time redaction is **key-based only** (`Authorization`, `cookie`, `password`,
> `*_token`, `*_secret`, api keys, …) and does not remove secrets embedded in free
> text (e.g. a config/file body a probe reads), the `payload`, or the raw
> transcripts — that leaked material is often the proof of the vulnerability.
> Artifacts are written owner-only (`0700`/`0600`); treat them as confidential and
> review/redact their contents before sharing.

---

### Step 6 — Generate the report

```bash
mcp-striker report \
  --base-dir .mcp-striker/<server>/ \
  --title "Target Corp — MCP Security Assessment"
```

Produces `report.html`: a self-contained file with executive summary, severity chart, findings with proof, tested surface, and probe metrics. Pass `--format markdown` for a GitLab/GitHub-ready alternative.

---

## 🚌 Supported Transports

| Flag | Protocol | Use when |
|---|---|---|
| _(default)_ | STDIO | Server is launched as a subprocess |
| `--transport http` | Streamable HTTP (2025-03-26) | Modern HTTP server |
| `--transport sse` | HTTP+SSE legacy (2024-11-05) | Older servers (e.g. `damn-vulnerable-MCP-server`) |

> **How to tell them apart:** if connecting to a URL and `--transport http` returns `HTTP 405: Method Not Allowed`, the server uses the legacy SSE transport — switch to `--transport sse`.

---

## 💻 CLI Reference

### `enum` — Enumerate the attack surface

```bash
# STDIO (default)
mcp-striker enum --cmd "python /absolute/path/to/server.py"

# Streamable HTTP
mcp-striker enum --transport http --url http://server:8080

# HTTP+SSE legacy (protocol 2024-11-05)
mcp-striker enum --transport sse --url http://server:9007

# Custom path (server not on /mcp)
mcp-striker enum --transport http --url http://server:8080 --path /api/mcp
mcp-striker enum --transport sse  --url http://server:9007 --path /sse

# Self-signed / mismatched TLS certificate
mcp-striker enum --transport http --url https://server:8443 --no-verify-ssl
mcp-striker enum --transport sse  --url https://server:9007 --no-verify-ssl --path /sse

# JWT authentication — HTTP: Bearer header
mcp-striker enum --transport http --url http://server:8080 \
  --header "Authorization=Bearer eyJhbGciOiJSUzI1NiJ9..."

# JWT authentication — STDIO: environment variable
mcp-striker enum --cmd "node /abs/path/server.js" \
  --extra-env "MCP_TOKEN=eyJhbGciOiJSUzI1NiJ9..."

# Multiple headers
mcp-striker enum --transport http --url http://server:8080 \
  --header "Authorization=Bearer eyJ..." \
  --header "X-Tenant-Id=acme"
```

Output is saved automatically to `.mcp-striker/<server-name>/`. Use `--output-dir` to override.

> **Important — STDIO requires absolute paths.**
> `StdioTransport` runs the subprocess in a temporary sandbox directory,
> so relative paths like `python server.py` will fail with `FileNotFoundError`.

---

### `strike` — Execute probes

```bash
# Basic — uses transport and path saved during enum
mcp-striker strike --from-enum .mcp-striker/<server>/sessions/<server>.json

# Generic modules only
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --modules-dir modules/basic

# Generic + server-specific (--modules-dir is repeatable)
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --modules-dir modules/basic \
  --modules-dir modules/servers/<server>

# Single module
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --module modules/servers/chrome/chrome_navigate_ssrf.yaml

# Allow mutating tools (required for tools/call probes on unknown/mutating tools)
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --modules-dir modules/basic \
  --modules-dir modules/servers/<server> \
  --allow-mutating

# Dry-run: see probe responses without writing findings
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --module modules/basic/tools/tool_path_traversal.yaml \
  --dry-run

# Override the transport saved in the registry (useful if enum used wrong transport)
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --modules-dir modules/basic \
  --transport sse --path /sse

# TLS and auth overrides (same flags as enum)
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --no-verify-ssl \
  --header "Authorization=Bearer eyJ..."
```

**`--dry-run`** executes all probes normally but does not write finding artifacts to disk. For each probe, it prints the compact request + response JSON and a per-matcher `WOULD MATCH / would NOT match` verdict. Use it to calibrate regex patterns before a real strike run.

---

### `scaffold` — Generate YAML module skeletons

After `enum`, generate pre-filled starting points for custom probes:

```bash
# Offline — generate skeletons from snapshot only
mcp-striker scaffold --from-enum .mcp-striker/<server>/sessions/<server>.json

# With sample responses — connect and probe each tool with empty values
mcp-striker scaffold \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --allow-mutating
```

Writes files into two subdirectories under `modules/servers/<server-name>/`:

- **`tool/`** — one file per tool with injectable string parameters. Each file contains:
  - Tool name and parameter name pre-filled; one step per injectable parameter
  - Payload suggestions as **comments** categorised by parameter semantics (`path` → path traversal, `url` → SSRF, `id` → IDOR, …)
  - All matchers commented out
  - `# SAMPLE RESPONSE` block when `--allow-mutating` is passed

- **`template/`** — one file per resource template (e.g. `secret://user/{id}/data`). Each file contains:
  - One step per `{placeholder}` in the URI template
  - The URI pre-wired as `scheme://prefix/${payload}/suffix` with the placeholder replaced
  - Payload suggestions based on placeholder name and URI scheme
  - All matchers commented out

```bash
# After editing the scaffold:
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --module modules/servers/<server>/tool/<server>-<tool>.yaml \
  --allow-mutating

# Or run generic + server-specific modules together:
mcp-striker strike \
  --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --modules-dir modules/basic \
  --modules-dir modules/servers/<server>/ \
  --allow-mutating
```

> **Matcher rule:** a `mutate` step with only `jsonrpc_success` is rejected at parse time — it has no content evidence and would match any successful response. Always combine it with a `regex` or `json_path` matcher.

---

### `report` — Generate PT deliverable

```bash
# HTML report (default) — auto-detects base dir when only one server tested
mcp-striker report

# Explicit base dir (required when multiple servers tested)
mcp-striker report --base-dir .mcp-striker/<server>/

# Markdown
mcp-striker report --base-dir .mcp-striker/<server>/ --format markdown --output report.md

# Custom title
mcp-striker report \
  --base-dir .mcp-striker/<server>/ \
  --title "ACME Corp — MCP Security Assessment"
```

The report reads findings, session transcripts, and the enum snapshot from `--base-dir` and generates a self-contained HTML file with: executive summary, severity chart, findings with proof, tested surface, probe metrics (sent / blocked / failed).

---

### `http-probe` — Transport security probes (HTTP only)

```bash
# With enum snapshot — inherits URL and writes findings alongside strike output
mcp-striker http-probe --from-enum .mcp-striker/<server>/sessions/<server>.json

# Standalone — output goes to .mcp-striker/<hostname>/
mcp-striker http-probe --url http://server:8080

# --url overrides the URL from the snapshot (e.g. different port/path)
mcp-striker http-probe --from-enum .mcp-striker/<server>/sessions/<server>.json \
  --url https://server:8443 --no-verify-ssl
```

Tests: missing Origin validation, protocol version not enforced, session ID reuse accepted.

When `--from-enum` is used, findings land in the same `.mcp-striker/<server>/findings/`
directory as `strike` findings — `mcp-striker report` picks them all up automatically.

---

### `auth-diff` — Broken access control (IDOR)

```bash
mcp-striker auth-diff \
  --identities identities.yaml \
  --ownership ownership.yaml \
  --cmd "python /abs/path/server.py"
```

---

## 📁 Modules structure

```
modules/
├── basic/             ← generic modules, not server-specific
│   ├── resource/      ← protocol-level attacks on resources/read
│   │   ├── resource_path_traversal.yaml   (critical)
│   │   ├── resource_enumeration.yaml      (high)
│   │   └── ssrf_via_resource.yaml         (high)
│   └── tools/         ← generic tools/call attacks
│       ├── tool_path_traversal.yaml       (critical)
│       ├── tool_ssrf.yaml                 (high)
│       └── tool_command_injection.yaml    (critical)
└── servers/           ← empty by default; populated during engagements
```

`modules/servers/` is intentionally empty in the default distribution.
Server-specific modules are **engagement assets**: they are generated by
`mcp-striker scaffold` and written by the operator during an assessment.

`--modules-dir` is repeatable — pass it multiple times to compose exactly
the module set you need without loading unrelated engagement assets:

```bash
mcp-striker strike --from-enum ... \
  --modules-dir modules/basic \
  --modules-dir modules/servers/<server>/
```

---

## 📄 Evidence Artifacts

Every confirmed finding produces a self-contained, replayable artifact.

```json
{
  "schema_version": "mcp-striker.finding/v1",
  "finding_id": "MCPSTRIKE-001",
  "severity": "critical",
  "session_id": "a1b2c3d4",
  "type": "server_vulnerability",
  "module": "tool-path-traversal",
  "transport": "stdio",
  "protocol_version": "2025-03-26",
  "method": "tools/call",
  "payload": "path=/etc/passwd",
  "matchers_hit": ["jsonrpc_success", "regex:root:x:0:0"],
  "raw_request": { "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                   "params": { "name": "read_file", "arguments": { "path": "/etc/passwd" } } },
  "raw_response": { "jsonrpc": "2.0", "id": 4,
                    "result": { "content": [{ "type": "text", "text": "root:x:0:0:..." }] } }
}
```

---

## 🛡 Safety Policy Engine

**Read-Only by Default.** Only `resources/list`, `resources/read`, and `tools/list` are probed without explicit opt-in. Tools are enumerated but never invoked unless `--allow-mutating` is passed.

**Unknown = Unsafe.** Any tool whose behavior cannot be confidently classified as read-only is blocked unless `--allow-mutating` is passed.

**`isError` aware.** Tool-level errors (`result.isError: true`) are not treated as security findings — only successful responses that match the probe criteria count.

**STDIO Sandbox.** When spawning a local `stdio` server subprocess, `mcp-striker` isolates it with a temporary `HOME`, a controlled working directory, and scrubbed inherited environment variables.

---

## 🗂 Finding Severity

| Severity | Typical examples |
|---|---|
| `critical` | Arbitrary file read, command injection, RCE |
| `high` | SSRF, arbitrary file write, path prefix bypass |
| `medium` | Transport security issues (Origin, session reuse) |
| `low` | Information disclosure, weak schema typing |
| `info` | Capability exposure, design risk |

---

## 🚀 Roadmap

| Version | Status | What |
|---|---|---|
| v0.1 | ✅ | STDIO transport + path traversal probes + evidence artifacts |
| v0.2 | ✅ | Streamable HTTP + transport security probes (Origin, session, version) |
| v0.3 | ✅ | Auth-Differential Engine (IDOR, Tenant Breakout) |
| v0.4 | ✅ | YAML Flow-Based Attack DSL |
| v0.5 | ✅ | Tool Call Probes (`tools/call` attack surface) |
| v0.5.5 | ✅ | Scaffold Generator (`mcp-striker scaffold`) |
| v0.6 | ✅ | Report Engine (`mcp-striker report` → HTML + Markdown) |
| v0.7 | ✅ | Legacy HTTP+SSE transport (protocol 2024-11-05) |
| v0.8 | ✅ | False-positive prevention (matcher validation + scaffold sample responses + dry-run) |
| v1.0 | ✅ | Full engagement workflow: enum → scaffold → strike → report |
| Post-v1.0 | 🔮 | Replay Engine + module library for popular servers |
