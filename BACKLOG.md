# MCP-STRIKER: Project Backlog & TODOs
**Status:** Active | **Last Updated:** 2026-05-07

This backlog tracks the implementation phases for `mcp-striker`. It captures the architectural decisions and features that were intentionally deferred from the MVP (Milestone 1) to maintain the "Walking Skeleton" approach.

---

## 🏃 Milestone 1: The Walking Skeleton (MVP) ✅ DONE
**Goal:** End-to-end execution of a single path traversal probe over STDIO.

- [x] **Setup & Boundary:** Initialize `pyproject.toml`, `ruff`, `mypy`. Implement `mcp_striker/types.py` (`JsonValue`, `JsonObject`, `parse_json_value`).
- [x] **Models:** Implement Pydantic v2 schemas for `JsonRpcRequest`, `JsonRpcResponse`, `SafetyDecision`, `TransportExchange`.
- [x] **Transport:** Implement `StdioTransport` (subprocess execution, stdin/stdout piping, `stderr` capture, environment variable scrubbing).
- [x] **Protocol:** Implement `ProtocolClient` (handshake: `initialize` -> `notifications/initialized`).
- [x] **Enum:** Implement `CapabilityRegistry` to store the results of `resources/list`.
- [x] **Safety:** Implement `SafetyPolicyEngine` (hardcoded to only allow `resources/*` methods for MVP).
- [x] **Engine:** Implement `StrikeEngine` using a hardcoded Python list of path traversal payloads against discovered URIs. Probe design follows **Option A**: each `PathTraversalProbe` object in `mcp_striker/modules/resource_path_traversal.py` carries its own `Matcher` list. `StrikeEngine` is "dumb" — it fires each probe and calls `probe.matches(exchange)`.
- [x] **Evidence:** Implement `SessionRecorder` and `EvidenceGenerator` (with automatic redaction of `*_TOKEN`, `Authorization`, `cookie`, `*_SECRET`).
- [x] **CLI:** Wire `typer` commands (`enum` and `strike`). Post-MVP commands (`auth-diff`, `replay`, `validate-modules`) wired to placeholders that print `Not available in MVP` and exit cleanly.
- [x] **Testing:** Create three Python fixture servers (`stdio_path_traversal.py`, `stdio_malformed.py`, `stdio_clean.py`) and write full CI integration test + 42 unit tests. **45/45 tests pass.**

---

## 🌐 Milestone 2: Streamable HTTP & Transport Probes ✅ DONE
**Goal:** Support modern MCP HTTP transports and validate transport-layer security.

- [x] **Implementation:** Create `StreamableHttpTransport` using `httpx` and `httpx-sse`. Handles both `application/json` and `text/event-stream` (SSE) responses.
- [x] **Session Handling:** `StreamableHttpTransport` automatically parses `MCP-Session-Id` from the `initialize` response and injects it into all subsequent requests.
- [x] **Protocol Versioning:** `MCP-Protocol-Version` header sent on every request; version validated in JSON body params by the probe engine.
- [x] **Transport Probes:** `TransportProbeEngine` + `mcp_striker/modules/transport_probes.py` implement three probes (Option A — self-contained matchers):
  - `origin-missing-check` — hostile `Origin` header on `initialize`.
  - `protocol-version-mismatch` — invalid `protocolVersion` in JSON body.
  - `session-reuse` — fabricated `MCP-Session-Id` on `resources/list` (non-initialize).
- [x] **McpTransport ABC:** Formalised in `transport/base.py`; both `StdioTransport` and `StreamableHttpTransport` implement it. `ProtocolClient` and `StrikeEngine` are now transport-agnostic.
- [x] **CLI:** `mcp-striker http-probe --url <URL>` command added. `enum` and `strike` accept `--transport http --url <URL>`.
- [x] **Testing:** Python fixture servers (`http_vulnerable.py`, `http_clean.py`) + TypeScript fixture server (`ts_server/http_vulnerable.ts`). **64/64 tests pass (53 unit + 11 integration).**

---

## 🎭 Milestone 3: Auth-Differential Engine ✅ DONE
**Goal:** Detect Broken Access Control (IDOR) and Tenant Breakout.

- [x] **IdentityManager** (`mcp_striker/identity.py`): Loads YAML identity profiles (Bearer tokens, custom headers, env vars). Exposes `sensitive_keys()` for dynamic redaction of identity credentials in finding artifacts.
- [x] **OwnershipRegistry** (`mcp_striker/ownership.py`): Loads YAML ownership fixtures (who owns a resource, who must be denied). Enumerates (resource, owner, attacker) test pairs.
- [x] **AuthDiffEngine** (`engine/auth_diff.py`): Separate engine (not a StrikeEngine modification). Opens a fresh transport per identity per resource, executes two sequential passes (owner baseline → attacker attempt), delegates to `DiffMatcher`.
- [x] **DiffMatcher**: Verdict logic refined from plan — `is_success=True` for BOTH always yields `IDOR_CONFIRMED` regardless of content similarity. `similarity_score` is an informational severity flag only (`data_leaked: True` when ≥ 0.8).
- [x] **Dynamic redaction**: `EvidenceGenerator.promote_diff()` receives `extra_sensitive_keys` from `IdentityManager.sensitive_keys()`. Credentials from identity YAML are redacted from BOTH exchanges before writing to disk.
- [x] **StdioTransport `extra_env`**: New parameter for identity credential injection into subprocess environment after scrubbing.
- [x] **CLI**: `mcp-striker auth-diff` command implemented (was placeholder). Supports `--transport stdio|http`, `--identities`, `--ownership`.
- [x] **Testing**: STDIO and HTTP IDOR fixture servers + clean server false-positive guard. **90/90 tests pass (74 unit + 16 integration).**

---

## 📜 Milestone 4: Flow-Based Attack DSL (YAML) ✅ DONE
**Goal:** Move away from hardcoded Python payloads to declarative, stateful YAML scenarios.

- [x] **YAMLFlowParser** (`dsl/parser.py`): Pydantic v2 schema validation at load time. Compiles `MatcherSpec` → runtime `Matcher` dataclasses. Rejects invalid modules with explicit errors before any probe is sent.
- [x] **FlowEngine** (`engine/flow.py`): Separate engine (StrikeEngine untouched). Sequential steps (setup → mutate → cleanup). Mutate requests run concurrently via `asyncio.Semaphore` passed at construction.
- [x] **FlowContext** (`dsl/context.py`): Mutable variable store. Resolves `${var}` references; expands list variables into cartesian products. `${payload}` is a first-class system variable populated from `step.payloads` — injection point is explicit in the YAML params, not inferred.
- [x] **JSONPath extraction**: Uses `jsonpath-ng` on `model_dump(mode='json')` output (no JSON round-trip, Pydantic v2 native).
- [x] **ModuleSelector** (`dsl/selector.py`): Matches modules against `CapabilityRegistry`. Checks `server_capabilities` (from `initialize` response) and `resource_templates` regex patterns.
- [x] **CapabilityRegistry + ProtocolClient**: Added `server_capabilities: list[str]` field populated from the `initialize` response. Enables precise capability-based module selection.
- [x] **CLI**: `strike --module <path.yaml>` and `strike --modules-dir <dir>` flags added. Without flags: M1 hardcoded behaviour unchanged.
- [x] **3 built-in YAML modules** in `modules/`: `resource_path_traversal.yaml`, `resource_enumeration.yaml`, `ssrf_via_resource.yaml`.
- [x] **Testing**: 33 new tests (26 unit + 7 integration). **126/126 tests pass.**

---

## 🔧 Milestone 5: Tool Call Probes ✅ DONE
**Goal:** Extend mcp-striker to attack the `tools/call` surface, which is the dominant pattern in modern MCP servers (2025-2026 ecosystem).

**Rationale for reprioritisation:** Testing against real-world servers revealed that the majority of production MCP servers expose filesystem and network access via `tools/call`, not `resources/read`. The existing resource-based probes cover a real but shrinking attack surface. Tool call probes make mcp-striker effective against the current ecosystem.

- [x] **McpTool model + CapabilityRegistry.tools**: Extend `CapabilityRegistry` with `tools: list[McpTool]`. `McpTool` stores name, description, and input JSON Schema.
- [x] **ProtocolClient**: Enumerate `tools/list` and populate `registry.tools`. Store schema for each tool's parameters.
- [x] **ToolClassifier**: Heuristic classifier that labels each tool as `read_only`, `mutating`, or `unknown` based on name and description patterns. Used by `SafetyPolicyEngine` to allow read-only tools without `--allow-mutating`.
- [x] **SafetyPolicyEngine**: Extend to permit `tools/call` for tools classified as `read_only`. Block `mutating` and `unknown` unless `--allow-mutating` is passed.
- [x] **ModuleSelector**: Extend `RequiresSpec` with `tools:` field (list of name regex patterns). A module is selected only if the server exposes at least one matching tool.
- [x] **YAML tool modules** in `modules/`: `tool_path_traversal.yaml`, `tool_ssrf.yaml`, `tool_command_injection.yaml`.
- [x] **Fixture servers**: `stdio_tool_traversal.py` (no path sanitisation in `read_file` tool), `http_tool_traversal.py` (same via HTTP), `stdio_tool_clean.py` (sanitised, false-positive guard).
- [x] **CLI**: `enum` output extended to show discovered tools. No new commands needed — `strike --module` already handles arbitrary YAML flows.
- [x] **Testing**: 47 unit tests + 6 integration tests. **179/179 tests pass.**

---

## 🗂 Milestone 5.5: Scaffold Generator ✅ DONE
**Goal:** Reduce the time to write a new YAML module from scratch for an unknown server.

**Rationale:** mcp-striker is a specialized PT tool — not a generic scanner. Every serious engagement against an unknown server requires a custom YAML module. The scaffold generator eliminates the mechanical boilerplate while keeping the human in the loop for payload selection.

- [x] **`ScaffoldGenerator`** (`mcp_striker/scaffold.py`): reads `CapabilityRegistry`, generates skeletons for tools (injectable string parameters) and resource templates (URI placeholders). Files written into `tool/` and `template/` subdirectories.
- [x] **`mcp-striker scaffold`** CLI command: `--from-enum <snapshot.json>` + `--output-dir <dir>` (default: `modules/servers/<server-name>/`). Generates one file per injectable tool and one per resource template.
- [x] **Payloads as comments**: generated files are valid YAML but payloads are commented out — operator uncomments what applies, adds matchers, then runs `strike --module`.
- [x] **Semantic classification** (tools): `path|file|filepath` → path-traversal; `url|uri|endpoint` → SSRF; `function|code|script` → code-eval; `command|cmd|args` → injection.
- [x] **Semantic classification** (templates): `{id}|{user_id}|{account}` → IDOR; `{path}|{file}` → path-traversal; `{url}|{endpoint}` → SSRF; `file://` scheme fallback → path-traversal; opaque schemes → IDOR.
- [x] **Testing**: 44 unit tests. **223/223 tests pass.**

## 📄 Milestone 6: Report Engine ✅ DONE
**Goal:** Transform finding artifacts into a professional PT deliverable without leaving the CLI.

**Rationale:** mcp-striker produces structured JSON evidence artifacts. A pentest engagement ends with a report. Today the operator must manually assemble findings into a document. `mcp-striker report` closes that gap — one command, one HTML file ready to share.

- [x] **Severity field**: Add `severity: critical|high|medium|low|info` to `FlowModule` YAML schema (optional, default `medium`). Propagated through `EvidenceGenerator` into finding artifacts.
- [x] **ReportGenerator** (`mcp_striker/report.py`): loads all finding artifacts from a findings directory, loads the enum snapshot for server context, produces a self-contained HTML report.
- [x] **HTML report**: embedded CSS, no external dependencies, print-to-PDF friendly. Sections: executive summary → severity chart → findings (with proof) → tested surface → appendix.
- [x] **Markdown report**: alternative format for GitLab/GitHub issues and pandoc pipelines.
- [x] **CLI command**: `mcp-striker report --base-dir <dir> [--output report.html] [--format html|markdown] [--title "..."]`
- [x] **Testing**: 25 unit tests (severity schema, load, metrics, HTML, Markdown). **245/245 tests pass.**

---

## 🔬 Milestone 7: Scaffold Sample Responses + Strike Dry-Run ✅ DONE
**Goal:** Give the operator concrete evidence to calibrate regex matchers before committing to a strike run.

- [x] **`scaffold --allow-mutating`**: connects to the server and sends a probe call with empty values for each scaffolded tool; embeds the response as a `# SAMPLE RESPONSE` comment block above `matchers:`. If the tool is classified as mutating and `--allow-mutating` is not set, the block reads `not collected — tool classified as mutating`. Connection failures are silent — scaffold proceeds without samples.
- [x] **`strike --dry-run`**: runs all probes normally but does not call `EvidenceGenerator.promote()`. For each probe, prints compact request + response JSON to stdout with per-matcher `WOULD MATCH / would NOT match` verdicts. Session transcript is still written. No finding artifacts on disk.
- [x] **`scaffold` new flags**: `--allow-mutating`, `--timeout`, `--header`, `--extra-env`, `--no-verify-ssl`.
- [x] **Testing**: 5 unit tests (scaffold sample block) + 1 unit test (FlowEngine dry_run param) + 3 integration tests (dry-run no findings, no artifacts, session recorded). **264/264 tests pass.**

---

## 🔌 Legacy HTTP+SSE Transport ✅ DONE
**Goal:** Support servers using the deprecated 2024-11-05 HTTP+SSE transport.

- [x] `SseTransport` (`transport/sse.py`): persistent GET stream + correlated POST per request via two separate `httpx.AsyncClient` instances (SSE client + POST client, separate to avoid connection pool exhaustion).
- [x] `--transport sse` on `enum`, `strike`, `http-probe`.
- [x] `registry.target_transport` field: saved during `enum`, auto-used by `strike` for reconnection.
- [x] `--transport` override on `strike`: corrects a registry saved with wrong transport without re-running `enum`.
- [x] `--path` flag: overrides the default endpoint path (`/mcp` for HTTP, `/sse` for SSE).
- [x] `--no-verify-ssl` flag: disables TLS certificate verification on all HTTP/SSE commands.
- [x] Fixture server + 4 integration tests. **264/264 tests pass.**

---

## 🔮 Post-v1.0 (Future Ideas)

- **Replay Engine:** `mcp-striker replay <FINDING_ID>` — exact and normalised replay modes for client demonstrations.
- **Module library:** Curated YAML modules for popular MCP servers (chrome-devtools-mcp, filesystem servers, git servers, database connectors).
- **Tool Poisoning Vectors:** Test if malicious payloads inside a resource can manipulate an LLM's subsequent tool calls.
- **External Reporters:** Send finding artifacts directly to Jira, DefectDojo, or Slack.
