# MCP-STRIKER: Architecture Design Document
**Status:** Active — all milestones complete | **Last Updated:** 2026-05-13

---

## 1. DESIGN PRINCIPLE

`mcp-striker` is divided into strictly decoupled tiers. The dependency rule is **top-down only**: the Protocol tier has no knowledge of vulnerabilities; the Transport tier has no knowledge of attack modules.

```
CLI (cli.py)
  └── Orchestration: StrikeEngine | FlowEngine | AuthDiffEngine | TransportProbeEngine
        └── Safety: SafetyPolicyEngine
              └── Protocol: ProtocolClient → CapabilityRegistry
                    └── Transport: StdioTransport | StreamableHttpTransport | SseTransport
```

---

## 2. COMPONENT DIAGRAM

```text
┌─────────────────────────────────────────────────────────────────────┐
│                      CLI Layer  (Typer + Rich)                      │
│   enum | strike | scaffold | http-probe | auth-diff | report        │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                       ORCHESTRATION TIER                            │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────┐  │
│  │ StrikeEngine │  │  FlowEngine  │  │AuthDiff    │  │Transport │  │
│  │ (M1 legacy)  │  │ (YAML DSL)   │  │Engine      │  │Probe     │  │
│  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  │Engine    │  │
│         │                 │                │         └────┬─────┘  │
│  ┌──────▼─────────────────▼────────────────▼──────────────▼──────┐ │
│  │               SessionRecorder  │  EvidenceGenerator           │ │
│  └───────────────────────────────────────────────────────────────┘ │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                      SAFETY & POLICY TIER                           │
│              SafetyPolicyEngine + ToolClassifier                    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                    PROTOCOL & TRANSPORT TIER                        │
│                                                                     │
│  ┌──────────────────┐     ┌──────────────────────────────────────┐  │
│  │ CapabilityRegistry│◄───│          ProtocolClient              │  │
│  │ (immutable snap) │     │  (handshake, init, enumeration)      │  │
│  └──────────────────┘     └────────────────┬─────────────────────┘  │
│                                            │                        │
│              ┌─────────────────────────────┼──────────────────┐    │
│              │                             │                  │    │
│   ┌──────────▼──────┐  ┌──────────────────▼──┐  ┌────────────▼──┐ │
│   │ StdioTransport  │  │StreamableHttpTransport│  │ SseTransport  │ │
│   │ (subprocess)    │  │ (HTTP 2025-03-26)     │  │ (HTTP+SSE     │ │
│   └─────────────────┘  └──────────────────────┘  │  2024-11-05)  │ │
│                                                   └───────────────┘ │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                       ┌───────▼───────┐
                       │   MCP SERVER  │
                       └───────────────┘
```

---

## 3. COMPONENT RESPONSIBILITIES

### 3.1 Transport Tier

**`McpTransport` (ABC, `transport/base.py`)**

```python
async def connect(self) -> None: ...
async def send(self, request: JsonRpcRequest, context: TransportContext) -> TransportExchange: ...
async def close(self) -> None: ...
```

**`StdioTransport`** — Spawns the server subprocess, scrubs inherited environment variables, sets a temporary `HOME` and working directory, pipes stdin/stdout as the JSON-RPC channel. Accepts `extra_env` for identity credential injection (AuthDiff).

**`StreamableHttpTransport`** — Streamable HTTP (protocol 2025-03-26). POSTs every JSON-RPC request. Parses `MCP-Session-Id` from `initialize` and injects it into all subsequent requests. Supports `--path`, `--no-verify-ssl`, `extra_headers`.

**`SseTransport`** — Legacy HTTP+SSE (protocol 2024-11-05). Opens a persistent GET SSE stream and POSTs requests to the endpoint URL. Uses **two separate** `httpx.AsyncClient` instances (`_sse_client` for the GET stream, `_post_client` for POST) to avoid connection pool exhaustion. Responses arrive via SSE `message` events correlated by `id` via `asyncio.Future`.

**`ProtocolClient`** — Owns the MCP session lifecycle: `initialize` → `notifications/initialized` → `resources/list` → `tools/list`. Verifies protocol version. Aborts with a clear error if the server is incompatible.

**`CapabilityRegistry`** — Immutable Pydantic snapshot produced by `ProtocolClient.enumerate_capabilities()`. Stores: server metadata, transport config (`target_cmd` / `target_url` / `target_transport`), `server_capabilities`, `tools: list[McpTool]`, `resources`, `resource_templates`. Serialised to JSON by `enum`, loaded by `strike` and `scaffold`.

---

### 3.2 Safety & Policy Tier

**`ToolClassifier` (`tool_classifier.py`)** — Heuristic classifier: `READ_ONLY` / `MUTATING` / `UNKNOWN` based on name prefix patterns and description keywords.

**`SafetyPolicyEngine` (`safety.py`)** — Intercepts every outgoing request before transport:
- `resources/list`, `resources/read`, `tools/list` → always allowed
- `tools/call` for `READ_ONLY` tools → allowed
- `tools/call` for `MUTATING` / `UNKNOWN` tools → blocked unless `--allow-mutating`
- All other methods → blocked

**`SafetyDecision`** — Attached to every `TransportExchange` whether allowed or blocked.

---

### 3.3 Orchestration Tier

**`StrikeEngine` (`engine/strike.py`)** — M1 legacy engine. Runs the hardcoded `PROBES` list from `resource_path_traversal.py` against every URI template in the registry. Probe objects are self-contained (Option A): each carries its own matcher list and `matches()` method.

**`FlowEngine` (`engine/flow.py`)** — YAML DSL engine. Executes `FlowModule` objects sequentially (setup → mutate → cleanup). Within a mutate step, all `(param_set × payload)` combinations run concurrently under a shared `asyncio.Semaphore`.

Key parameters:
- `dry_run: bool = False` — when True, probes execute normally but matchers are evaluated in read-only mode: no finding artifacts are written, each probe prints compact request + response + per-matcher verdict to stdout.

**`AuthDiffEngine` (`engine/auth_diff.py`)** — Two-pass IDOR detection. For each `(resource, owner, attacker)` triple: opens fresh transport per identity, runs baseline → attacker pass, delegates to `DiffMatcher`.

**`TransportProbeEngine` (`engine/transport_probe.py`)** — HTTP-only. Fires three probes independent of `CapabilityRegistry`: Origin check, protocol version mismatch, session ID reuse.

**`SessionRecorder`** — Persists every exchange to `.mcp-striker/<server>/sessions/<session-id>/`. Always records, even in dry-run mode.

**`EvidenceGenerator`** — Promotes matched exchanges to versioned `MCPSTRIKE-NNN.json` artifacts. Redacts sensitive **keys** (`Authorization`, `cookie`, `password`, `*_token`, `*_secret`, api keys, …) at write time — key-based only, so secrets in free text / the `payload` / raw transcripts are NOT redacted. Artifacts are raw evidence, written owner-only (0700/0600); treat as confidential. Not called in dry-run mode.

---

### 3.4 DSL Package (`mcp_striker/dsl/`)

| Module | Responsibility |
|---|---|
| `schema.py` | Pydantic v2 root schema (`FlowModule`, `StepSpec`, `MatcherSpec`). Validation at parse time including the no-`jsonrpc_success`-only rule. |
| `context.py` | `FlowContext` — mutable variable store with `${var}` resolution and cartesian expansion. |
| `parser.py` | `YAMLFlowParser` — loads YAML, validates schema, compiles `MatcherSpec` → runtime `Matcher` dataclasses. |
| `selector.py` | `ModuleSelector` — filters modules against `CapabilityRegistry` (capabilities, resource templates, tool patterns). |

**System variables:** `${payload}`, `${matched_tool}`, `${matched_param}` — populated by `FlowEngine` before each module run.

**Matcher rule:** a `mutate` step whose only matcher is `jsonrpc_success` is rejected at parse time (`_validate_step()`). A content-evidence matcher (`regex` or `json_path`) is mandatory alongside `jsonrpc_success`.

---

### 3.5 Scaffold Generator (`mcp_striker/scaffold.py`)

`ScaffoldGenerator.generate_all()` accepts optional `sample_responses: dict[str, str] | None`:
- Key: tool name
- Value: compact JSON of the `result`/`error` from a probe with empty values, or `SAMPLE_BLOCKED` sentinel when the tool is mutating and `--allow-mutating` was not passed.

When present, each scaffold file includes a `# SAMPLE RESPONSE` comment block above `matchers:` showing the actual server response — helps the operator calibrate the regex pattern. All matchers (including `jsonrpc_success`) are commented out in scaffold output.

---

### 3.6 CLI Layer (`cli.py`)

Commands: `enum`, `strike`, `scaffold`, `http-probe`, `auth-diff`, `report`.

**`_build_transport()`** — central transport factory used by all commands.

Key flag propagation chains:
- `--transport` → `_build_transport()` → transport class constructor
- `--dry-run` → `_strike()` → `FlowEngine(dry_run=True)`
- `--allow-mutating` on `scaffold` → `_collect_sample_responses()` → `SafetyPolicyEngine`

`_collect_sample_responses()` — connects to the server and probes each injectable tool with empty values. Connection is only attempted when at least one tool needs probing. Wrapped entirely in `try/except` — scaffold is always generated even if the connection fails.

---

## 4. TYPE BOUNDARIES & UNTRUSTED INPUT

All untrusted bytes from target servers enter through a single boundary:

```python
def parse_json_value(raw: bytes) -> JsonValue:
    parsed: object = json.loads(raw)
    return _validate(parsed)  # raises TypeError on unexpected Python types
```

Pydantic model fields that hold arbitrary JSON use `Any` (recursive `JsonValue` causes `RecursionError` in Pydantic v2 schema construction). These models are data holders only — `parse_json_value()` remains the sole untrusted entry point.

---

## 5. KEY DATA FLOWS

### enum flow
```
CLI (enum) → _build_transport()
           → ProtocolClient.initialize()
           → ProtocolClient.enumerate_capabilities()
               → resources/list → McpResource, McpResourceTemplate
               → tools/list    → McpTool
           → CapabilityRegistry.save(snapshot)
           → CLI prints summary
```

### strike --module flow
```
CLI (strike) → CapabilityRegistry.load(snapshot)
             → _build_transport() + ProtocolClient.initialize()
             → YAMLFlowParser.load() + ModuleSelector.select_with_report()
             → FlowEngine.run_modules(selected)
               → for each module:
                   for each step (setup → mutate → cleanup):
                     SafetyPolicyEngine.evaluate_request() → SafetyDecision
                     if BLOCKED: SessionRecorder.record(blocked exchange)
                     if ALLOWED:
                       transport.send() → TransportExchange
                       SessionRecorder.record(exchange)
                       if dry_run:
                         print(request + response + matcher verdicts)
                       else if all matchers hit:
                         EvidenceGenerator.promote() → MCPSTRIKE-NNN.json
             → CLI prints findings summary (or "no findings" in dry-run)
```

### scaffold --allow-mutating flow
```
CLI (scaffold) → CapabilityRegistry.load(snapshot)
              → _collect_sample_responses()
                  → classify tools (READ_ONLY / MUTATING / UNKNOWN)
                  → if any needs probing: _build_transport() + initialize()
                  → for each tool: tools/call with empty argument values
                  → on error: return partial results silently
              → ScaffoldGenerator.generate_all(registry, sample_responses)
              → write one YAML file per injectable tool
```

---

## 6. OUTPUT DIRECTORY CONVENTION

```
.mcp-striker/
└── <server-slug>/
    ├── sessions/
    │   ├── <server-slug>.json          ← CapabilityRegistry snapshot (from enum)
    │   └── <session-id>/
    │       ├── 001.json                ← TransportExchange records
    │       └── ...
    └── findings/
        ├── MCPSTRIKE-001.json
        └── ...
```

All commands auto-derive the output directory from `server_name` after `initialize`. `--output-dir` overrides.

---

## 7. MILESTONE HISTORY

| Milestone | What was added |
|---|---|
| M1 | STDIO transport, hardcoded path traversal probes, evidence artifacts, CLI |
| M2 | StreamableHttpTransport, McpTransport ABC, TransportProbeEngine |
| M3 | AuthDiffEngine, IdentityManager, OwnershipRegistry, dynamic redaction |
| M4 | YAML DSL (FlowEngine, YAMLFlowParser, FlowContext, ModuleSelector) |
| M5 | Tool call probes, ToolClassifier, tool-aware SafetyPolicyEngine, ${matched_tool} |
| M5.5 | ScaffoldGenerator (`mcp-striker scaffold`) |
| M6 | ReportGenerator (`mcp-striker report` → HTML + Markdown) |
| SSE | SseTransport (legacy 2024-11-05), --transport sse, --path, --no-verify-ssl |
| M7 | jsonrpc_success-only validation rule, scaffold sample responses (--allow-mutating), strike --dry-run |
