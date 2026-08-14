# MCP-STRIKER: Engineering Guidelines & Conventions
**Status:** Active — all milestones complete | **Last Updated:** 2026-08-14

> The per-milestone `N/N tests pass` figures below are historical snapshots
> recorded at each milestone's completion. The current suite totals **286
> tests** (`pytest tests/`).

---

## 1. TECHNOLOGY STACK

| Concern | Choice |
|---|---|
| Runtime | Python 3.12+ (strict type hints, `asyncio`) |
| Package manager | `hatchling` (build backend), `pip install -e .` (local dev) |
| Linter / Formatter | `Ruff` (`py312`, `ASYNC` + `RUF` rule sets) |
| Type checker | `mypy --strict` |
| Validation | `Pydantic v2` (JSON-RPC parsing, Evidence schemas, DSL schema) |
| CLI | `typer` + `rich` |
| Network | `httpx` + `httpx-sse` |
| Testing | `pytest` + `pytest-asyncio` + `pytest-cov` + `hypothesis` |

> **Local dev requirement:** Always run `mcp-striker` inside a Python virtualenv (`venv`). Do not install into the system Python.
>
> ```bash
> python -m venv venv
> source venv/bin/activate
> pip install -e .
> ```

---

## 2. DEVELOPMENT METHODOLOGY: WALKING SKELETON

We follow a strict Walking Skeleton to prevent scope creep. Each milestone must be fully working end-to-end before the next begins.

### Milestone 1 — MVP ✅ DONE
**One full vertical slice, nothing else.**

```
StdioTransport → ProtocolClient → CapabilityRegistry
→ SafetyPolicyEngine → StrikeEngine (hardcoded payloads)
→ SessionRecorder → EvidenceGenerator → CLI (enum + strike)
```

Done means: `mcp-striker enum` + `mcp-striker strike` work against the fixture STDIO server, produce a valid `MCPSTRIKE-001.json`, and CI passes. **45/45 tests pass (42 unit + 3 integration).**

### Milestone 2 ✅ DONE
`StreamableHttpTransport` + `McpTransport` ABC + `TransportProbeEngine` (Origin, version, session probes). **64/64 tests pass.**

### Milestone 3 ✅ DONE
`AuthDiffEngine` + `DiffMatcher` + `IdentityManager` + `OwnershipRegistry`. Dynamic credential redaction via `sensitive_keys()`. **90/90 tests pass.**

### Milestone 4 ✅ DONE
`FlowEngine` + `YAMLFlowParser` + `FlowContext` + `ModuleSelector`. `${payload}` as first-class system variable. Semaphore-based concurrency inside mutate steps. **126/126 tests pass.**

### Milestone 5 ✅ DONE
`ToolClassifier` + `McpTool` in `CapabilityRegistry` + tool-aware `SafetyPolicyEngine` + `ModuleSelector` tool patterns + `${matched_tool}` system variable + 3 YAML modules + STDIO/HTTP fixture servers. **179/179 tests pass.**

### Milestone 5.5 ✅ DONE
Scaffold Generator (`mcp-striker scaffold`). **223/223 tests pass.**

### Auth flags (hotfix) ✅ DONE
`--header KEY=VALUE` (HTTP) and `--extra-env KEY=VALUE` (STDIO) on `enum`, `strike`, `http-probe`. Both transports already supported internally; CLI exposure added.

### Milestone 6 ✅ DONE
`ReportGenerator` (`mcp-striker report` → HTML + Markdown). Severity field on `FlowModule`. **251/251 tests pass.**

### Legacy SSE Transport ✅ DONE
`SseTransport` (protocol 2024-11-05). `--transport sse`, `--path`, `--no-verify-ssl`. **256/256 tests pass.**

### Milestone 7 ✅ DONE
False-positive prevention: `jsonrpc_success`-only mutate steps rejected at parse time. Scaffold sample responses (`--allow-mutating`). `strike --dry-run`. **264/264 tests pass.**

---

## 3. CODING CONVENTIONS

### 3.1 The Untrusted Boundary (Type Safety)

`mcp-striker` is a fuzzer — it will receive malformed data from target servers. The validation boundary is `parse_json_value(raw: bytes) -> JsonValue` in `mcp_striker/types.py`. No unvalidated bytes from a server enter any other module.

```python
# Defined once in mcp_striker/types.py
JsonScalar = str | int | float | bool | None
JsonValue  = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]
```

**Pydantic v2 constraint:** `JsonValue` cannot be used directly as a Pydantic field type because its recursive definition triggers a `RecursionError` during schema construction. Pydantic model fields that hold arbitrary JSON therefore use `Any`. These models are **data holders only** — they never receive unvalidated data from outside the process. The `parse_json_value()` boundary is still the sole entry point for all untrusted input.

### 3.2 Probe Design — Option A (self-contained probes)

Matcher logic lives **inside** the probe object, not in the `StrikeEngine`. This keeps the engine dumb and makes each probe independently testable.

```python
@dataclass(frozen=True)
class PathTraversalProbe:
    payload: str
    matchers: list[Matcher]

    def matches(self, exchange: TransportExchange) -> bool:
        return all(m.fn(exchange) for m in self.matchers)

    def matchers_hit(self, exchange: TransportExchange) -> list[str]:
        return [m.name for m in self.matchers if m.fn(exchange)]
```

When adding a new attack module, define its probe class and `PROBES` list in a new file under `mcp_striker/modules/`. The `StrikeEngine` contract never changes.

### 3.3 Error Handling & Resilience

Two distinct behaviors depending on tier:

**Transport layer — Fail Fast.** Raise custom typed exceptions immediately.

```python
class TransportConnectionError(Exception): ...
class ProtocolParsingError(Exception): ...
```

**Strike Engine — Graceful Degradation.** Catch payload exceptions, log as `probe_failed`, and continue. A scanning session must never crash because a single probe returned garbage.

A crash is only a finding if it is reproducibly linked to a specific payload (potential DoS or type confusion). Otherwise it is a `transport_error`, `protocol_error`, or `probe_failed` in the session log.

### 3.4 Concurrency Control

All probe execution paths that perform network or subprocess I/O must be governed by `asyncio.Semaphore`. Default concurrency limit: 5. Configurable via CLI flag `--concurrency`.

```python
semaphore = asyncio.Semaphore(concurrency)
async with semaphore:
    exchange = await transport.send(request, context)
```

### 3.5 Secret Handling & Self-Protection

- **Redaction:** `EvidenceGenerator` redacts values for known sensitive **keys** (`Authorization`, `cookie`, `password`, `*_token`, `*_secret`, api keys, …) plus identity-YAML credentials, at write time. This is **key-based only**: it does NOT redact secrets embedded in free text (e.g. a file/config body returned by a probe), the `payload` field, or the raw session transcripts. Finding and session artifacts therefore contain raw, potentially secret-bearing evidence (the proof of the finding); they are written owner-only (0700/0600) and must be treated as confidential. Do not claim artifacts are secret-free.
- **No `eval()`:** Never use `eval()` or string-interpolated shell commands (`os.system`, `subprocess.run(shell=True)`).
- **Artifact path sanitization:** Sanitize all output paths before writing evidence files. No user-controlled string may compose a file path without passing through `pathlib.Path` resolution and a root-directory check.
- **`.gitignore` enforcement:** The `mcp-striker enum` command appends `.mcp-striker/` to the project's `.gitignore` on first run (if a `.git` directory is detected) to prevent accidental commits of session transcripts, tokens, and evidence.

---

## 4. TESTING STRATEGY

### 4.1 Unit Tests

Use `pytest`. Cover all Pydantic models, the `SafetyPolicyEngine`, probe matchers, and `EvidenceGenerator` with standard unit tests.

Use `hypothesis` to fuzz `parse_json_value()` with malformed byte sequences. The goal is to confirm the validation boundary never raises an unhandled exception — only `json.JSONDecodeError`, `ValueError`, or `TypeError`.

### 4.2 Integration Tests (Fixture Servers)

Deliberately vulnerable MCP servers live in `tests/fixtures/servers/`. CI runs `mcp-striker` against them on every push.

**Milestone 1 testing matrix (3 servers):**

| Server | Language | Purpose |
|---|---|---|
| `stdio_path_traversal.py` | Python | Vulnerable — confirms path traversal is detected |
| `stdio_malformed.py` | Python | Returns broken JSON — confirms engine never crashes |
| `stdio_clean.py` | Python | Sanitised server — confirms zero false positives |

TypeScript servers and Streamable HTTP fixtures are added at Milestone 2.

**TypeScript fixture (`tests/fixtures/servers/ts_server/`):** `node_modules/` is
gitignored, not vendored. Before running the TS integration tests, install
dependencies and compile once:

```bash
cd tests/fixtures/servers/ts_server
npm install
npx tsc
```

Without a compiled `dist/`, `ts_vulnerable_server`-dependent tests are skipped
(not failed) — see the `pytest.skip("TypeScript fixture not compiled — run tsc
in ts_server/")` guard in `tests/integration/test_http_strike.py`.

### 4.3 Evidence Schema Versioning

Every finding artifact must include `"schema_version": "mcp-striker.finding/v1"`. This field is validated on read by the `ReplayEngine` (post-MVP) and any external reporter. Breaking schema changes require a version bump.
