"""STDIO transport for MCP servers spawned as local subprocesses.

Design notes
------------
* The server process is launched with a scrubbed environment (allowlist only)
  and a temporary HOME / working directory to limit blast radius.
* A background ``_stdout_reader`` task reads newline-delimited JSON-RPC
  messages and dispatches each response to the caller's ``asyncio.Future``
  by matching on the ``id`` field.  Notifications (no ``id``) are silently
  discarded.
* A background ``_stderr_reader`` task buffers stderr lines; callers drain
  the buffer after receiving a response to get a per-exchange transcript.
* **Fail fast**: transport-layer problems raise typed exceptions immediately.
  The Strike Engine is responsible for catching them gracefully.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile

from mcp_striker.models import (
    JsonRpcRequest,
    JsonRpcResponse,
    TransportContext,
    TransportExchange,
)
from mcp_striker.transport.base import McpTransport
from mcp_striker.types import parse_json_value

# ---------------------------------------------------------------------------
# Exceptions (fail-fast contract)
# ---------------------------------------------------------------------------


class TransportConnectionError(Exception):
    """Raised when the subprocess cannot be spawned or the pipe is broken."""


class ProtocolParsingError(Exception):
    """Raised when a server response cannot be parsed as a JsonRpcResponse."""


# ---------------------------------------------------------------------------
# Environment sanitisation
# ---------------------------------------------------------------------------

_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {"PATH", "HOME", "USER", "LANG", "TMPDIR", "TEMP", "TMP", "PYTHONPATH"}
)


def _scrub_environment() -> dict[str, str]:
    """Return a copy of ``os.environ`` containing only allowlisted keys."""
    return {k: v for k, v in os.environ.items() if k in _ENV_ALLOWLIST}


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class StdioTransport(McpTransport):
    """Manages a single MCP server subprocess and its stdin/stdout pipes."""

    def __init__(
        self,
        cmd: list[str],
        timeout: float = 30.0,
        extra_env: dict[str, str] | None = None,
    ) -> None:
        """
        Args:
            cmd:       Command list used to spawn the server subprocess.
            timeout:   Per-request timeout in seconds.
            extra_env: Additional environment variables injected into the
                       subprocess after the allowlist scrub.  Used by
                       ``AuthDiffEngine`` to pass identity credentials
                       (e.g. ``MCP_AUTH_TOKEN``) to STDIO servers.

                       NOTE: this engine opens a new subprocess per
                       (identity, resource) pair.  Servers with stateful
                       initialisation (db migrations, lock files, shared
                       state) may behave unexpectedly under this access
                       pattern.  Post-v1.0 optimisation: pool connections
                       per identity.
        """
        self._cmd = cmd
        self._timeout = timeout
        self._extra_env: dict[str, str] = extra_env or {}
        self._process: asyncio.subprocess.Process | None = None
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        # Map request-id → Future awaiting the matching response.
        self._pending: dict[int | str, asyncio.Future[JsonRpcResponse]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._stderr_buffer: list[str] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Spawn the server subprocess and start background reader tasks."""
        self._tmpdir = tempfile.TemporaryDirectory()
        env = _scrub_environment()
        env["HOME"] = self._tmpdir.name
        # Inject identity credentials after scrubbing.
        env.update(self._extra_env)

        try:
            self._process = await asyncio.create_subprocess_exec(
                *self._cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=self._tmpdir.name,
            )
        except OSError as exc:
            raise TransportConnectionError(
                f"Failed to spawn server process {self._cmd!r}: {exc}"
            ) from exc

        self._reader_task = asyncio.create_task(
            self._stdout_reader(), name="stdio-stdout-reader"
        )
        self._stderr_task = asyncio.create_task(
            self._stderr_reader(), name="stdio-stderr-reader"
        )

    async def close(self) -> None:
        """Terminate the subprocess and release all resources."""
        # Fail any still-pending request futures so their awaiters (send())
        # don't hang, and the exception is retrieved rather than leaking.
        closed = TransportConnectionError("transport closed")
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(closed)
        self._pending.clear()

        # Cancel the background readers AND await them, so cancellation is
        # confirmed and the CancelledError is retrieved (no "Task was destroyed
        # but it is pending" / "exception never retrieved" warnings).
        tasks = [t for t in (self._reader_task, self._stderr_task) if t is not None]
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._reader_task = None
        self._stderr_task = None

        if self._process is not None:
            if self._process.stdin is not None:
                self._process.stdin.close()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()

        if self._tmpdir is not None:
            self._tmpdir.cleanup()

    # ------------------------------------------------------------------
    # Background tasks
    # ------------------------------------------------------------------

    async def _stdout_reader(self) -> None:
        """Read newline-delimited JSON from stdout and dispatch to waiters."""
        assert self._process is not None and self._process.stdout is not None
        while True:
            try:
                line = await self._process.stdout.readline()
            except Exception:
                break
            if not line:
                # EOF — server closed stdout; unblock all pending futures.
                exc = TransportConnectionError("Server closed stdout (EOF)")
                for fut in list(self._pending.values()):
                    if not fut.done():
                        fut.set_exception(exc)
                self._pending.clear()
                break

            stripped = line.strip()
            if not stripped:
                continue

            try:
                parsed = parse_json_value(stripped)
                response = JsonRpcResponse.model_validate(parsed)
            except Exception:
                # Malformed line — skip; callers will time out.
                continue

            msg_id = response.id
            if msg_id is not None:
                future = self._pending.pop(msg_id, None)
                if future is not None and not future.done():
                    future.set_result(response)

    async def _stderr_reader(self) -> None:
        """Buffer stderr lines for attachment to TransportExchange objects."""
        assert self._process is not None and self._process.stderr is not None
        while True:
            try:
                line = await self._process.stderr.readline()
            except Exception:
                break
            if not line:
                break
            self._stderr_buffer.append(line.decode(errors="replace"))

    def _drain_stderr(self) -> str:
        """Return all buffered stderr lines and clear the buffer."""
        captured = "".join(self._stderr_buffer)
        self._stderr_buffer.clear()
        return captured

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    async def send(
        self,
        request: JsonRpcRequest,
        context: TransportContext,
    ) -> TransportExchange:
        """Write *request* to stdin and return the server's response.

        Notifications (``id`` is ``None``) are fire-and-forget; the method
        returns immediately with an empty exchange.
        """
        if self._process is None or self._process.stdin is None:
            raise TransportConnectionError("Transport is not connected")

        raw = json.dumps(request.model_dump(exclude_none=True)).encode() + b"\n"

        # Notifications: no response expected.
        if request.id is None:
            self._process.stdin.write(raw)
            await self._process.stdin.drain()
            return TransportExchange(request=request)

        # Register a Future *before* writing to avoid a race where the server
        # responds before we have a chance to register.
        loop = asyncio.get_running_loop()
        future: asyncio.Future[JsonRpcResponse] = loop.create_future()
        self._pending[request.id] = future

        self._process.stdin.write(raw)
        await self._process.stdin.drain()

        # ``asyncio.wait`` does not cancel the future on timeout, which is
        # what we want: late responses are simply discarded by the reader.
        done, _ = await asyncio.wait({future}, timeout=self._timeout)

        if not done:
            self._pending.pop(request.id, None)
            return TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"timeout after {self._timeout}s waiting for response",
                stderr_transcript=self._drain_stderr(),
            )

        try:
            response = future.result()
        except TransportConnectionError as exc:
            return TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=str(exc),
                stderr_transcript=self._drain_stderr(),
            )

        return TransportExchange(
            request=request,
            response=response,
            stderr_transcript=self._drain_stderr(),
        )
