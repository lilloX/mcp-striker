"""Regression test for StdioTransport.close() (review debt item).

close() must fail any still-pending request futures (so send() awaiters do not
hang and the exception is retrieved) and clear them.
"""

from __future__ import annotations

import asyncio

from mcp_striker.transport.stdio import StdioTransport, TransportConnectionError


async def test_close_fails_and_clears_pending_futures() -> None:
    transport = StdioTransport(cmd=["true"])
    fut: asyncio.Future = asyncio.get_running_loop().create_future()
    transport._pending[1] = fut

    await transport.close()  # no process/readers connected

    assert fut.done()
    assert isinstance(fut.exception(), TransportConnectionError)
    assert transport._pending == {}
