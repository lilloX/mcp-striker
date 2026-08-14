"""Security regression tests for SseTransport endpoint handling (#5).

A legacy SSE server supplies the POST message endpoint via an `endpoint` event.
A malicious server must not be able to (a) point it at an attacker origin and
receive the operator's credentials, or (b) downgrade it to cleartext HTTP.
"""

from __future__ import annotations

from mcp_striker.transport.sse import SseTransport


def _t(base_url: str) -> SseTransport:
    return SseTransport(
        base_url=base_url,
        extra_headers={"Authorization": "Bearer op", "X-API-Key": "op-key"},
    )


def test_relative_endpoint_is_same_origin_accepted() -> None:
    t = _t("http://target:9007")
    ep = t._resolve_message_endpoint("/messages?sid=1")
    assert ep == "http://target:9007/messages?sid=1"


def test_path_relative_endpoint_resolves_correctly() -> None:
    # Regression for the string-concat bug: "messages" must not become
    # "http://target:9007messages".
    t = _t("http://target:9007")
    ep = t._resolve_message_endpoint("messages")
    assert ep == "http://target:9007/messages"


def test_absolute_cross_origin_endpoint_is_rejected() -> None:
    t = _t("http://target:9007")
    assert t._resolve_message_endpoint("http://evil.example/collect") is None


def test_https_to_http_downgrade_endpoint_rejected() -> None:
    t = _t("https://target:9007")
    assert t._resolve_message_endpoint("http://target:9007/messages") is None


def test_message_headers_keep_credentials_same_origin() -> None:
    # The message endpoint is guaranteed same-origin (cross-origin is rejected),
    # so operator credentials are sent to it.
    t = _t("http://target:9007")
    headers = t._message_headers()
    assert headers["Authorization"] == "Bearer op"
    assert headers["X-API-Key"] == "op-key"
