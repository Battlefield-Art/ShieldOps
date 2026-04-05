"""Tests for the OPA HTTP client — especially fail-closed behaviour."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from shieldops.policy.opa_client import query_opa


@pytest.mark.asyncio
async def test_successful_query() -> None:
    """A healthy OPA returns the result dict."""
    expected_result = {"deny": False, "matched_policies": ["base"]}
    mock_resp = httpx.Response(
        200,
        json={"result": expected_result},
        request=httpx.Request("POST", "http://localhost:8181/v1/data/shieldops/allow"),
    )

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("shieldops.policy.opa_client.httpx.AsyncClient", return_value=mock_client):
        result = await query_opa("shieldops/allow", {"action": "test"})

    assert result == expected_result


@pytest.mark.asyncio
async def test_fail_closed_on_timeout() -> None:
    """When OPA times out, the client returns a deny payload."""
    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.TimeoutException("timeout")
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("shieldops.policy.opa_client.httpx.AsyncClient", return_value=mock_client):
        result = await query_opa("shieldops/allow", {"action": "test"})

    assert result["deny"] is True
    assert "unreachable" in result["reason"].lower()


@pytest.mark.asyncio
async def test_fail_closed_on_http_error() -> None:
    """When OPA returns a 500, the client retries then denies."""
    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.HTTPStatusError(
        "500", request=httpx.Request("POST", "http://x"), response=httpx.Response(500)
    )
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("shieldops.policy.opa_client.httpx.AsyncClient", return_value=mock_client):
        result = await query_opa("shieldops/allow", {"action": "test"})

    assert result["deny"] is True


@pytest.mark.asyncio
async def test_retries_once_before_deny() -> None:
    """The client should attempt 1 + 1 retry = 2 total calls."""
    call_count = 0

    async def _fail(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectError("refused")

    mock_client = AsyncMock()
    mock_client.post = _fail
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("shieldops.policy.opa_client.httpx.AsyncClient", return_value=mock_client):
        result = await query_opa("shieldops/allow", {"action": "test"})

    assert call_count == 2  # 1 initial + 1 retry
    assert result["deny"] is True


@pytest.mark.asyncio
async def test_policy_path_slash_conversion() -> None:
    """Dots in policy_path are converted to slashes in the URL."""
    captured_url: str = ""

    async def _capture(url, **kwargs):
        nonlocal captured_url
        captured_url = str(url)
        raise httpx.ConnectError("not real")

    mock_client = AsyncMock()
    mock_client.post = _capture
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("shieldops.policy.opa_client.httpx.AsyncClient", return_value=mock_client):
        await query_opa("shieldops.agent.action", {"action": "test"})

    assert "/v1/data/shieldops/agent/action" in captured_url
