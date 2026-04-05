"""OPA (Open Policy Agent) HTTP client — fail-closed on any error.

Queries OPA's Data API at ``OPA_ENDPOINT`` (env var, default ``http://localhost:8181``).
On any failure (network, timeout, bad response) the client **denies** the action
and logs an error for ops alerting.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

OPA_ENDPOINT = os.environ.get("OPA_ENDPOINT", "http://localhost:8181")
OPA_TIMEOUT_SECONDS = 5.0
OPA_MAX_RETRIES = 1


async def query_opa(policy_path: str, input_data: dict[str, Any]) -> dict[str, Any]:
    """Query OPA for a policy decision.

    Args:
        policy_path: Dot-separated OPA policy path (e.g. ``shieldops/agent_action``).
                     Converted to ``/v1/data/{policy_path}`` automatically.
        input_data: The ``input`` document OPA will evaluate against.

    Returns:
        The OPA result dict.  On success this is whatever ``result`` the policy
        returns.  On failure this is a synthetic deny payload.

    Raises:
        Nothing — errors are caught internally and converted to deny decisions
        (fail-closed).
    """
    url = f"{OPA_ENDPOINT}/v1/data/{policy_path.replace('.', '/')}"
    payload = {"input": input_data}
    last_error: Exception | None = None

    for attempt in range(1 + OPA_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=OPA_TIMEOUT_SECONDS) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                body = response.json()
                result: dict[str, Any] = body.get("result", {})
                logger.debug(
                    "opa_query_success",
                    policy_path=policy_path,
                    attempt=attempt + 1,
                )
                return result

        except (httpx.HTTPError, httpx.TimeoutException, Exception) as exc:
            last_error = exc
            logger.warning(
                "opa_query_attempt_failed",
                policy_path=policy_path,
                attempt=attempt + 1,
                error=str(exc),
            )

    # All attempts exhausted — fail closed
    logger.error(
        "opa_unreachable_fail_closed",
        policy_path=policy_path,
        error=str(last_error),
    )
    return {
        "deny": True,
        "reason": f"OPA unreachable after {1 + OPA_MAX_RETRIES} attempts. Fail-closed deny.",
        "matched_policies": [],
    }
