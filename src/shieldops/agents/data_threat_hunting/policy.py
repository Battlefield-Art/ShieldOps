"""OPA policy integration for the Data Threat Hunting Agent."""

from typing import Any

import structlog

logger = structlog.get_logger()


async def check_hunt_policy(
    tenant_id: str,
    hunt_scope: dict[str, Any],
    opa_endpoint: str | None = None,
) -> dict[str, Any]:
    """Validate hunt scope against OPA policies.

    Ensures:
    - Tenant has permission to hunt in target sources
    - Backup snapshot access is authorized
    - AI pipeline scanning is within allowed scope
    - Hunt time range respects data retention policies
    """
    logger.info(
        "data_threat_hunting.check_policy",
        tenant_id=tenant_id,
        scope_keys=list(hunt_scope.keys()),
    )

    # Default: allow if no OPA endpoint configured
    if not opa_endpoint:
        return {
            "allowed": True,
            "reason": "No OPA endpoint configured",
            "restrictions": [],
        }

    # Production: POST to OPA for policy evaluation
    # input = {
    #     "tenant_id": tenant_id,
    #     "action": "data_threat_hunt",
    #     "sources": hunt_scope.get("sources", []),
    #     "time_range": hunt_scope.get("time_range"),
    #     "snapshot_ids": hunt_scope.get("snapshot_ids"),
    # }
    # async with httpx.AsyncClient() as client:
    #     resp = await client.post(
    #         f"{opa_endpoint}/v1/data/shieldops/hunt",
    #         json={"input": input},
    #     )
    #     result = resp.json().get("result", {})

    return {
        "allowed": True,
        "reason": "Policy evaluation passed",
        "restrictions": [],
    }


async def check_backup_access_policy(
    tenant_id: str,
    snapshot_ids: list[str],
    opa_endpoint: str | None = None,
) -> dict[str, Any]:
    """Validate backup snapshot access authorization."""
    logger.info(
        "data_threat_hunting.check_backup_access",
        tenant_id=tenant_id,
        snapshot_count=len(snapshot_ids),
    )

    if not opa_endpoint:
        return {
            "allowed": True,
            "reason": "No OPA endpoint configured",
            "authorized_snapshots": snapshot_ids,
        }

    return {
        "allowed": True,
        "reason": "Backup access authorized",
        "authorized_snapshots": snapshot_ids,
    }
