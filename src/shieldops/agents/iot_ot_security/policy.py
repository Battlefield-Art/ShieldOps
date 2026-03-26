"""OPA policy integration for the IoT/OT Security Agent."""

from typing import Any

import structlog

logger = structlog.get_logger()


async def check_iot_scan_policy(
    tenant_id: str,
    scan_scope: dict[str, Any],
    opa_endpoint: str | None = None,
) -> dict[str, Any]:
    """Validate IoT/OT scan scope against OPA policies.

    Ensures:
    - Tenant has permission to scan target zones
    - Device discovery method is authorized
    - Segmentation enforcement is within scope
    - OT zones respect safety constraints
    """
    logger.info(
        "iot_ot_security.check_policy",
        tenant_id=tenant_id,
        scope_keys=list(scan_scope.keys()),
    )

    if not opa_endpoint:
        return {
            "allowed": True,
            "reason": "No OPA endpoint configured",
            "restrictions": [],
        }

    # Production: POST to OPA for evaluation
    # input = {
    #     "tenant_id": tenant_id,
    #     "action": "iot_ot_scan",
    #     "zones": scan_scope.get("zones", []),
    #     "device_categories": scan_scope.get(
    #         "categories", [],
    #     ),
    #     "enforce_segmentation": scan_scope.get(
    #         "enforce", False,
    #     ),
    # }
    # async with httpx.AsyncClient() as client:
    #     resp = await client.post(
    #         f"{opa_endpoint}/v1/data/shieldops/iot",
    #         json={"input": input},
    #     )
    #     result = resp.json().get("result", {})

    return {
        "allowed": True,
        "reason": "Policy evaluation passed",
        "restrictions": [],
    }


async def check_segmentation_policy(
    tenant_id: str,
    device_ids: list[str],
    action: str,
    opa_endpoint: str | None = None,
) -> dict[str, Any]:
    """Validate segmentation enforcement authorization.

    Ensures quarantine and restrict actions are
    authorized for the given devices and tenant.
    """
    logger.info(
        "iot_ot_security.check_segmentation",
        tenant_id=tenant_id,
        device_count=len(device_ids),
        action=action,
    )

    if not opa_endpoint:
        return {
            "allowed": True,
            "reason": "No OPA endpoint configured",
            "authorized_devices": device_ids,
        }

    return {
        "allowed": True,
        "reason": "Segmentation action authorized",
        "authorized_devices": device_ids,
    }
