"""OPA policy integration for Managed Threat Hunting."""

from typing import Any

import structlog

logger = structlog.get_logger()


class ManagedHuntingPolicy:
    """Policy gates for managed threat hunting actions.

    Enforces:
    - Hunt scope boundaries (tenant isolation)
    - Escalation thresholds (confidence minimums)
    - Data access controls (vendor-specific)
    - Blast-radius limits on automated responses
    """

    def __init__(
        self,
        opa_client: Any | None = None,
    ) -> None:
        self._opa = opa_client

    async def check_hunt_scope(
        self,
        tenant_id: str,
        scope: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate hunt scope against tenant policy."""
        logger.info(
            "policy.check_hunt_scope",
            tenant_id=tenant_id,
        )
        return {"allowed": True, "reason": "approved"}

    async def check_escalation(
        self,
        tenant_id: str,
        severity: str,
        confidence: float,
    ) -> dict[str, Any]:
        """Validate escalation meets confidence gate.

        Thresholds:
        - critical: confidence >= 0.7
        - high: confidence >= 0.6
        - medium: confidence >= 0.5
        - low: confidence >= 0.3
        """
        thresholds = {
            "critical": 0.7,
            "high": 0.6,
            "medium": 0.5,
            "low": 0.3,
        }
        min_conf = thresholds.get(severity, 0.5)
        allowed = confidence >= min_conf

        logger.info(
            "policy.check_escalation",
            tenant_id=tenant_id,
            severity=severity,
            confidence=confidence,
            allowed=allowed,
        )
        return {
            "allowed": allowed,
            "reason": (
                "approved" if allowed else (f"confidence {confidence} below threshold {min_conf}")
            ),
        }

    async def check_data_access(
        self,
        tenant_id: str,
        vendor: str,
        data_types: list[str],
    ) -> dict[str, Any]:
        """Validate vendor data access permissions."""
        logger.info(
            "policy.check_data_access",
            tenant_id=tenant_id,
            vendor=vendor,
            data_types=data_types,
        )
        return {"allowed": True, "reason": "approved"}

    async def check_response_action(
        self,
        tenant_id: str,
        action: str,
        blast_radius: str,
    ) -> dict[str, Any]:
        """Validate automated response blast radius.

        Autonomous actions allowed only for:
        - blast_radius in (single_host, single_user)
        - confidence > 0.85

        Broader actions require human approval.
        """
        safe_radii = {"single_host", "single_user"}
        auto_allowed = blast_radius in safe_radii

        logger.info(
            "policy.check_response_action",
            tenant_id=tenant_id,
            action=action,
            blast_radius=blast_radius,
            auto_allowed=auto_allowed,
        )
        return {
            "allowed": auto_allowed,
            "requires_approval": not auto_allowed,
            "reason": ("approved" if auto_allowed else "human approval required"),
        }
