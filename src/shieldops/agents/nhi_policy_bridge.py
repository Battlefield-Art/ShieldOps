"""NHI Policy Bridge — connects identity_graph discoveries to agent_firewall enforcement."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger()


class NHIPolicyBridge:
    """Translates NHI risk assessments into firewall policy rules."""

    def __init__(self) -> None:
        self._nhi_inventory: dict[str, dict[str, Any]] = {}
        self._policy_rules: list[dict[str, Any]] = []

    def update_inventory(self, identities: list[dict[str, Any]]) -> int:
        """Update NHI inventory from identity_graph discoveries."""
        added = 0
        for identity in identities:
            id_key = identity.get("id", "")
            if id_key:
                self._nhi_inventory[id_key] = identity
                added += 1
        self._regenerate_rules()
        logger.info(
            "nhi_bridge.inventory_updated",
            total=len(self._nhi_inventory),
            added=added,
        )
        return added

    def _regenerate_rules(self) -> None:
        """Generate firewall rules from NHI risk assessments."""
        self._policy_rules = []
        for nhi_id, identity in self._nhi_inventory.items():
            risk_score = identity.get("risk_score", 0)
            risk_level = identity.get("risk_level", "low")
            name = identity.get("name", nhi_id)

            if risk_level == "critical":
                self._policy_rules.append(
                    {
                        "identity_id": nhi_id,
                        "action": "block",
                        "reason": f"Critical risk NHI: {name}",
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                    }
                )
            elif risk_level == "high":
                self._policy_rules.append(
                    {
                        "identity_id": nhi_id,
                        "action": "audit_enhanced",
                        "reason": f"High risk NHI: {name}",
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                    }
                )

    def evaluate_identity(self, identity_id: str) -> dict[str, Any]:
        """Check if an identity has policy restrictions."""
        for rule in self._policy_rules:
            if rule["identity_id"] == identity_id:
                return {"restricted": True, **rule}
        return {"restricted": False, "action": "allow", "identity_id": identity_id}

    def get_policy_rules(self) -> list[dict[str, Any]]:
        """Return all active NHI policy rules."""
        return list(self._policy_rules)

    def get_stats(self) -> dict[str, Any]:
        """Return bridge statistics."""
        blocked = sum(1 for r in self._policy_rules if r["action"] == "block")
        audited = sum(1 for r in self._policy_rules if r["action"] == "audit_enhanced")
        return {
            "total_identities": len(self._nhi_inventory),
            "total_rules": len(self._policy_rules),
            "blocked": blocked,
            "audit_enhanced": audited,
            "unrestricted": len(self._nhi_inventory) - blocked - audited,
        }
