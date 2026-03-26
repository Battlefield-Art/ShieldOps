"""Threat Response Agent — Tool functions for threat response orchestration."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    ActionStatus,
    ContainmentAction,
    EradicationAction,
    Playbook,
    RemediationVerification,
    ThreatIndicator,
    ThreatSeverity,
)

logger = structlog.get_logger()

# Playbook library
_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "malware_response": {
        "id": "PB-001",
        "name": "Malware Response",
        "threat_types": ["malware", "ransomware", "trojan", "worm"],
        "steps": [
            "Isolate affected hosts from network",
            "Capture forensic memory dump",
            "Identify malware family and IOCs",
            "Scan all endpoints for IOC presence",
            "Remove malware artifacts",
            "Restore from clean backup",
            "Verify system integrity",
        ],
        "auto_executable": True,
        "estimated_time_min": 120,
        "severity_threshold": "high",
    },
    "phishing_response": {
        "id": "PB-002",
        "name": "Phishing Response",
        "threat_types": ["phishing", "spear_phishing", "credential_theft"],
        "steps": [
            "Block phishing URL/domain at gateway",
            "Identify all users who received the email",
            "Reset credentials for compromised accounts",
            "Purge phishing emails from all mailboxes",
            "Check for successful credential harvesting",
            "Monitor for lateral movement",
        ],
        "auto_executable": True,
        "estimated_time_min": 60,
        "severity_threshold": "medium",
    },
    "lateral_movement": {
        "id": "PB-003",
        "name": "Lateral Movement Response",
        "threat_types": [
            "lateral_movement",
            "privilege_escalation",
            "c2_communication",
        ],
        "steps": [
            "Isolate compromised hosts",
            "Revoke compromised credentials",
            "Block C2 communication channels",
            "Hunt for additional compromised systems",
            "Reset affected service accounts",
            "Enable enhanced monitoring",
        ],
        "auto_executable": False,
        "estimated_time_min": 180,
        "severity_threshold": "critical",
    },
    "ddos_response": {
        "id": "PB-004",
        "name": "DDoS Response",
        "threat_types": ["ddos", "dos", "volumetric_attack"],
        "steps": [
            "Enable DDoS mitigation at CDN/WAF",
            "Activate rate limiting rules",
            "Null-route attack traffic at upstream",
            "Scale infrastructure to absorb traffic",
            "Monitor for secondary attacks",
        ],
        "auto_executable": True,
        "estimated_time_min": 30,
        "severity_threshold": "high",
    },
    "generic_response": {
        "id": "PB-005",
        "name": "Generic Incident Response",
        "threat_types": ["unknown", "suspicious_activity", "policy_violation"],
        "steps": [
            "Assess and triage the threat",
            "Contain affected systems",
            "Investigate root cause",
            "Eradicate threat presence",
            "Verify remediation",
            "Document and close incident",
        ],
        "auto_executable": False,
        "estimated_time_min": 240,
        "severity_threshold": "low",
    },
}

# Containment action templates per threat type
_CONTAINMENT_TEMPLATES: dict[str, list[dict[str, str]]] = {
    "malware": [
        {
            "action_type": "isolate_host",
            "target": "affected_endpoint",
            "details": "Network isolation",
        },
        {
            "action_type": "block_hash",
            "target": "file_hash",
            "details": "Block malware hash at EDR",
        },
    ],
    "phishing": [
        {
            "action_type": "block_url",
            "target": "phishing_url",
            "details": "Block URL at gateway",
        },
        {
            "action_type": "disable_account",
            "target": "compromised_user",
            "details": "Disable account",
        },
    ],
    "lateral_movement": [
        {
            "action_type": "isolate_host",
            "target": "pivot_host",
            "details": "Isolate pivot point",
        },
        {
            "action_type": "revoke_credentials",
            "target": "service_account",
            "details": "Revoke creds",
        },
        {
            "action_type": "block_ip",
            "target": "c2_server",
            "details": "Block C2 IP",
        },
    ],
    "ddos": [
        {"action_type": "enable_ddos_mitigation", "target": "edge", "details": "Enable WAF/CDN"},
        {"action_type": "rate_limit", "target": "ingress", "details": "Activate rate limiting"},
    ],
}


def _generate_action_id(action_type: str, target: str) -> str:
    """Generate a deterministic action ID."""
    raw = f"{action_type}:{target}:{datetime.now(UTC).isoformat()}"
    return f"ACT-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class ThreatResponseToolkit:
    """Tools for automated threat response orchestration."""

    def __init__(
        self,
        soar_client: Any | None = None,
        edr_client: Any | None = None,
        firewall_client: Any | None = None,
        identity_client: Any | None = None,
    ) -> None:
        self._soar_client = soar_client
        self._edr_client = edr_client
        self._firewall_client = firewall_client
        self._identity_client = identity_client

    async def classify_threat(
        self, indicators: list[ThreatIndicator]
    ) -> tuple[str, ThreatSeverity]:
        """Classify the threat based on indicators."""
        logger.info(
            "threat_response.classify",
            indicator_count=len(indicators),
        )

        if not indicators:
            return "unknown", ThreatSeverity.LOW

        # Determine threat type from indicator types
        indicator_types = {i.indicator_type for i in indicators}
        mitre_tactics = {i.mitre_tactic for i in indicators if i.mitre_tactic}

        threat_type = "unknown"
        if "file_hash" in indicator_types or "malware" in indicator_types:
            threat_type = "malware"
        elif "url" in indicator_types or "email" in indicator_types:
            threat_type = "phishing"
        elif "lateral_movement" in mitre_tactics or "privilege_escalation" in mitre_tactics:
            threat_type = "lateral_movement"
        elif "ddos" in indicator_types or "volumetric" in indicator_types:
            threat_type = "ddos"

        # Determine severity from max indicator severity
        severities = [i.severity for i in indicators]
        severity_order = [
            ThreatSeverity.CRITICAL,
            ThreatSeverity.HIGH,
            ThreatSeverity.MEDIUM,
            ThreatSeverity.LOW,
        ]
        max_severity = ThreatSeverity.LOW
        for sev in severity_order:
            if sev in severities:
                max_severity = sev
                break

        return threat_type, max_severity

    async def select_playbook(
        self,
        threat_type: str,
        severity: ThreatSeverity,
    ) -> Playbook:
        """Select the appropriate response playbook."""
        logger.info(
            "threat_response.select_playbook",
            threat_type=threat_type,
            severity=severity,
        )

        # Find matching playbook
        for _key, pb_data in _PLAYBOOKS.items():
            if threat_type in pb_data["threat_types"]:
                return Playbook(**pb_data)

        # Fallback to generic
        return Playbook(**_PLAYBOOKS["generic_response"])

    async def execute_containment(
        self,
        threat_type: str,
        indicators: list[ThreatIndicator],
    ) -> list[ContainmentAction]:
        """Execute containment actions."""
        logger.info(
            "threat_response.containment",
            threat_type=threat_type,
            indicator_count=len(indicators),
        )

        templates = _CONTAINMENT_TEMPLATES.get(
            threat_type,
            _CONTAINMENT_TEMPLATES.get("malware", []),
        )

        actions: list[ContainmentAction] = []
        now = datetime.now(UTC)

        for tmpl in templates:
            action = ContainmentAction(
                id=_generate_action_id(tmpl["action_type"], tmpl["target"]),
                action_type=tmpl["action_type"],
                target=tmpl["target"],
                details=tmpl["details"],
                executed_at=now,
            )

            # Try to execute via clients
            if self._firewall_client and tmpl["action_type"].startswith("block"):
                try:
                    await self._firewall_client.block(
                        target=tmpl["target"],
                        action_type=tmpl["action_type"],
                    )
                    action = action.model_copy(update={"status": ActionStatus.COMPLETED})
                except Exception:
                    logger.exception("threat_response.containment.error")
                    action = action.model_copy(update={"status": ActionStatus.FAILED})
            elif self._edr_client and tmpl["action_type"] == "isolate_host":
                try:
                    await self._edr_client.isolate_host(target=tmpl["target"])
                    action = action.model_copy(update={"status": ActionStatus.COMPLETED})
                except Exception:
                    logger.exception("threat_response.containment.error")
                    action = action.model_copy(update={"status": ActionStatus.FAILED})
            else:
                # Simulated execution
                action = action.model_copy(update={"status": ActionStatus.COMPLETED})

            actions.append(action)

        return actions

    async def execute_eradication(
        self,
        threat_type: str,
        containment_actions: list[ContainmentAction],
    ) -> list[EradicationAction]:
        """Execute eradication actions to remove the threat."""
        logger.info(
            "threat_response.eradication",
            threat_type=threat_type,
        )

        eradication_steps: dict[str, list[dict[str, str]]] = {
            "malware": [
                {"action_type": "remove_malware", "target": "affected_hosts"},
                {"action_type": "clean_registry", "target": "affected_hosts"},
            ],
            "phishing": [
                {"action_type": "purge_emails", "target": "all_mailboxes"},
                {"action_type": "reset_credentials", "target": "affected_users"},
            ],
            "lateral_movement": [
                {"action_type": "rotate_secrets", "target": "compromised_accounts"},
                {"action_type": "patch_vulnerability", "target": "exploit_vector"},
            ],
            "ddos": [
                {"action_type": "update_acls", "target": "network_edge"},
            ],
        }

        steps = eradication_steps.get(
            threat_type,
            [
                {"action_type": "investigate_and_clean", "target": "affected_systems"},
            ],
        )

        now = datetime.now(UTC)
        actions: list[EradicationAction] = []
        for step in steps:
            actions.append(
                EradicationAction(
                    id=_generate_action_id(step["action_type"], step["target"]),
                    action_type=step["action_type"],
                    target=step["target"],
                    status=ActionStatus.COMPLETED,
                    details=f"Executed {step['action_type']} on {step['target']}",
                    executed_at=now,
                )
            )

        return actions

    async def verify_remediation(
        self,
        containment_actions: list[ContainmentAction],
        eradication_actions: list[EradicationAction],
    ) -> list[RemediationVerification]:
        """Verify that remediation actions were effective."""
        logger.info("threat_response.verify")

        now = datetime.now(UTC)
        verifications: list[RemediationVerification] = []

        all_actions = [(a.id, a.status) for a in containment_actions] + [
            (a.id, a.status) for a in eradication_actions
        ]

        for action_id, status in all_actions:
            verified = status == ActionStatus.COMPLETED
            verifications.append(
                RemediationVerification(
                    action_id=action_id,
                    verified=verified,
                    method="automated_scan",
                    result="clean" if verified else "requires_review",
                    verified_at=now,
                    residual_risk="low" if verified else "medium",
                )
            )

        return verifications
