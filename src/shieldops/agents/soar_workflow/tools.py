"""SOAR Workflow Orchestrator Agent — Tool functions for SOAR workflow execution."""

from __future__ import annotations

import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    AlertIntake,
    EnrichmentResult,
    PlaybookType,
    ResponseAction,
    ResponseStatus,
)

logger = structlog.get_logger()

# Threat intel enrichment profiles by indicator type
_ENRICHMENT_PROFILES: dict[str, dict[str, Any]] = {
    "ip": {
        "enrichment_type": "ip_reputation",
        "sources": ["AbuseIPDB", "VirusTotal", "GreyNoise"],
        "malicious_probability": 0.6,
    },
    "domain": {
        "enrichment_type": "domain_reputation",
        "sources": ["VirusTotal", "URLhaus", "MISP"],
        "malicious_probability": 0.5,
    },
    "hash": {
        "enrichment_type": "file_analysis",
        "sources": ["VirusTotal", "MalwareBazaar", "Hybrid-Analysis"],
        "malicious_probability": 0.7,
    },
    "email": {
        "enrichment_type": "email_reputation",
        "sources": ["PhishTank", "EmailRep", "internal_allow_list"],
        "malicious_probability": 0.3,
    },
}

# Severity-to-risk-score mapping (RBA-inspired)
_SEVERITY_SCORES: dict[str, int] = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "informational": 5,
}

# Containment action templates
_CONTAINMENT_ACTIONS: dict[str, dict[str, Any]] = {
    "block_ip": {
        "description": "Block IP at perimeter firewall",
        "avg_duration_ms": 1500,
        "success_rate": 0.95,
    },
    "isolate_host": {
        "description": "Isolate host via EDR network containment",
        "avg_duration_ms": 3000,
        "success_rate": 0.90,
    },
    "disable_account": {
        "description": "Disable user account in identity provider",
        "avg_duration_ms": 800,
        "success_rate": 0.98,
    },
}

# Eradication action templates
_ERADICATION_ACTIONS: dict[str, dict[str, Any]] = {
    "remove_malware": {
        "description": "Remove malware artifacts from affected host",
        "avg_duration_ms": 5000,
        "success_rate": 0.85,
    },
    "patch_vulnerability": {
        "description": "Apply security patch to exploited vulnerability",
        "avg_duration_ms": 10000,
        "success_rate": 0.92,
    },
    "rotate_credentials": {
        "description": "Rotate compromised credentials and API keys",
        "avg_duration_ms": 2000,
        "success_rate": 0.97,
    },
}

# Recovery action templates
_RECOVERY_ACTIONS: dict[str, dict[str, Any]] = {
    "restore_service": {
        "description": "Restore service from clean backup",
        "avg_duration_ms": 15000,
        "success_rate": 0.88,
    },
    "verify_health": {
        "description": "Run health checks and synthetic monitoring",
        "avg_duration_ms": 3000,
        "success_rate": 0.95,
    },
    "reenable_access": {
        "description": "Re-enable user access after credential rotation",
        "avg_duration_ms": 1200,
        "success_rate": 0.97,
    },
}


def _classify_indicator(indicator: str) -> str:
    """Classify an indicator by type based on its format."""
    if "@" in indicator:
        return "email"
    parts = indicator.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    if len(indicator) in (32, 40, 64) and all(c in "0123456789abcdef" for c in indicator.lower()):
        return "hash"
    return "domain"


class SOARWorkflowToolkit:
    """Tools for SOAR workflow orchestration and response execution."""

    def __init__(
        self,
        siem_client: Any | None = None,
        edr_client: Any | None = None,
        firewall_client: Any | None = None,
        threat_intel_client: Any | None = None,
    ) -> None:
        self._siem_client = siem_client
        self._edr_client = edr_client
        self._firewall_client = firewall_client
        self._threat_intel_client = threat_intel_client

    async def intake_alert(self, alert_data: dict[str, Any]) -> AlertIntake:
        """Normalize and classify an incoming security alert.

        Extracts IOCs, maps to MITRE tactics, and assigns initial priority
        using RBA risk-based scoring.
        """
        logger.info("soar_workflow.intake_alert", alert_id=alert_data.get("alert_id", ""))

        if self._siem_client is not None:
            try:
                raw = await self._siem_client.normalize_alert(alert_data)
                return AlertIntake(**raw)
            except Exception:
                logger.exception("soar_workflow.intake_alert.siem_error")

        # Mock fallback — normalize from raw alert data
        alert_id = alert_data.get("alert_id", f"ALERT-{uuid.uuid4().hex[:8].upper()}")
        source = alert_data.get("source", "unknown")
        severity = alert_data.get("severity", "medium")
        description = alert_data.get("description", "Security alert received")
        indicators = alert_data.get("indicators", [])
        mitre_tactics = alert_data.get("mitre_tactics", [])

        # Auto-detect MITRE tactics if not provided
        if not mitre_tactics:
            desc_lower = description.lower()
            tactic_keywords: dict[str, str] = {
                "phishing": "TA0001-Initial Access",
                "brute force": "TA0006-Credential Access",
                "lateral": "TA0008-Lateral Movement",
                "exfiltration": "TA0010-Exfiltration",
                "malware": "TA0002-Execution",
                "persistence": "TA0003-Persistence",
                "privilege": "TA0004-Privilege Escalation",
                "command and control": "TA0011-Command and Control",
                "c2": "TA0011-Command and Control",
            }
            for keyword, tactic in tactic_keywords.items():
                if keyword in desc_lower:
                    mitre_tactics.append(tactic)
            if not mitre_tactics:
                mitre_tactics = ["TA0043-Reconnaissance"]

        return AlertIntake(
            alert_id=alert_id,
            source=source,
            severity=severity,
            description=description,
            indicators=indicators,
            mitre_tactics=mitre_tactics,
        )

    async def enrich_indicators(self, indicators: list[str]) -> list[EnrichmentResult]:
        """Enrich IOCs via threat intelligence feeds.

        Queries multiple TI sources, correlates results, and scores
        confidence based on source reliability.
        """
        logger.info("soar_workflow.enrich_indicators", indicator_count=len(indicators))

        if self._threat_intel_client is not None:
            try:
                raw = await self._threat_intel_client.enrich_bulk(indicators)
                return [EnrichmentResult(**r) for r in raw]
            except Exception:
                logger.exception("soar_workflow.enrich_indicators.ti_error")

        # Mock fallback — simulate enrichment
        results: list[EnrichmentResult] = []
        for indicator in indicators:
            indicator_type = _classify_indicator(indicator)
            profile = _ENRICHMENT_PROFILES.get(indicator_type, _ENRICHMENT_PROFILES["domain"])

            is_malicious = random.random() < profile["malicious_probability"]
            confidence = round(
                random.uniform(0.7, 0.99) if is_malicious else random.uniform(0.1, 0.4), 2
            )

            result_data: dict[str, Any] = {
                "indicator_type": indicator_type,
                "is_malicious": is_malicious,
                "sources_checked": profile["sources"],
                "hits": random.randint(1, len(profile["sources"])) if is_malicious else 0,
                "first_seen": "2025-01-15T10:30:00Z" if is_malicious else None,
                "tags": ["suspicious", "automated"] if is_malicious else ["benign"],
            }

            results.append(
                EnrichmentResult(
                    indicator=indicator,
                    enrichment_type=profile["enrichment_type"],
                    result=result_data,
                    confidence=confidence,
                )
            )

        return results

    async def execute_containment(self, target: str, action_type: str) -> ResponseAction:
        """Execute a containment action (block IP, isolate host, disable account).

        Coordinates with firewall, EDR, and identity provider to contain
        the threat and limit blast radius.
        """
        logger.info(
            "soar_workflow.execute_containment",
            target=target,
            action_type=action_type,
        )

        action_profile = _CONTAINMENT_ACTIONS.get(action_type, _CONTAINMENT_ACTIONS["block_ip"])
        start_time = time.monotonic()

        if self._firewall_client is not None and action_type == "block_ip":
            try:
                raw = await self._firewall_client.block_ip(target)
                duration_ms = int((time.monotonic() - start_time) * 1000)
                return ResponseAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
                    playbook_type=PlaybookType.CONTAINMENT,
                    target=target,
                    status=ResponseStatus.COMPLETED,
                    result=raw,
                    duration_ms=duration_ms,
                )
            except Exception:
                logger.exception("soar_workflow.execute_containment.error")

        # Mock fallback
        success = random.random() < action_profile["success_rate"]
        duration_ms = action_profile["avg_duration_ms"] + random.randint(-200, 500)

        return ResponseAction(
            action_id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
            playbook_type=PlaybookType.CONTAINMENT,
            target=target,
            status=ResponseStatus.COMPLETED if success else ResponseStatus.FAILED,
            result={
                "action_type": action_type,
                "description": action_profile["description"],
                "success": success,
                "target": target,
            },
            duration_ms=max(0, duration_ms),
        )

    async def execute_eradication(self, target: str, action_type: str) -> ResponseAction:
        """Execute an eradication action (remove malware, patch vuln, rotate creds).

        Removes threat artifacts and remediates the exploited vulnerability
        or compromised credential.
        """
        logger.info(
            "soar_workflow.execute_eradication",
            target=target,
            action_type=action_type,
        )

        action_profile = _ERADICATION_ACTIONS.get(
            action_type, _ERADICATION_ACTIONS["remove_malware"]
        )

        if self._edr_client is not None and action_type == "remove_malware":
            try:
                raw = await self._edr_client.remove_malware(target)
                return ResponseAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
                    playbook_type=PlaybookType.ERADICATION,
                    target=target,
                    status=ResponseStatus.COMPLETED,
                    result=raw,
                    duration_ms=0,
                )
            except Exception:
                logger.exception("soar_workflow.execute_eradication.error")

        # Mock fallback
        success = random.random() < action_profile["success_rate"]
        duration_ms = action_profile["avg_duration_ms"] + random.randint(-500, 1000)

        return ResponseAction(
            action_id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
            playbook_type=PlaybookType.ERADICATION,
            target=target,
            status=ResponseStatus.COMPLETED if success else ResponseStatus.FAILED,
            result={
                "action_type": action_type,
                "description": action_profile["description"],
                "success": success,
                "target": target,
            },
            duration_ms=max(0, duration_ms),
        )

    async def execute_recovery(self, target: str, action_type: str) -> ResponseAction:
        """Execute a recovery action (restore service, verify health, re-enable access).

        Restores affected services and validates health before re-enabling
        user access.
        """
        logger.info(
            "soar_workflow.execute_recovery",
            target=target,
            action_type=action_type,
        )

        action_profile = _RECOVERY_ACTIONS.get(action_type, _RECOVERY_ACTIONS["restore_service"])

        # Mock fallback (no external client pattern for recovery)
        success = random.random() < action_profile["success_rate"]
        duration_ms = action_profile["avg_duration_ms"] + random.randint(-500, 1000)

        return ResponseAction(
            action_id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
            playbook_type=PlaybookType.RECOVERY,
            target=target,
            status=ResponseStatus.COMPLETED if success else ResponseStatus.FAILED,
            result={
                "action_type": action_type,
                "description": action_profile["description"],
                "success": success,
                "target": target,
            },
            duration_ms=max(0, duration_ms),
        )
