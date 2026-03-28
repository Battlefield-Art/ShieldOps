"""Tool functions for the IR Playbook Engine Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ir_playbook_engine.models import (
    ContainmentValidation,
    IncidentClassification,
    IncidentType,
    PlaybookSelection,
    StepExecution,
)

logger = structlog.get_logger()

# Playbook templates by incident type
PLAYBOOK_TEMPLATES: dict[IncidentType, dict[str, Any]] = {
    IncidentType.MALWARE: {
        "name": "malware_containment_v2",
        "steps": [
            {"name": "isolate_host", "auto": True},
            {"name": "kill_process", "auto": True},
            {"name": "collect_samples", "auto": False},
            {"name": "scan_lateral", "auto": True},
            {"name": "restore_clean", "auto": False},
        ],
        "duration": 45,
    },
    IncidentType.RANSOMWARE: {
        "name": "ransomware_response_v3",
        "steps": [
            {"name": "isolate_network", "auto": True},
            {"name": "identify_variant", "auto": False},
            {"name": "assess_encryption", "auto": False},
            {"name": "check_backups", "auto": True},
            {"name": "restore_systems", "auto": False},
            {"name": "threat_hunt", "auto": True},
        ],
        "duration": 120,
    },
    IncidentType.DATA_BREACH: {
        "name": "data_breach_response_v2",
        "steps": [
            {"name": "contain_access", "auto": True},
            {"name": "assess_scope", "auto": False},
            {"name": "preserve_evidence", "auto": True},
            {"name": "notify_legal", "auto": False},
            {"name": "remediate_vuln", "auto": False},
        ],
        "duration": 90,
    },
    IncidentType.PHISHING: {
        "name": "phishing_response_v2",
        "steps": [
            {"name": "block_sender", "auto": True},
            {"name": "quarantine_emails", "auto": True},
            {"name": "reset_credentials", "auto": True},
            {"name": "scan_clicked", "auto": True},
        ],
        "duration": 30,
    },
    IncidentType.DDOS: {
        "name": "ddos_mitigation_v2",
        "steps": [
            {"name": "enable_waf_rules", "auto": True},
            {"name": "rate_limit", "auto": True},
            {"name": "scale_infra", "auto": True},
            {"name": "analyze_traffic", "auto": False},
        ],
        "duration": 20,
    },
    IncidentType.INSIDER: {
        "name": "insider_threat_v1",
        "steps": [
            {"name": "revoke_access", "auto": True},
            {"name": "audit_actions", "auto": True},
            {"name": "preserve_evidence", "auto": True},
            {"name": "notify_hr_legal", "auto": False},
        ],
        "duration": 60,
    },
    IncidentType.SUPPLY_CHAIN: {
        "name": "supply_chain_response_v1",
        "steps": [
            {"name": "identify_components", "auto": True},
            {"name": "assess_impact", "auto": False},
            {"name": "block_artifacts", "auto": True},
            {"name": "scan_deployments", "auto": True},
            {"name": "notify_vendors", "auto": False},
        ],
        "duration": 90,
    },
    IncidentType.ACCOUNT_COMPROMISE: {
        "name": "account_compromise_v2",
        "steps": [
            {"name": "disable_account", "auto": True},
            {"name": "revoke_sessions", "auto": True},
            {"name": "audit_activity", "auto": True},
            {"name": "reset_credentials", "auto": True},
            {"name": "review_access", "auto": False},
        ],
        "duration": 30,
    },
}

# Indicator patterns for incident type detection
TYPE_INDICATORS: dict[IncidentType, list[str]] = {
    IncidentType.MALWARE: [
        "malware",
        "trojan",
        "virus",
        "worm",
        "c2 beacon",
        "backdoor",
    ],
    IncidentType.RANSOMWARE: [
        "ransomware",
        "encrypted files",
        "ransom note",
        "crypto",
        "locked files",
    ],
    IncidentType.DATA_BREACH: [
        "data breach",
        "exfiltration",
        "data leak",
        "unauthorized access to data",
        "pii exposed",
    ],
    IncidentType.PHISHING: [
        "phishing",
        "suspicious email",
        "credential harvest",
        "social engineering",
        "spear phishing",
    ],
    IncidentType.DDOS: [
        "ddos",
        "denial of service",
        "traffic spike",
        "syn flood",
        "volumetric attack",
    ],
    IncidentType.INSIDER: [
        "insider",
        "employee",
        "privilege abuse",
        "unauthorized download",
        "policy violation",
    ],
    IncidentType.SUPPLY_CHAIN: [
        "supply chain",
        "dependency",
        "compromised package",
        "upstream",
        "third-party compromise",
    ],
    IncidentType.ACCOUNT_COMPROMISE: [
        "account compromise",
        "stolen credentials",
        "brute force",
        "credential stuffing",
        "impossible travel",
    ],
}


class IRPlaybookEngineToolkit:
    """Toolkit for IR playbook execution."""

    def __init__(
        self,
        playbook_db: Any | None = None,
        infra_client: Any | None = None,
    ) -> None:
        self._playbook_db = playbook_db
        self._infra_client = infra_client

    async def classify_incident(
        self,
        incident: dict[str, Any],
    ) -> IncidentClassification:
        """Classify incident type from indicators."""
        text = (f"{incident.get('title', '')} {incident.get('description', '')}").lower()

        best_type = IncidentType.MALWARE
        best_score = 0.0

        for itype, keywords in TYPE_INDICATORS.items():
            hits = sum(1 for k in keywords if k in text)
            score = hits / len(keywords) if keywords else 0
            if score > best_score:
                best_score = score
                best_type = itype

        severity = incident.get("severity", "medium")
        confidence = min(best_score * 2, 1.0)

        indicators = [k for k in TYPE_INDICATORS.get(best_type, []) if k in text]

        logger.info(
            "ir_playbook.classified",
            incident_type=best_type.value,
            confidence=confidence,
        )

        return IncidentClassification(
            id=f"cls-{uuid4().hex[:12]}",
            incident_id=incident.get("id", ""),
            incident_type=best_type,
            severity=severity,
            confidence=confidence,
            indicators=indicators,
            reasoning=(f"Matched {len(indicators)} indicators for {best_type.value}"),
        )

    async def select_playbook(
        self,
        classification: IncidentClassification,
    ) -> PlaybookSelection:
        """Select the best playbook for the incident."""
        template = PLAYBOOK_TEMPLATES.get(
            classification.incident_type,
            PLAYBOOK_TEMPLATES[IncidentType.MALWARE],
        )

        auto_steps = sum(1 for s in template["steps"] if s["auto"])
        total = len(template["steps"])
        if auto_steps == total:
            level = "fully_automated"
        elif auto_steps > 0:
            level = "semi_automated"
        else:
            level = "manual"

        logger.info(
            "ir_playbook.selected",
            playbook=template["name"],
            automation=level,
        )

        return PlaybookSelection(
            id=f"pb-{uuid4().hex[:12]}",
            playbook_name=template["name"],
            incident_type=classification.incident_type,
            steps=template["steps"],
            estimated_duration_min=template["duration"],
            automation_level=level,
            selection_reason=(
                f"Best match for "
                f"{classification.incident_type.value} "
                f"with confidence "
                f"{classification.confidence:.2f}"
            ),
        )

    async def execute_step(
        self,
        step: dict[str, Any],
        index: int,
    ) -> StepExecution:
        """Execute a single playbook step."""
        start = time.time()
        name = step.get("name", f"step_{index}")
        automated = step.get("auto", False)

        # Simulate execution
        status = "completed"
        output = f"Step '{name}' executed successfully"
        error = ""

        if self._infra_client is not None:
            try:
                result = await self._infra_client.execute(name)
                output = str(result)
            except Exception as exc:
                status = "failed"
                error = str(exc)

        elapsed = int((time.time() - start) * 1000)

        logger.info(
            "ir_playbook.step_executed",
            step=name,
            status=status,
            duration_ms=elapsed,
        )

        return StepExecution(
            id=f"step-{uuid4().hex[:12]}",
            step_index=index,
            step_name=name,
            status=status,
            output=output,
            duration_ms=elapsed,
            automated=automated,
            error=error,
        )

    async def validate_containment(
        self,
        classification: IncidentClassification,
        step_results: list[StepExecution],
    ) -> list[ContainmentValidation]:
        """Validate containment effectiveness."""
        checks: list[ContainmentValidation] = []
        now = time.time()

        completed = sum(1 for s in step_results if s.status == "completed")
        total = len(step_results)

        checks.append(
            ContainmentValidation(
                id=f"cv-{uuid4().hex[:12]}",
                check_name="steps_completed",
                passed=completed == total,
                evidence=(f"{completed}/{total} steps completed"),
                timestamp=now,
            )
        )

        failed = [s for s in step_results if s.status == "failed"]
        checks.append(
            ContainmentValidation(
                id=f"cv-{uuid4().hex[:12]}",
                check_name="no_failures",
                passed=len(failed) == 0,
                evidence=(f"{len(failed)} steps failed" if failed else "No failures"),
                timestamp=now,
            )
        )

        checks.append(
            ContainmentValidation(
                id=f"cv-{uuid4().hex[:12]}",
                check_name="threat_contained",
                passed=completed >= total * 0.8,
                evidence=(f"Completion rate: {completed / max(total, 1) * 100:.0f}%"),
                timestamp=now,
            )
        )

        logger.info(
            "ir_playbook.containment_validated",
            checks=len(checks),
            all_passed=all(c.passed for c in checks),
        )

        return checks
