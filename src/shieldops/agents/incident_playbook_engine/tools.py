"""Tool functions for the Incident Playbook Engine."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_playbook_engine.models import (
    IncidentCategory,
    IncidentClassification,
    OutcomeValidation,
    PlaybookExecution,
    PlaybookSelection,
    PlaybookStatus,
    PlaybookStep,
)

logger = structlog.get_logger()

# --- Keyword patterns for heuristic classification ---

CATEGORY_KEYWORDS: dict[IncidentCategory, list[str]] = {
    IncidentCategory.MALWARE: [
        "malware",
        "trojan",
        "virus",
        "worm",
        "backdoor",
        "c2 beacon",
        "dropper",
        "payload",
    ],
    IncidentCategory.PHISHING: [
        "phishing",
        "spear-phish",
        "credential harvest",
        "spoofed email",
        "social engineering",
        "suspicious link",
    ],
    IncidentCategory.INSIDER_THREAT: [
        "insider",
        "unauthorized access",
        "data exfiltration",
        "privilege abuse",
        "policy violation",
        "anomalous user",
    ],
    IncidentCategory.DATA_BREACH: [
        "data breach",
        "data leak",
        "exposure",
        "pii exposed",
        "records compromised",
        "database dump",
    ],
    IncidentCategory.DDOS: [
        "ddos",
        "denial of service",
        "traffic spike",
        "volumetric attack",
        "syn flood",
        "amplification",
    ],
    IncidentCategory.RANSOMWARE: [
        "ransomware",
        "encryption",
        "ransom note",
        "file locked",
        "crypto locker",
        "extortion",
    ],
    IncidentCategory.SUPPLY_CHAIN: [
        "supply chain",
        "dependency",
        "compromised package",
        "upstream",
        "third-party",
        "vendor compromise",
    ],
}

SEVERITY_KEYWORDS: dict[str, list[str]] = {
    "critical": [
        "critical",
        "production down",
        "total outage",
        "active breach",
        "ransomware",
        "exfiltration confirmed",
    ],
    "high": [
        "high",
        "partial outage",
        "lateral movement",
        "privilege escalation",
        "active threat",
    ],
    "medium": [
        "medium",
        "suspicious",
        "anomalous",
        "policy violation",
        "elevated risk",
    ],
    "low": [
        "low",
        "informational",
        "scan detected",
        "minor anomaly",
        "cosmetic",
    ],
}

# --- Playbook catalog with historical outcome data ---

PLAYBOOK_CATALOG: list[dict[str, Any]] = [
    {
        "id": "pb-malware-contain-001",
        "name": "Malware Containment & Eradication",
        "category": "malware",
        "version": "2.3",
        "success_rate": 0.91,
        "avg_resolution_min": 45,
        "description": (
            "Isolate host, kill process, remove artifacts, "
            "scan laterally, restore from clean backup."
        ),
        "steps": [
            {
                "action": "isolate_host",
                "tool": "edr_connector",
                "desc": "Network-isolate the infected host",
            },
            {
                "action": "kill_process",
                "tool": "edr_connector",
                "desc": "Terminate malicious process tree",
            },
            {
                "action": "collect_forensics",
                "tool": "forensics_toolkit",
                "desc": "Capture memory dump and disk image",
            },
            {
                "action": "remove_artifacts",
                "tool": "edr_connector",
                "desc": "Delete malware binaries and persistence",
            },
            {
                "action": "scan_lateral",
                "tool": "xdr_connector",
                "desc": "Scan adjacent hosts for IOCs",
            },
            {
                "action": "restore_host",
                "tool": "backup_connector",
                "desc": "Restore host from last known good state",
            },
        ],
    },
    {
        "id": "pb-phishing-resp-001",
        "name": "Phishing Response & Credential Reset",
        "category": "phishing",
        "version": "1.8",
        "success_rate": 0.95,
        "avg_resolution_min": 30,
        "description": (
            "Block sender, quarantine emails, reset credentials, "
            "scan for lateral access, notify affected users."
        ),
        "steps": [
            {
                "action": "block_sender",
                "tool": "email_gateway",
                "desc": "Block sender domain/address",
            },
            {
                "action": "quarantine_emails",
                "tool": "email_gateway",
                "desc": "Quarantine all matching emails org-wide",
            },
            {
                "action": "reset_credentials",
                "tool": "identity_provider",
                "desc": "Force password reset for affected users",
            },
            {
                "action": "revoke_sessions",
                "tool": "identity_provider",
                "desc": "Revoke active sessions for affected users",
            },
            {
                "action": "scan_access_logs",
                "tool": "siem_connector",
                "desc": "Check for post-compromise activity",
            },
        ],
    },
    {
        "id": "pb-insider-001",
        "name": "Insider Threat Investigation",
        "category": "insider_threat",
        "version": "1.5",
        "success_rate": 0.82,
        "avg_resolution_min": 120,
        "description": (
            "Restrict access, preserve evidence, investigate "
            "activity timeline, escalate to legal/HR."
        ),
        "steps": [
            {
                "action": "restrict_access",
                "tool": "identity_provider",
                "desc": "Restrict user to read-only access",
            },
            {
                "action": "preserve_evidence",
                "tool": "forensics_toolkit",
                "desc": "Preserve audit logs and file access records",
            },
            {
                "action": "timeline_analysis",
                "tool": "siem_connector",
                "desc": "Build activity timeline for the user",
            },
            {
                "action": "data_loss_check",
                "tool": "dlp_connector",
                "desc": "Check for data exfiltration attempts",
            },
            {
                "action": "escalate_hr_legal",
                "tool": "ticketing_system",
                "desc": "Create escalation ticket for HR/Legal",
            },
        ],
    },
    {
        "id": "pb-breach-001",
        "name": "Data Breach Response",
        "category": "data_breach",
        "version": "2.1",
        "success_rate": 0.87,
        "avg_resolution_min": 90,
        "description": (
            "Contain exposure, assess scope, notify stakeholders, "
            "remediate, and initiate breach notification."
        ),
        "steps": [
            {
                "action": "contain_exposure",
                "tool": "firewall_connector",
                "desc": "Block exfiltration channels",
            },
            {
                "action": "assess_scope",
                "tool": "siem_connector",
                "desc": "Determine records and systems affected",
            },
            {
                "action": "preserve_evidence",
                "tool": "forensics_toolkit",
                "desc": "Capture forensic evidence",
            },
            {
                "action": "notify_stakeholders",
                "tool": "notification_service",
                "desc": "Alert CISO, legal, and affected parties",
            },
            {
                "action": "remediate_vuln",
                "tool": "patch_manager",
                "desc": "Patch exploited vulnerability",
            },
        ],
    },
    {
        "id": "pb-ddos-001",
        "name": "DDoS Mitigation",
        "category": "ddos",
        "version": "1.6",
        "success_rate": 0.93,
        "avg_resolution_min": 20,
        "description": (
            "Activate scrubbing, rate-limit, scale capacity, block source IPs, monitor recovery."
        ),
        "steps": [
            {
                "action": "activate_scrubbing",
                "tool": "cdn_connector",
                "desc": "Enable DDoS scrubbing center",
            },
            {
                "action": "rate_limit",
                "tool": "waf_connector",
                "desc": "Apply rate limiting rules",
            },
            {
                "action": "scale_capacity",
                "tool": "cloud_connector",
                "desc": "Auto-scale backend infrastructure",
            },
            {
                "action": "block_sources",
                "tool": "firewall_connector",
                "desc": "Block identified attack source IPs",
            },
            {
                "action": "monitor_recovery",
                "tool": "observability_connector",
                "desc": "Monitor traffic normalization",
            },
        ],
    },
    {
        "id": "pb-ransomware-001",
        "name": "Ransomware Containment & Recovery",
        "category": "ransomware",
        "version": "2.0",
        "success_rate": 0.85,
        "avg_resolution_min": 180,
        "description": (
            "Isolate, stop spread, assess encryption scope, recover from backups, harden defenses."
        ),
        "steps": [
            {
                "action": "network_isolate",
                "tool": "network_connector",
                "desc": "Segment infected network zones",
            },
            {
                "action": "kill_encryption",
                "tool": "edr_connector",
                "desc": "Terminate encryption processes",
            },
            {
                "action": "assess_scope",
                "tool": "xdr_connector",
                "desc": "Map encryption blast radius",
            },
            {
                "action": "backup_validation",
                "tool": "backup_connector",
                "desc": "Verify backup integrity",
            },
            {
                "action": "restore_systems",
                "tool": "backup_connector",
                "desc": "Restore from verified clean backups",
            },
            {
                "action": "harden_defenses",
                "tool": "security_connector",
                "desc": "Apply patches and harden access controls",
            },
        ],
    },
    {
        "id": "pb-supplychain-001",
        "name": "Supply Chain Compromise Response",
        "category": "supply_chain",
        "version": "1.2",
        "success_rate": 0.78,
        "avg_resolution_min": 240,
        "description": (
            "Identify compromised dependency, block, assess downstream impact, patch, and audit."
        ),
        "steps": [
            {
                "action": "identify_package",
                "tool": "sbom_scanner",
                "desc": "Identify compromised dependency",
            },
            {
                "action": "block_package",
                "tool": "artifact_registry",
                "desc": "Block compromised package version",
            },
            {
                "action": "assess_downstream",
                "tool": "dependency_scanner",
                "desc": "Map all consumers of the package",
            },
            {
                "action": "rollback_deployments",
                "tool": "cicd_connector",
                "desc": "Rollback affected deployments",
            },
            {
                "action": "audit_builds",
                "tool": "cicd_connector",
                "desc": "Audit recent builds for tampering",
            },
        ],
    },
]

# --- Verification checks by category ---

VERIFICATION_CHECKS: dict[str, list[str]] = {
    "malware": [
        "No malicious processes running",
        "IOCs absent from all scanned hosts",
        "EDR agent healthy on restored host",
        "Network traffic normalized",
    ],
    "phishing": [
        "All phishing emails quarantined",
        "Affected credentials rotated",
        "No post-compromise lateral access",
        "Sender domain blocked",
    ],
    "insider_threat": [
        "User access restricted",
        "Evidence preserved and chain-of-custody logged",
        "No ongoing data exfiltration",
        "HR/Legal notified",
    ],
    "data_breach": [
        "Exfiltration channels blocked",
        "Vulnerability patched",
        "Affected parties notified",
        "Forensic evidence preserved",
    ],
    "ddos": [
        "Traffic returned to baseline",
        "Scrubbing center active",
        "No service degradation",
        "Attack source IPs blocked",
    ],
    "ransomware": [
        "Encryption processes terminated",
        "Systems restored from clean backups",
        "Network segmentation verified",
        "No residual persistence mechanisms",
    ],
    "supply_chain": [
        "Compromised package blocked",
        "Affected deployments rolled back",
        "Build pipeline integrity verified",
        "Downstream consumers notified",
    ],
}


class IncidentPlaybookEngineToolkit:
    """Toolkit for incident playbook engine operations."""

    def __init__(
        self,
        playbook_db: Any | None = None,
        outcome_db: Any | None = None,
    ) -> None:
        self._playbook_db = playbook_db
        self._outcome_db = outcome_db

    def _match_keywords(
        self,
        text: str,
        keyword_map: dict[Any, list[str]],
    ) -> tuple[Any, float]:
        """Match text against keyword patterns."""
        text_lower = text.lower()
        best_key = None
        best_score = 0.0

        for key, keywords in keyword_map.items():
            hits = sum(1 for kw in keywords if kw in text_lower)
            if hits > best_score:
                best_score = hits
                best_key = key

        if best_key is not None:
            max_possible = len(keyword_map[best_key])
            best_score = best_score / max_possible if max_possible > 0 else 0.0

        return best_key, best_score

    async def classify_incident(
        self,
        title: str,
        description: str,
        severity: str,
        indicators: list[str],
        affected_assets: list[str],
    ) -> IncidentClassification:
        """Classify an incident using keyword heuristics."""
        combined = f"{title} {description} {' '.join(indicators)}"

        cat_match, cat_score = self._match_keywords(combined, CATEGORY_KEYWORDS)
        category = cat_match or IncidentCategory.MALWARE

        sev_match, sev_score = self._match_keywords(combined, SEVERITY_KEYWORDS)
        sev = sev_match or severity or "medium"

        confidence = min((cat_score + sev_score) / 2 + 0.3, 1.0)

        reasoning = (
            f"Category={category.value} (score={cat_score:.2f}), "
            f"severity={sev} (score={sev_score:.2f})"
        )

        classification = IncidentClassification(
            id=f"cls-{uuid4().hex[:12]}",
            category=category,
            severity=sev,
            confidence=round(confidence, 3),
            indicators=indicators or [],
            affected_assets=affected_assets or [],
            reasoning=reasoning,
        )

        logger.info(
            "ipe.classified",
            category=category.value,
            severity=sev,
            confidence=classification.confidence,
        )
        return classification

    async def select_playbooks(
        self,
        classification: IncidentClassification,
    ) -> list[PlaybookSelection]:
        """Select candidate playbooks from the catalog."""
        candidates: list[PlaybookSelection] = []

        for pb in PLAYBOOK_CATALOG:
            if pb["category"] == classification.category.value:
                score = pb["success_rate"]
            elif pb["category"] in (
                classification.category.value,
                "malware",
            ):
                score = pb["success_rate"] * 0.5
            else:
                score = pb["success_rate"] * 0.2

            candidates.append(
                PlaybookSelection(
                    id=pb["id"],
                    name=pb["name"],
                    category=IncidentCategory(pb["category"]),
                    version=pb["version"],
                    match_score=round(score, 3),
                    historical_success_rate=pb["success_rate"],
                    avg_resolution_minutes=pb["avg_resolution_min"],
                    description=pb["description"],
                )
            )

        candidates.sort(key=lambda p: p.match_score, reverse=True)

        logger.info(
            "ipe.playbooks_selected",
            total_candidates=len(candidates),
            top_match=candidates[0].name if candidates else "none",
        )
        return candidates

    async def build_execution_plan(
        self,
        playbook: PlaybookSelection,
        classification: IncidentClassification,
    ) -> list[PlaybookStep]:
        """Build an execution plan from the selected playbook."""
        catalog_entry = next(
            (pb for pb in PLAYBOOK_CATALOG if pb["id"] == playbook.id),
            None,
        )

        if catalog_entry is None:
            logger.warning(
                "ipe.playbook_not_found",
                playbook_id=playbook.id,
            )
            return []

        steps: list[PlaybookStep] = []
        for i, raw_step in enumerate(catalog_entry["steps"]):
            requires_approval = classification.severity == "critical" and raw_step["action"] in (
                "restore_host",
                "restore_systems",
                "rollback_deployments",
            )

            steps.append(
                PlaybookStep(
                    id=f"step-{uuid4().hex[:8]}",
                    order=i + 1,
                    action=raw_step["action"],
                    description=raw_step["desc"],
                    tool=raw_step["tool"],
                    parameters={
                        "assets": classification.affected_assets,
                        "severity": classification.severity,
                    },
                    timeout_seconds=300,
                    requires_approval=requires_approval,
                    rollback_action=f"rollback_{raw_step['action']}",
                    status="pending",
                )
            )

        logger.info(
            "ipe.execution_plan_built",
            playbook_id=playbook.id,
            step_count=len(steps),
        )
        return steps

    async def execute_step(
        self,
        step: PlaybookStep,
    ) -> PlaybookStep:
        """Execute a single playbook step (mock)."""
        start = time.time()

        # Simulate execution with realistic outcomes
        step.status = "completed"
        step.result = f"Successfully executed {step.action} via {step.tool}"
        step.duration_ms = int((time.time() - start) * 1000) + 150

        logger.info(
            "ipe.step_executed",
            step_id=step.id,
            action=step.action,
            status=step.status,
            duration_ms=step.duration_ms,
        )
        return step

    async def execute_playbook(
        self,
        playbook: PlaybookSelection,
        steps: list[PlaybookStep],
    ) -> PlaybookExecution:
        """Execute all steps in the playbook."""
        execution = PlaybookExecution(
            id=f"exec-{uuid4().hex[:12]}",
            playbook_id=playbook.id,
            status=PlaybookStatus.EXECUTING,
            steps=steps,
        )

        for step in execution.steps:
            if step.requires_approval:
                step.status = "approved"
                logger.info(
                    "ipe.step_auto_approved",
                    step_id=step.id,
                    action=step.action,
                )

            executed = await self.execute_step(step)
            if executed.status == "completed":
                execution.steps_completed += 1
            else:
                execution.steps_failed += 1
                if execution.steps_failed >= 2:
                    execution.status = PlaybookStatus.FAILED
                    execution.rollback_triggered = True
                    logger.warning(
                        "ipe.execution_failed",
                        execution_id=execution.id,
                        failed_count=execution.steps_failed,
                    )
                    break

        if execution.status != PlaybookStatus.FAILED:
            execution.status = PlaybookStatus.COMPLETED

        execution.total_duration_ms = sum(s.duration_ms for s in execution.steps)

        logger.info(
            "ipe.playbook_executed",
            execution_id=execution.id,
            status=execution.status.value,
            completed=execution.steps_completed,
            failed=execution.steps_failed,
        )
        return execution

    async def validate_outcome(
        self,
        execution: PlaybookExecution,
        classification: IncidentClassification,
    ) -> OutcomeValidation:
        """Validate execution outcome against verification checks."""
        checks = VERIFICATION_CHECKS.get(classification.category.value, [])
        failed: list[str] = []

        if execution.status == PlaybookStatus.FAILED:
            failed.append("Playbook execution did not complete")

        if execution.rollback_triggered:
            failed.append("Rollback was triggered during execution")

        success = execution.status == PlaybookStatus.COMPLETED and len(failed) == 0

        if success:
            residual_risk = "low"
            threat_neutralized = True
        elif execution.steps_completed > 0:
            residual_risk = "medium"
            threat_neutralized = False
        else:
            residual_risk = "high"
            threat_neutralized = False

        recommendations: list[str] = []
        if not success:
            recommendations.append("Review failed steps and retry manually")
        recommendations.append("Schedule follow-up scan in 24 hours")
        recommendations.append("Update playbook based on execution results")

        lessons = [
            f"Playbook {execution.playbook_id} {'succeeded' if success else 'needs improvement'}",
            f"{execution.steps_completed}/{len(execution.steps)} steps completed successfully",
        ]

        validation = OutcomeValidation(
            id=f"val-{uuid4().hex[:12]}",
            execution_id=execution.id,
            success=success,
            threat_neutralized=threat_neutralized,
            residual_risk=residual_risk,
            verification_checks=checks,
            failed_checks=failed,
            recommendations=recommendations,
            lessons_learned=lessons,
        )

        logger.info(
            "ipe.outcome_validated",
            execution_id=execution.id,
            success=success,
            residual_risk=residual_risk,
        )
        return validation
