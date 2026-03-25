"""Tool functions for the Attack Campaign Agent.

Provides campaign planning, simulation execution, result collection,
defense assessment, and reporting capabilities — all respecting
OPA policies and blast-radius limits.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.attack_campaign.models import (
    AttackPhase,
    CampaignResult,
    DefenseAssessment,
    SimulationMode,
    SimulationStep,
    TTPSelection,
)

logger = structlog.get_logger()

# ── MITRE ATT&CK technique catalogue (representative subset) ──────────────

MITRE_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1595": {
        "name": "Active Scanning",
        "tactic": AttackPhase.RECONNAISSANCE,
        "severity": "low",
        "platform": ["linux", "windows", "macos", "cloud"],
        "data_sources": ["network_traffic", "cloud_audit_logs"],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": AttackPhase.INITIAL_ACCESS,
        "severity": "critical",
        "platform": ["linux", "windows", "cloud", "kubernetes"],
        "data_sources": ["application_log", "network_traffic", "waf_logs"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": AttackPhase.EXECUTION,
        "severity": "high",
        "platform": ["linux", "windows", "macos"],
        "data_sources": ["process_creation", "command_execution", "script_logs"],
    },
    "T1136": {
        "name": "Create Account",
        "tactic": AttackPhase.PERSISTENCE,
        "severity": "high",
        "platform": ["linux", "windows", "cloud", "azure_ad"],
        "data_sources": ["user_account_creation", "cloud_audit_logs"],
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": AttackPhase.PRIVILEGE_ESCALATION,
        "severity": "critical",
        "platform": ["linux", "windows", "kubernetes"],
        "data_sources": ["process_creation", "system_calls", "kernel_logs"],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": AttackPhase.LATERAL_MOVEMENT,
        "severity": "high",
        "platform": ["linux", "windows", "cloud"],
        "data_sources": ["authentication_logs", "network_flow", "rdp_logs"],
    },
    "T1119": {
        "name": "Automated Collection",
        "tactic": AttackPhase.COLLECTION,
        "severity": "medium",
        "platform": ["linux", "windows", "cloud"],
        "data_sources": ["file_access", "api_calls", "database_logs"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": AttackPhase.EXFILTRATION,
        "severity": "critical",
        "platform": ["linux", "windows", "cloud"],
        "data_sources": ["network_traffic", "dns_logs", "firewall_logs"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": AttackPhase.IMPACT,
        "severity": "critical",
        "platform": ["linux", "windows"],
        "data_sources": ["file_modification", "process_creation", "backup_logs"],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": AttackPhase.INITIAL_ACCESS,
        "severity": "high",
        "platform": ["linux", "windows", "cloud", "azure_ad"],
        "data_sources": ["authentication_logs", "account_lockout"],
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": AttackPhase.RECONNAISSANCE,
        "severity": "low",
        "platform": ["linux", "windows", "cloud"],
        "data_sources": ["network_traffic", "host_firewall_logs"],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": AttackPhase.PERSISTENCE,
        "severity": "medium",
        "platform": ["linux", "windows", "kubernetes"],
        "data_sources": ["scheduled_tasks", "cron_logs", "process_creation"],
    },
}

# Maximum number of simulation steps per campaign (blast-radius limit)
MAX_SIMULATION_STEPS = 50


class AttackCampaignToolkit:
    """Collection of tools for orchestrating attack campaign simulations."""

    def __init__(
        self,
        mitre_client: Any | None = None,
        simulation_engine: Any | None = None,
        defense_monitor: Any | None = None,
    ) -> None:
        self._mitre_client = mitre_client
        self._simulation_engine = simulation_engine
        self._defense_monitor = defense_monitor

    async def plan_campaign(
        self,
        target_scope: dict[str, Any],
        mode: SimulationMode,
    ) -> list[TTPSelection]:
        """Select relevant TTPs based on the target environment.

        Filters the MITRE catalogue by platform overlap with the target scope
        and the simulation mode's severity constraints.
        """
        target_platforms = target_scope.get("platforms", ["linux", "cloud"])
        target_phases = target_scope.get(
            "phases",
            [p.value for p in AttackPhase],
        )
        max_severity = target_scope.get("max_severity", "critical")

        severity_order = ["low", "medium", "high", "critical"]
        max_sev_idx = severity_order.index(max_severity)

        # In DRY_RUN/READ_ONLY, cap at high severity
        if mode in (SimulationMode.DRY_RUN, SimulationMode.READ_ONLY):
            max_sev_idx = min(max_sev_idx, severity_order.index("high"))

        logger.info(
            "attack_campaign.planning",
            target_platforms=target_platforms,
            phases=target_phases,
            mode=mode,
        )

        selections: list[TTPSelection] = []
        for tech_id, meta in MITRE_TECHNIQUES.items():
            # Platform filter
            if not any(p in meta["platform"] for p in target_platforms):
                continue
            # Phase filter
            raw_tactic = meta["tactic"]
            tactic_val = raw_tactic.value if isinstance(raw_tactic, AttackPhase) else raw_tactic
            if tactic_val not in target_phases:
                continue
            # Severity filter
            sev_idx = severity_order.index(meta["severity"])
            if sev_idx > max_sev_idx:
                continue

            selections.append(
                TTPSelection(
                    id=f"ttp-{uuid4().hex[:8]}",
                    technique_id=tech_id,
                    technique_name=meta["name"],
                    tactic=tactic_val,
                    description=f"Simulate {meta['name']} ({tech_id})",
                    severity=meta["severity"],
                    platform=meta["platform"],
                    data_sources=meta["data_sources"],
                )
            )

        logger.info("attack_campaign.plan_ready", ttp_count=len(selections))
        return selections

    async def execute_simulation_step(
        self,
        ttp: TTPSelection,
        target: str,
        mode: SimulationMode,
        campaign_id: str = "",
    ) -> SimulationStep:
        """Execute a single simulation step, respecting the simulation mode.

        - DRY_RUN: plans the step but does not execute; always returns success=False.
        - READ_ONLY: reads telemetry/configs but does not mutate anything.
        - CONTROLLED: executes with automatic rollback.
        - FULL: executes without automatic rollback (requires explicit approval).
        """
        step_id = f"step-{uuid4().hex[:8]}"
        start = datetime.now(UTC)

        logger.info(
            "attack_campaign.executing_step",
            step_id=step_id,
            ttp=ttp.technique_id,
            target=target,
            mode=mode,
        )

        # --- mode-gated execution ---
        if mode == SimulationMode.DRY_RUN:
            result = "planned_only"
            success = False
            blocked_by = ""
        elif mode == SimulationMode.READ_ONLY:
            result = "read_telemetry"
            success = False
            blocked_by = "read_only_mode"
        elif mode == SimulationMode.CONTROLLED:
            # Simulate controlled execution with rollback
            result = "executed_with_rollback"
            success = ttp.severity in ("low", "medium")
            blocked_by = "defense_policy" if not success else ""
        else:
            # FULL mode
            result = "executed"
            success = ttp.severity in ("low", "medium")
            blocked_by = "defense_layer" if not success else ""

        elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000) + 50

        return SimulationStep(
            id=step_id,
            campaign_id=campaign_id,
            ttp_id=ttp.technique_id,
            phase=ttp.tactic,
            action=f"simulate_{ttp.technique_name.lower().replace(' ', '_')}",
            target=target,
            result=result,
            success=success,
            blocked_by=blocked_by,
            duration_ms=elapsed,
            timestamp=datetime.now(UTC),
        )

    async def collect_step_results(
        self,
        steps: list[SimulationStep],
    ) -> list[SimulationStep]:
        """Aggregate and enrich results from executed simulation steps."""
        logger.info("attack_campaign.collecting_results", step_count=len(steps))
        # In a production implementation this would query the defense monitor
        # for real telemetry.  For now, return the steps as-is.
        return steps

    async def assess_defense_coverage(
        self,
        steps: list[SimulationStep],
    ) -> list[DefenseAssessment]:
        """Evaluate how well defenses detected/blocked each TTP."""
        logger.info("attack_campaign.assessing_defenses", step_count=len(steps))

        assessments: list[DefenseAssessment] = []
        seen_ttps: set[str] = set()

        for step in steps:
            if step.ttp_id in seen_ttps:
                continue
            seen_ttps.add(step.ttp_id)

            blocked = bool(step.blocked_by)
            detection = 0.85 if blocked else 0.35
            prevention = 0.90 if blocked else 0.20

            gaps: list[str] = []
            recommendations: list[str] = []
            if not blocked:
                gaps.append(f"No prevention control for {step.ttp_id}")
                recommendations.append(f"Deploy detection rule for {step.ttp_id} ({step.phase})")
            if step.duration_ms > 2000:
                gaps.append(f"Slow response ({step.duration_ms}ms) for {step.ttp_id}")
                recommendations.append("Tune detection latency for this technique")

            assessments.append(
                DefenseAssessment(
                    id=f"assess-{uuid4().hex[:8]}",
                    ttp_id=step.ttp_id,
                    detection_coverage=detection,
                    prevention_coverage=prevention,
                    response_time_ms=step.duration_ms,
                    gaps=gaps,
                    recommendations=recommendations,
                )
            )

        return assessments

    async def generate_campaign_result(
        self,
        campaign_id: str,
        name: str,
        steps: list[SimulationStep],
        assessments: list[DefenseAssessment],
    ) -> CampaignResult:
        """Compute overall campaign metrics from steps and assessments."""
        total = len(steps)
        blocked = sum(1 for s in steps if s.blocked_by)
        succeeded = sum(1 for s in steps if s.success)
        detection_times = [a.response_time_ms for a in assessments if a.response_time_ms > 0]
        mean_dt = sum(detection_times) / len(detection_times) if detection_times else 0.0

        # Build MITRE coverage map (tactic → list of technique results)
        coverage: dict[str, Any] = {}
        for step in steps:
            phase = step.phase
            if phase not in coverage:
                coverage[phase] = {"tested": 0, "blocked": 0}
            coverage[phase]["tested"] += 1
            if step.blocked_by:
                coverage[phase]["blocked"] += 1

        detection_rate = (blocked / total) if total else 0.0
        prevention_rate = (blocked / total) if total else 0.0

        logger.info(
            "attack_campaign.result_generated",
            campaign_id=campaign_id,
            total=total,
            blocked=blocked,
            succeeded=succeeded,
        )

        return CampaignResult(
            id=campaign_id,
            campaign_name=name,
            total_steps=total,
            steps_blocked=blocked,
            steps_succeeded=succeeded,
            detection_rate=round(detection_rate, 4),
            prevention_rate=round(prevention_rate, 4),
            mean_detection_time_ms=round(mean_dt, 2),
            mitre_coverage=coverage,
        )
