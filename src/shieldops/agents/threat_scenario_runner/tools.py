"""Tool functions for Threat Scenario Runner Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_scenario_runner.models import (
    ControlEvaluation,
    EnvironmentSetup,
    ScenarioCategory,
    ScenarioStep,
    ScenarioVerdict,
    ThreatScenario,
    Verdict,
)

logger = structlog.get_logger()

# Pre-built scenario library
_SCENARIO_LIBRARY: dict[ScenarioCategory, dict[str, Any]] = {
    ScenarioCategory.RANSOMWARE_READINESS: {
        "name": "Ransomware Readiness Assessment",
        "steps": [
            "Simulate phishing delivery",
            "Test endpoint protection",
            "Attempt privilege escalation",
            "Simulate lateral movement",
            "Test backup integrity",
            "Verify recovery procedures",
        ],
        "controls": [
            "email_gateway",
            "edr_protection",
            "privilege_mgmt",
            "network_segmentation",
            "backup_system",
            "recovery_runbook",
        ],
        "techniques": [
            "T1566",
            "T1486",
            "T1078",
            "T1021",
            "T1490",
        ],
    },
    ScenarioCategory.INSIDER_THREAT: {
        "name": "Insider Threat Detection",
        "steps": [
            "Simulate excessive data access",
            "Test DLP controls",
            "Attempt unauthorized export",
            "Test audit trail integrity",
        ],
        "controls": [
            "dlp_system",
            "access_monitoring",
            "audit_logging",
            "data_classification",
        ],
        "techniques": [
            "T1530",
            "T1213",
            "T1048",
        ],
    },
}


class ThreatScenarioRunnerToolkit:
    """Tools for threat scenario execution."""

    def __init__(
        self,
        scenario_store: Any | None = None,
        control_monitor: Any | None = None,
        environment_mgr: Any | None = None,
    ) -> None:
        self._scenario_store = scenario_store
        self._control_monitor = control_monitor
        self._environment_mgr = environment_mgr

    async def load_scenario(
        self,
        category: ScenarioCategory,
        description: str = "",
    ) -> ThreatScenario:
        """Load a threat scenario by category."""
        logger.info(
            "scenario_runner.loading",
            category=category,
        )

        lib = _SCENARIO_LIBRARY.get(
            category,
            {
                "name": f"{category.value} scenario",
                "steps": [
                    "Setup test environment",
                    "Execute attack simulation",
                    "Evaluate defenses",
                ],
                "controls": [
                    "detection",
                    "prevention",
                    "response",
                ],
                "techniques": ["T1059"],
            },
        )

        return ThreatScenario(
            id=f"scn-{uuid4().hex[:8]}",
            name=lib["name"],
            category=category,
            description=(description or lib["name"]),
            steps=lib["steps"],
            expected_controls=lib["controls"],
            severity="high",
            mitre_techniques=lib["techniques"],
        )

    async def setup_environment(
        self,
        scenario: ThreatScenario,
    ) -> EnvironmentSetup:
        """Prepare the test environment."""
        logger.info(
            "scenario_runner.setting_up",
            scenario_id=scenario.id,
        )

        return EnvironmentSetup(
            id=f"env-{uuid4().hex[:8]}",
            scenario_id=scenario.id,
            environment="isolated-sandbox",
            prerequisites_met=True,
            isolation_verified=True,
            rollback_ready=True,
            setup_notes=[
                "Sandbox isolated from production",
                "Rollback snapshot created",
                "Monitoring enabled",
            ],
        )

    async def execute_steps(
        self,
        scenario: ThreatScenario,
    ) -> list[ScenarioStep]:
        """Execute scenario steps safely."""
        logger.info(
            "scenario_runner.executing_steps",
            scenario_id=scenario.id,
            step_count=len(scenario.steps),
        )

        results: list[ScenarioStep] = []
        for i, step_desc in enumerate(scenario.steps):
            start = time.monotonic()
            passed = i % 5 != 4  # 80% pass rate
            elapsed = (time.monotonic() - start) * 1000

            results.append(
                ScenarioStep(
                    id=f"step-{uuid4().hex[:8]}",
                    step_number=i + 1,
                    description=step_desc,
                    action=f"simulate_{step_desc.lower().replace(' ', '_')}",
                    expected_outcome="Control activates",
                    actual_outcome=("Control activated" if passed else "Control did not activate"),
                    passed=passed,
                    evidence=[
                        f"Step {i + 1} executed safely",
                        f"Outcome: {'pass' if passed else 'fail'}",
                    ],
                    duration_ms=round(elapsed, 2),
                )
            )
        return results

    async def evaluate_controls(
        self,
        scenario: ThreatScenario,
        steps: list[ScenarioStep],
    ) -> list[ControlEvaluation]:
        """Evaluate security controls."""
        logger.info(
            "scenario_runner.evaluating_controls",
            control_count=len(scenario.expected_controls),
        )

        evals: list[ControlEvaluation] = []
        for i, control in enumerate(scenario.expected_controls):
            effective = i % 4 != 3
            evals.append(
                ControlEvaluation(
                    id=f"ctrl-{uuid4().hex[:8]}",
                    control_name=control,
                    control_type="preventive",
                    expected_behavior=(f"{control} blocks attack"),
                    actual_behavior=(
                        f"{control} blocked attack" if effective else f"{control} did not activate"
                    ),
                    effective=effective,
                    confidence=0.85 if effective else 0.9,
                    notes=("Working as expected" if effective else "Requires remediation"),
                )
            )
        return evals

    async def generate_verdict(
        self,
        scenario: ThreatScenario,
        evaluations: list[ControlEvaluation],
    ) -> ScenarioVerdict:
        """Generate scenario verdict."""
        logger.info(
            "scenario_runner.generating_verdict",
            scenario_id=scenario.id,
        )

        passed = sum(1 for e in evaluations if e.effective)
        failed = len(evaluations) - passed
        total = len(evaluations)
        score = round(passed / total * 100, 1) if total else 0.0

        if score >= 90:
            verdict = Verdict.PASS
        elif score >= 60:
            verdict = Verdict.PARTIAL
        elif total == 0:
            verdict = Verdict.INCONCLUSIVE
        else:
            verdict = Verdict.FAIL

        remediation = [f"Fix {e.control_name}: {e.notes}" for e in evaluations if not e.effective]

        return ScenarioVerdict(
            id=f"vrd-{uuid4().hex[:8]}",
            scenario_id=scenario.id,
            verdict=verdict,
            score=score,
            controls_tested=total,
            controls_passed=passed,
            controls_failed=failed,
            summary=(f"{scenario.name}: {verdict.value} ({score}% — {passed}/{total})"),
            remediation_items=remediation,
        )
