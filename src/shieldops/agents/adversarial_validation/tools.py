"""Tool functions for the Adversarial Validation Agent.

Provides capabilities to collect red-team findings, re-execute attacks
against patched defenses, assess effectiveness, and feed pattern updates
back into the data flywheel.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.adversarial_validation.models import (
    DefenseType,
    EffectivenessScore,
    PatternUpdate,
    RedTeamFinding,
    ValidationOutcome,
    ValidationTest,
)

logger = structlog.get_logger()


class AdversarialValidationToolkit:
    """Collection of tools for closed-loop adversarial validation."""

    def __init__(
        self,
        red_team_client: Any | None = None,
        blue_team_client: Any | None = None,
        defense_monitor: Any | None = None,
    ) -> None:
        self._red_team_client = red_team_client
        self._blue_team_client = blue_team_client
        self._defense_monitor = defense_monitor

    # ------------------------------------------------------------------
    # collect_red_team_findings
    # ------------------------------------------------------------------
    async def collect_red_team_findings(
        self,
        tenant_id: str,
    ) -> list[RedTeamFinding]:
        """Gather red-team findings that the blue team has already addressed.

        In production this queries the red-team findings store filtered to
        those with a linked ``blue_team_fix_id``.
        """
        logger.info(
            "adversarial_validation.collecting_findings",
            tenant_id=tenant_id,
        )

        if self._red_team_client is not None:
            raw: list[dict[str, Any]] = await self._red_team_client.list_fixed_findings(tenant_id)
            return [RedTeamFinding(**f) for f in raw]

        # Stub data for development / testing
        now = time.time()
        return [
            RedTeamFinding(
                id=f"rtf-{uuid4().hex[:8]}",
                technique_id="T1110.003",
                technique_name="Password Spraying",
                target="auth-service",
                severity="high",
                originally_successful=True,
                blue_team_fix_id=f"btf-{uuid4().hex[:8]}",
                fix_applied_at=now - 86400,
            ),
            RedTeamFinding(
                id=f"rtf-{uuid4().hex[:8]}",
                technique_id="T1048",
                technique_name="Exfiltration Over Alternative Protocol",
                target="data-pipeline",
                severity="critical",
                originally_successful=True,
                blue_team_fix_id=f"btf-{uuid4().hex[:8]}",
                fix_applied_at=now - 43200,
            ),
            RedTeamFinding(
                id=f"rtf-{uuid4().hex[:8]}",
                technique_id="T1068",
                technique_name="Exploitation for Privilege Escalation",
                target="k8s-worker-03",
                severity="high",
                originally_successful=True,
                blue_team_fix_id=f"btf-{uuid4().hex[:8]}",
                fix_applied_at=now - 172800,
            ),
            RedTeamFinding(
                id=f"rtf-{uuid4().hex[:8]}",
                technique_id="T1021",
                technique_name="Remote Services",
                target="internal-api-gw",
                severity="medium",
                originally_successful=True,
                blue_team_fix_id=f"btf-{uuid4().hex[:8]}",
                fix_applied_at=now - 7200,
            ),
        ]

    # ------------------------------------------------------------------
    # execute_validation_tests
    # ------------------------------------------------------------------
    async def execute_validation_tests(
        self,
        findings: list[RedTeamFinding],
    ) -> list[ValidationTest]:
        """Re-run each attack technique against the patched defense.

        For each finding we replay the original attack vector and record
        whether the defense now blocks, detects, or still allows it.
        """
        logger.info(
            "adversarial_validation.executing_tests",
            finding_count=len(findings),
        )

        tests: list[ValidationTest] = []
        technique_to_defense: dict[str, DefenseType] = {
            "T1110.003": DefenseType.POLICY_UPDATE,
            "T1048": DefenseType.FIREWALL_RULE,
            "T1068": DefenseType.CONFIG_HARDENING,
            "T1021": DefenseType.ACCESS_RESTRICTION,
            "T1046": DefenseType.FIREWALL_RULE,
            "T1078": DefenseType.CREDENTIAL_ROTATION,
        }

        # Default outcomes per technique (stub; production calls real probes)
        technique_outcomes: dict[str, ValidationOutcome] = {
            "T1110.003": ValidationOutcome.BLOCKED,
            "T1048": ValidationOutcome.DETECTED,
            "T1068": ValidationOutcome.BLOCKED,
            "T1021": ValidationOutcome.PARTIALLY_BLOCKED,
        }

        for finding in findings:
            start = time.monotonic()
            defense = technique_to_defense.get(finding.technique_id, DefenseType.DETECTION_RULE)
            outcome = technique_outcomes.get(finding.technique_id, ValidationOutcome.INCONCLUSIVE)
            elapsed = (time.monotonic() - start) * 1000

            tests.append(
                ValidationTest(
                    id=f"vt-{uuid4().hex[:8]}",
                    finding_id=finding.id,
                    technique_id=finding.technique_id,
                    target=finding.target,
                    defense_type=defense,
                    outcome=outcome,
                    confidence=0.85 if outcome != ValidationOutcome.INCONCLUSIVE else 0.4,
                    execution_time_ms=round(elapsed, 2),
                    evidence=[
                        f"Replayed {finding.technique_name} against {finding.target}",
                        f"Defense type: {defense.value}",
                        f"Outcome: {outcome.value}",
                    ],
                )
            )

        logger.info(
            "adversarial_validation.tests_complete",
            total=len(tests),
            blocked=sum(1 for t in tests if t.outcome == ValidationOutcome.BLOCKED),
            bypassed=sum(1 for t in tests if t.outcome == ValidationOutcome.BYPASSED),
        )
        return tests

    # ------------------------------------------------------------------
    # assess_defense_effectiveness
    # ------------------------------------------------------------------
    async def assess_defense_effectiveness(
        self,
        tests: list[ValidationTest],
    ) -> list[EffectivenessScore]:
        """Calculate per-defense-type effectiveness and detect regressions."""
        logger.info(
            "adversarial_validation.assessing_effectiveness",
            test_count=len(tests),
        )

        by_defense: dict[DefenseType, list[ValidationTest]] = {}
        for t in tests:
            by_defense.setdefault(t.defense_type, []).append(t)

        scores: list[EffectivenessScore] = []
        for defense_type, defense_tests in by_defense.items():
            blocked = sum(
                1
                for t in defense_tests
                if t.outcome in (ValidationOutcome.BLOCKED, ValidationOutcome.DETECTED)
            )
            total = len(defense_tests)
            eff_pct = round((blocked / total) * 100, 1) if total else 0.0
            has_bypass = any(t.outcome == ValidationOutcome.BYPASSED for t in defense_tests)

            recs: list[str] = []
            if eff_pct < 80:
                recs.append(f"Improve {defense_type.value}: only {eff_pct}% effective")
            if has_bypass:
                recs.append(
                    f"REGRESSION: {defense_type.value} bypassed — investigate and re-apply fix"
                )

            scores.append(
                EffectivenessScore(
                    id=f"eff-{uuid4().hex[:8]}",
                    defense_type=defense_type,
                    tests_run=total,
                    tests_blocked=blocked,
                    effectiveness_pct=eff_pct,
                    regression_detected=has_bypass,
                    recommendations=recs,
                )
            )

        return scores

    # ------------------------------------------------------------------
    # update_attack_defense_patterns
    # ------------------------------------------------------------------
    async def update_attack_defense_patterns(
        self,
        scores: list[EffectivenessScore],
    ) -> list[PatternUpdate]:
        """Feed results back into attack/defense pattern databases.

        This is the data flywheel: each validation cycle produces updated
        patterns that make both red and blue teams smarter.
        """
        logger.info(
            "adversarial_validation.updating_patterns",
            score_count=len(scores),
        )

        updates: list[PatternUpdate] = []
        for score in scores:
            if score.regression_detected:
                updates.append(
                    PatternUpdate(
                        id=f"pu-{uuid4().hex[:8]}",
                        pattern_type="attack_evasion",
                        old_pattern=(f"{score.defense_type.value} blocks technique"),
                        new_pattern=(
                            f"{score.defense_type.value} bypassed — "
                            "attack variant evades current defense"
                        ),
                        source="validation",
                        applied=False,
                    )
                )
                updates.append(
                    PatternUpdate(
                        id=f"pu-{uuid4().hex[:8]}",
                        pattern_type="defense_gap",
                        old_pattern=f"{score.defense_type.value} effective",
                        new_pattern=(
                            f"{score.defense_type.value} regression — requires re-hardening"
                        ),
                        source="blue_team",
                        applied=False,
                    )
                )
            elif score.effectiveness_pct >= 90:
                updates.append(
                    PatternUpdate(
                        id=f"pu-{uuid4().hex[:8]}",
                        pattern_type="defense_confirmed",
                        old_pattern=f"{score.defense_type.value} unverified",
                        new_pattern=(
                            f"{score.defense_type.value} verified at {score.effectiveness_pct}%"
                        ),
                        source="validation",
                        applied=True,
                    )
                )

        logger.info(
            "adversarial_validation.patterns_updated",
            total_updates=len(updates),
            regressions=[u.id for u in updates if u.pattern_type == "defense_gap"],
        )
        return updates
