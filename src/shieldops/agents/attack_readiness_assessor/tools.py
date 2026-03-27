"""Attack Readiness Assessor Agent — Tool functions."""

from __future__ import annotations

from typing import Any

import structlog

from .models import (
    AttackScenario,
    DetectionAssessment,
    PreventionAssessment,
    ReadinessLevel,
    ReadinessScore,
    ResponseAssessment,
    ScenarioSelection,
)

logger = structlog.get_logger()

# Baseline readiness data per scenario
_SCENARIO_DATA: dict[AttackScenario, dict[str, Any]] = {
    AttackScenario.RANSOMWARE: {
        "relevance": 0.95,
        "intel": "Top threat per CISA advisory",
        "prevention": {
            "score": 72.0,
            "in_place": [
                "EDR",
                "Email filtering",
                "Backup",
            ],
            "missing": [
                "App whitelisting",
                "Network segmentation",
            ],
            "effectiveness": "Good but gaps exist",
        },
        "detection": {
            "score": 65.0,
            "rules": 12,
            "coverage": 68.0,
            "mttd": "4.2 hours",
            "gaps": ["Fileless ransomware"],
        },
        "response": {
            "score": 58.0,
            "runbook": True,
            "mttr": "8 hours",
            "automation": "partial",
            "gaps": ["Automated isolation"],
        },
    },
    AttackScenario.APT_CAMPAIGN: {
        "relevance": 0.85,
        "intel": "Nation-state threat groups active",
        "prevention": {
            "score": 55.0,
            "in_place": ["MFA", "EDR"],
            "missing": [
                "Zero trust",
                "Micro-segmentation",
            ],
            "effectiveness": "Moderate",
        },
        "detection": {
            "score": 48.0,
            "rules": 8,
            "coverage": 45.0,
            "mttd": "72 hours",
            "gaps": [
                "Living-off-the-land",
                "Slow lateral movement",
            ],
        },
        "response": {
            "score": 42.0,
            "runbook": False,
            "mttr": "48 hours",
            "automation": "none",
            "gaps": [
                "APT playbook",
                "Threat hunting",
            ],
        },
    },
    AttackScenario.INSIDER_THREAT: {
        "relevance": 0.80,
        "intel": "Industry baseline risk",
        "prevention": {
            "score": 60.0,
            "in_place": ["DLP", "RBAC"],
            "missing": ["UEBA", "Data classification"],
            "effectiveness": "Moderate",
        },
        "detection": {
            "score": 45.0,
            "rules": 5,
            "coverage": 40.0,
            "mttd": "14 days",
            "gaps": [
                "Behavioral anomalies",
                "Data hoarding",
            ],
        },
        "response": {
            "score": 50.0,
            "runbook": True,
            "mttr": "24 hours",
            "automation": "partial",
            "gaps": ["HR integration"],
        },
    },
    AttackScenario.SUPPLY_CHAIN: {
        "relevance": 0.88,
        "intel": "SolarWinds-class risk",
        "prevention": {
            "score": 45.0,
            "in_place": ["SBOM"],
            "missing": [
                "Vendor risk scoring",
                "Build verification",
            ],
            "effectiveness": "Insufficient",
        },
        "detection": {
            "score": 35.0,
            "rules": 3,
            "coverage": 30.0,
            "mttd": "30 days",
            "gaps": [
                "Dependency tampering",
                "CI/CD injection",
            ],
        },
        "response": {
            "score": 40.0,
            "runbook": False,
            "mttr": "72 hours",
            "automation": "none",
            "gaps": [
                "Supply chain playbook",
                "Vendor notification",
            ],
        },
    },
    AttackScenario.CREDENTIAL_COMPROMISE: {
        "relevance": 0.92,
        "intel": "Most common initial access vector",
        "prevention": {
            "score": 68.0,
            "in_place": ["MFA", "Password policy"],
            "missing": [
                "Passwordless auth",
                "Phishing-resistant MFA",
            ],
            "effectiveness": "Good",
        },
        "detection": {
            "score": 62.0,
            "rules": 10,
            "coverage": 65.0,
            "mttd": "6 hours",
            "gaps": ["Token theft"],
        },
        "response": {
            "score": 70.0,
            "runbook": True,
            "mttr": "2 hours",
            "automation": "partial",
            "gaps": ["Session revocation"],
        },
    },
    AttackScenario.CLOUD_BREACH: {
        "relevance": 0.87,
        "intel": "Cloud misconfig top risk",
        "prevention": {
            "score": 52.0,
            "in_place": ["IAM policies"],
            "missing": [
                "CSPM",
                "Service control policies",
            ],
            "effectiveness": "Moderate",
        },
        "detection": {
            "score": 55.0,
            "rules": 7,
            "coverage": 50.0,
            "mttd": "12 hours",
            "gaps": [
                "Cross-account access",
                "API abuse",
            ],
        },
        "response": {
            "score": 48.0,
            "runbook": False,
            "mttr": "18 hours",
            "automation": "none",
            "gaps": ["Cloud IR playbook"],
        },
    },
    AttackScenario.DDOS: {
        "relevance": 0.70,
        "intel": "Commodity threat",
        "prevention": {
            "score": 75.0,
            "in_place": ["WAF", "CDN", "Rate limiting"],
            "missing": ["DDoS scrubbing service"],
            "effectiveness": "Good",
        },
        "detection": {
            "score": 80.0,
            "rules": 15,
            "coverage": 85.0,
            "mttd": "2 minutes",
            "gaps": [],
        },
        "response": {
            "score": 72.0,
            "runbook": True,
            "mttr": "15 minutes",
            "automation": "full",
            "gaps": [],
        },
    },
    AttackScenario.DATA_EXFILTRATION: {
        "relevance": 0.90,
        "intel": "Critical business risk",
        "prevention": {
            "score": 55.0,
            "in_place": ["DLP", "Encryption"],
            "missing": [
                "Data classification",
                "CASB",
            ],
            "effectiveness": "Moderate",
        },
        "detection": {
            "score": 50.0,
            "rules": 6,
            "coverage": 48.0,
            "mttd": "48 hours",
            "gaps": [
                "Encrypted channels",
                "Cloud storage",
            ],
        },
        "response": {
            "score": 45.0,
            "runbook": False,
            "mttr": "36 hours",
            "automation": "none",
            "gaps": [
                "Data breach playbook",
                "Forensics",
            ],
        },
    },
}


def _score_to_readiness(
    score: float,
) -> ReadinessLevel:
    """Convert numeric score to readiness level."""
    if score >= 85:
        return ReadinessLevel.EXCELLENT
    if score >= 70:
        return ReadinessLevel.GOOD
    if score >= 55:
        return ReadinessLevel.ADEQUATE
    if score >= 40:
        return ReadinessLevel.INSUFFICIENT
    return ReadinessLevel.CRITICAL


class AttackReadinessAssessorToolkit:
    """Toolkit for attack readiness assessment."""

    def __init__(
        self,
        threat_intel: Any | None = None,
        control_registry: Any | None = None,
        detection_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._threat_intel = threat_intel
        self._control_registry = control_registry
        self._detection_engine = detection_engine
        self._repository = repository

    async def select_scenarios(
        self,
        tenant_id: str,
        scenarios: list[str] | None = None,
    ) -> list[ScenarioSelection]:
        """Select attack scenarios for assessment."""
        logger.info(
            "readiness.select_scenarios",
            tenant_id=tenant_id,
        )
        selected = [AttackScenario(s) for s in scenarios] if scenarios else list(AttackScenario)

        return [
            ScenarioSelection(
                scenario=s,
                relevance_score=_SCENARIO_DATA.get(
                    s,
                    {},
                ).get("relevance", 0.5),
                threat_intel_basis=_SCENARIO_DATA.get(
                    s,
                    {},
                ).get("intel", ""),
            )
            for s in selected
        ]

    async def assess_prevention(
        self,
        scenarios: list[ScenarioSelection],
    ) -> list[PreventionAssessment]:
        """Assess prevention capabilities."""
        logger.info(
            "readiness.assess_prevention",
            count=len(scenarios),
        )
        results: list[PreventionAssessment] = []
        for sel in scenarios:
            data = _SCENARIO_DATA.get(
                sel.scenario,
                {},
            ).get("prevention", {})
            results.append(
                PreventionAssessment(
                    scenario=sel.scenario,
                    score=data.get("score", 50.0),
                    controls_in_place=data.get(
                        "in_place",
                        [],
                    ),
                    controls_missing=data.get(
                        "missing",
                        [],
                    ),
                    effectiveness=data.get(
                        "effectiveness",
                        "",
                    ),
                )
            )
        return results

    async def assess_detection(
        self,
        scenarios: list[ScenarioSelection],
    ) -> list[DetectionAssessment]:
        """Assess detection capabilities."""
        logger.info(
            "readiness.assess_detection",
            count=len(scenarios),
        )
        results: list[DetectionAssessment] = []
        for sel in scenarios:
            data = _SCENARIO_DATA.get(
                sel.scenario,
                {},
            ).get("detection", {})
            results.append(
                DetectionAssessment(
                    scenario=sel.scenario,
                    score=data.get("score", 50.0),
                    detection_rules=data.get(
                        "rules",
                        0,
                    ),
                    coverage_pct=data.get(
                        "coverage",
                        0.0,
                    ),
                    mean_time_to_detect=data.get(
                        "mttd",
                        "",
                    ),
                    gaps=data.get("gaps", []),
                )
            )
        return results

    async def assess_response(
        self,
        scenarios: list[ScenarioSelection],
    ) -> list[ResponseAssessment]:
        """Assess response capabilities."""
        logger.info(
            "readiness.assess_response",
            count=len(scenarios),
        )
        results: list[ResponseAssessment] = []
        for sel in scenarios:
            data = _SCENARIO_DATA.get(
                sel.scenario,
                {},
            ).get("response", {})
            results.append(
                ResponseAssessment(
                    scenario=sel.scenario,
                    score=data.get("score", 50.0),
                    runbook_exists=data.get(
                        "runbook",
                        False,
                    ),
                    mean_time_to_respond=data.get(
                        "mttr",
                        "",
                    ),
                    automation_level=data.get(
                        "automation",
                        "none",
                    ),
                    gaps=data.get("gaps", []),
                )
            )
        return results

    async def calculate_readiness(
        self,
        prevention: list[PreventionAssessment],
        detection: list[DetectionAssessment],
        response: list[ResponseAssessment],
    ) -> list[ReadinessScore]:
        """Calculate overall readiness scores."""
        logger.info(
            "readiness.calculate_readiness",
        )
        prev_map = {p.scenario: p for p in prevention}
        det_map = {d.scenario: d for d in detection}
        resp_map = {r.scenario: r for r in response}

        scores: list[ReadinessScore] = []
        all_scenarios = set(list(prev_map) + list(det_map) + list(resp_map))

        for scenario in all_scenarios:
            p = prev_map.get(scenario)
            d = det_map.get(scenario)
            r = resp_map.get(scenario)

            p_score = p.score if p else 0
            d_score = d.score if d else 0
            r_score = r.score if r else 0

            overall = p_score * 0.35 + d_score * 0.35 + r_score * 0.30

            all_gaps: list[str] = []
            if p:
                all_gaps.extend(p.controls_missing)
            if d:
                all_gaps.extend(d.gaps)
            if r:
                all_gaps.extend(r.gaps)

            scores.append(
                ReadinessScore(
                    scenario=scenario,
                    prevention_score=p_score,
                    detection_score=d_score,
                    response_score=r_score,
                    overall_score=round(overall, 1),
                    readiness=_score_to_readiness(
                        overall,
                    ),
                    top_gaps=all_gaps[:5],
                )
            )

        scores.sort(
            key=lambda s: s.overall_score,
        )
        return scores
