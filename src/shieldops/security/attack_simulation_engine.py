"""Attack Simulation Engine — continuous adversarial probing and defense evaluation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AttackPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"


class SimulationResult(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    DETECTED_AND_BLOCKED = "detected_and_blocked"
    NOT_APPLICABLE = "not_applicable"


class AttackComplexity(StrEnum):
    TRIVIAL = "trivial"
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    ADVANCED = "advanced"


# --- Models ---


class SimulationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str = ""
    attack_phase: AttackPhase = AttackPhase.RECONNAISSANCE
    result: SimulationResult = SimulationResult.NOT_APPLICABLE
    complexity: AttackComplexity = AttackComplexity.MODERATE
    mitre_technique_id: str = ""
    target_asset: str = ""
    detection_time_ms: int = 0
    blocked: bool = False
    details: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackTechnique(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    success_rate: float = 0.0
    avg_detection_time_ms: int = 0
    times_tested: int = 0
    last_tested_at: float = Field(default_factory=time.time)


class SimulationReport(BaseModel):
    total_simulations: int = 0
    total_blocked: int = 0
    total_successful: int = 0
    block_rate_pct: float = 0.0
    breach_probability: float = 0.0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_result: dict[str, int] = Field(default_factory=dict)
    by_complexity: dict[str, int] = Field(default_factory=dict)
    weakest_phases: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---

_PHASE_ORDER = list(AttackPhase)


class AttackSimulationEngine:
    """Continuous adversarial probing and defense evaluation."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[SimulationRecord] = []
        self._techniques: dict[str, AttackTechnique] = {}
        logger.info("attack_simulation_engine.initialized", max_records=max_records)

    # -- record --------------------------------------------------------------

    def record_simulation(
        self,
        campaign_name: str,
        attack_phase: AttackPhase = AttackPhase.RECONNAISSANCE,
        result: SimulationResult = SimulationResult.NOT_APPLICABLE,
        complexity: AttackComplexity = AttackComplexity.MODERATE,
        mitre_technique_id: str = "",
        target_asset: str = "",
        detection_time_ms: int = 0,
        details: str = "",
    ) -> SimulationRecord:
        blocked = result in (SimulationResult.BLOCKED, SimulationResult.DETECTED_AND_BLOCKED)
        record = SimulationRecord(
            campaign_name=campaign_name,
            attack_phase=attack_phase,
            result=result,
            complexity=complexity,
            mitre_technique_id=mitre_technique_id,
            target_asset=target_asset,
            detection_time_ms=detection_time_ms,
            blocked=blocked,
            details=details,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

        # Update technique tracking
        if mitre_technique_id:
            self._update_technique(mitre_technique_id, result, detection_time_ms)

        logger.info(
            "attack_simulation_engine.simulation_recorded",
            record_id=record.id,
            campaign=campaign_name,
            phase=attack_phase.value,
            result=result.value,
        )
        return record

    # -- domain operations ---------------------------------------------------

    def plan_campaign(
        self,
        campaign_name: str,
        target_phases: list[AttackPhase] | None = None,
        complexity: AttackComplexity = AttackComplexity.MODERATE,
    ) -> list[dict[str, Any]]:
        """Plan a simulation campaign across attack phases."""
        phases = target_phases or list(AttackPhase)
        plan: list[dict[str, Any]] = []
        for i, phase in enumerate(phases):
            # Find techniques with lowest block rate for this phase
            phase_records = [r for r in self._records if r.attack_phase == phase]
            success_rate = 0.0
            if phase_records:
                successes = sum(1 for r in phase_records if r.result == SimulationResult.SUCCESS)
                success_rate = round(successes / len(phase_records) * 100, 2)

            plan.append(
                {
                    "step": i + 1,
                    "phase": phase.value,
                    "campaign_name": campaign_name,
                    "complexity": complexity.value,
                    "historical_success_rate": success_rate,
                    "recommended_techniques": self._techniques_for_phase(phase),
                }
            )
        return plan

    def evaluate_defenses(self) -> list[dict[str, Any]]:
        """Evaluate defense effectiveness per attack phase."""
        phase_stats: dict[str, dict[str, int]] = {}
        for r in self._records:
            stats = phase_stats.setdefault(r.attack_phase.value, {"total": 0, "blocked": 0})
            stats["total"] += 1
            if r.blocked:
                stats["blocked"] += 1

        results: list[dict[str, Any]] = []
        for phase, stats in phase_stats.items():
            block_rate = round(stats["blocked"] / stats["total"] * 100, 2) if stats["total"] else 0
            results.append(
                {
                    "phase": phase,
                    "total_simulations": stats["total"],
                    "blocked": stats["blocked"],
                    "block_rate_pct": block_rate,
                    "defense_grade": (
                        "A"
                        if block_rate >= 90
                        else "B"
                        if block_rate >= 75
                        else "C"
                        if block_rate >= 50
                        else "D"
                        if block_rate >= 25
                        else "F"
                    ),
                }
            )
        results.sort(key=lambda x: x["block_rate_pct"])
        return results

    def calculate_breach_probability(self) -> dict[str, Any]:
        """Calculate the probability of a multi-phase breach succeeding."""
        if not self._records:
            return {"breach_probability": 0.0, "phase_probabilities": {}}

        phase_success: dict[str, float] = {}
        for phase in AttackPhase:
            phase_records = [r for r in self._records if r.attack_phase == phase]
            if not phase_records:
                phase_success[phase.value] = 0.0
                continue
            successes = sum(
                1
                for r in phase_records
                if r.result in (SimulationResult.SUCCESS, SimulationResult.PARTIAL)
            )
            phase_success[phase.value] = round(successes / len(phase_records), 4)

        # Breach probability = product of success rates across kill chain
        cumulative = 1.0
        for phase in _PHASE_ORDER:
            rate = phase_success.get(phase.value, 0.0)
            cumulative *= rate

        return {
            "breach_probability": round(cumulative * 100, 4),
            "phase_probabilities": phase_success,
            "highest_risk_phase": max(phase_success, key=lambda k: phase_success.get(k, 0.0))
            if phase_success
            else "",
        }

    # -- report / stats ------------------------------------------------------

    def generate_simulation_report(self) -> SimulationReport:
        by_phase: dict[str, int] = {}
        by_result: dict[str, int] = {}
        by_complexity: dict[str, int] = {}
        for r in self._records:
            by_phase[r.attack_phase.value] = by_phase.get(r.attack_phase.value, 0) + 1
            by_result[r.result.value] = by_result.get(r.result.value, 0) + 1
            by_complexity[r.complexity.value] = by_complexity.get(r.complexity.value, 0) + 1

        total = len(self._records)
        blocked = sum(1 for r in self._records if r.blocked)
        successful = sum(1 for r in self._records if r.result == SimulationResult.SUCCESS)
        block_rate = round(blocked / total * 100, 2) if total else 0.0

        breach = self.calculate_breach_probability()
        defenses = self.evaluate_defenses()
        weakest = [d["phase"] for d in defenses if d.get("defense_grade", "F") in ("D", "F")]

        recs: list[str] = []
        if weakest:
            recs.append(f"Weak defenses in phases: {', '.join(weakest)}")
        if breach.get("breach_probability", 0) > 10:
            recs.append(f"Breach probability {breach['breach_probability']}% exceeds 10% threshold")
        if block_rate < 80:
            recs.append(f"Overall block rate {block_rate}% below 80% target")
        if not recs:
            recs.append("Attack simulation results meet defense targets")

        return SimulationReport(
            total_simulations=total,
            total_blocked=blocked,
            total_successful=successful,
            block_rate_pct=block_rate,
            breach_probability=breach.get("breach_probability", 0.0),
            by_phase=by_phase,
            by_result=by_result,
            by_complexity=by_complexity,
            weakest_phases=weakest,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        phase_dist: dict[str, int] = {}
        for r in self._records:
            phase_dist[r.attack_phase.value] = phase_dist.get(r.attack_phase.value, 0) + 1
        return {
            "total_simulations": len(self._records),
            "total_techniques_tracked": len(self._techniques),
            "phase_distribution": phase_dist,
            "unique_campaigns": len({r.campaign_name for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._techniques.clear()
        logger.info("attack_simulation_engine.cleared")
        return {"status": "cleared"}

    # -- private helpers -----------------------------------------------------

    def _update_technique(
        self, technique_id: str, result: SimulationResult, detection_time_ms: int
    ) -> None:
        if technique_id not in self._techniques:
            self._techniques[technique_id] = AttackTechnique(technique_id=technique_id)

        t = self._techniques[technique_id]
        t.times_tested += 1
        t.last_tested_at = time.time()

        was_success = result in (SimulationResult.SUCCESS, SimulationResult.PARTIAL)
        old_total = t.times_tested - 1
        if old_total > 0:
            t.success_rate = round(
                (t.success_rate * old_total + (1.0 if was_success else 0.0)) / t.times_tested, 4
            )
            t.avg_detection_time_ms = int(
                (t.avg_detection_time_ms * old_total + detection_time_ms) / t.times_tested
            )
        else:
            t.success_rate = 1.0 if was_success else 0.0
            t.avg_detection_time_ms = detection_time_ms

    def _techniques_for_phase(self, phase: AttackPhase) -> list[str]:
        """Get technique IDs relevant to a phase based on records."""
        technique_ids: set[str] = set()
        for r in self._records:
            if r.attack_phase == phase and r.mitre_technique_id:
                technique_ids.add(r.mitre_technique_id)
        return list(technique_ids)[:10]
