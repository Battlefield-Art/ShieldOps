"""Detection Gap Finder Agent — Tool functions."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    AttackSimulation,
    BlindSpot,
    DetectionMonitor,
    DetectionOutcome,
    GapPrioritization,
    SimulationType,
    TechniqueSelection,
)

logger = structlog.get_logger()

# Safe techniques for simulation
_SIMULATION_TECHNIQUES: list[dict[str, Any]] = [
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "initial_access",
        "sim": "log_replay",
        "risk": 0.9,
    },
    {
        "id": "T1059.001",
        "name": "PowerShell Execution",
        "tactic": "execution",
        "sim": "atomic_test",
        "risk": 0.85,
    },
    {
        "id": "T1547.001",
        "name": "Registry Run Keys",
        "tactic": "persistence",
        "sim": "behavior_simulation",
        "risk": 0.8,
    },
    {
        "id": "T1003.001",
        "name": "LSASS Memory Dump",
        "tactic": "credential_access",
        "sim": "log_replay",
        "risk": 0.95,
    },
    {
        "id": "T1021.001",
        "name": "Remote Desktop Protocol",
        "tactic": "lateral_movement",
        "sim": "traffic_replay",
        "risk": 0.85,
    },
    {
        "id": "T1048.003",
        "name": "Exfil Over Unencrypted",
        "tactic": "exfiltration",
        "sim": "traffic_replay",
        "risk": 0.9,
    },
    {
        "id": "T1071.001",
        "name": "Web Protocols C2",
        "tactic": "command_and_control",
        "sim": "ioc_injection",
        "risk": 0.8,
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
        "sim": "log_replay",
        "risk": 0.95,
    },
]

# Simulated detection outcomes (some miss on purpose)
_DETECTION_RESULTS: dict[str, DetectionOutcome] = {
    "T1566.001": DetectionOutcome.DETECTED,
    "T1059.001": DetectionOutcome.PARTIALLY_DETECTED,
    "T1547.001": DetectionOutcome.MISSED,
    "T1003.001": DetectionOutcome.DETECTED,
    "T1021.001": DetectionOutcome.MISSED,
    "T1048.003": DetectionOutcome.FALSE_NEGATIVE,
    "T1071.001": DetectionOutcome.MISSED,
    "T1486": DetectionOutcome.DETECTED,
}


class DetectionGapFinderToolkit:
    """Toolkit for detection gap finding via safe simulation."""

    def __init__(
        self,
        siem_client: Any | None = None,
        simulation_engine: Any | None = None,
        detection_monitor: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._siem_client = siem_client
        self._simulation_engine = simulation_engine
        self._detection_monitor = detection_monitor
        self._repository = repository

    async def select_techniques(
        self,
        tenant_id: str,
    ) -> list[TechniqueSelection]:
        """Select techniques for simulation testing."""
        logger.info(
            "gap_finder.select_techniques",
            tenant_id=tenant_id,
        )
        if self._simulation_engine is not None:
            try:
                return await self._simulation_engine.select(
                    tenant_id,
                )
            except Exception:
                logger.warning(
                    "gap_finder.select_fallback",
                )

        return [
            TechniqueSelection(
                technique_id=t["id"],
                technique_name=t["name"],
                tactic=t["tactic"],
                simulation_type=SimulationType(
                    t["sim"],
                ),
                risk_priority=t["risk"],
            )
            for t in _SIMULATION_TECHNIQUES
        ]

    async def simulate_attacks(
        self,
        techniques: list[TechniqueSelection],
    ) -> list[AttackSimulation]:
        """Run safe attack simulations (log replay only)."""
        logger.info(
            "gap_finder.simulate_attacks",
            count=len(techniques),
        )
        simulations: list[AttackSimulation] = []
        for tech in techniques:
            sim = AttackSimulation(
                id=f"sim-{uuid4().hex[:8]}",
                technique_id=tech.technique_id,
                simulation_type=tech.simulation_type,
                artifacts_generated=[
                    f"{tech.technique_id}_log.json",
                ],
                logs_injected=10,
                timestamp=time.time(),
                safe=True,
            )
            simulations.append(sim)
        return simulations

    async def monitor_detections(
        self,
        simulations: list[AttackSimulation],
    ) -> list[DetectionMonitor]:
        """Check whether detections fired for simulations."""
        logger.info(
            "gap_finder.monitor_detections",
            count=len(simulations),
        )
        if self._detection_monitor is not None:
            try:
                return await self._detection_monitor.check(
                    simulations,
                )
            except Exception:
                logger.warning(
                    "gap_finder.monitor_fallback",
                )

        results: list[DetectionMonitor] = []
        for sim in simulations:
            outcome = _DETECTION_RESULTS.get(
                sim.technique_id,
                DetectionOutcome.MISSED,
            )
            results.append(
                DetectionMonitor(
                    simulation_id=sim.id,
                    technique_id=sim.technique_id,
                    outcome=outcome,
                    alert_id=(
                        f"alert-{uuid4().hex[:8]}" if outcome == DetectionOutcome.DETECTED else ""
                    ),
                    detection_time_sec=(2.5 if outcome == DetectionOutcome.DETECTED else 0.0),
                    rule_name=(
                        f"Rule for {sim.technique_id}"
                        if outcome == DetectionOutcome.DETECTED
                        else ""
                    ),
                )
            )
        return results

    async def identify_blind_spots(
        self,
        monitors: list[DetectionMonitor],
        techniques: list[TechniqueSelection],
    ) -> list[BlindSpot]:
        """Identify techniques that were not detected."""
        logger.info(
            "gap_finder.identify_blind_spots",
            monitor_count=len(monitors),
        )
        tech_map = {t.technique_id: t for t in techniques}
        blind_spots: list[BlindSpot] = []
        for mon in monitors:
            if mon.outcome in (
                DetectionOutcome.MISSED,
                DetectionOutcome.FALSE_NEGATIVE,
                DetectionOutcome.PARTIALLY_DETECTED,
            ):
                tech = tech_map.get(mon.technique_id)
                blind_spots.append(
                    BlindSpot(
                        technique_id=mon.technique_id,
                        technique_name=(tech.technique_name if tech else ""),
                        tactic=(tech.tactic if tech else ""),
                        outcome=mon.outcome,
                        data_sources_available=[
                            "process_logs",
                            "network_logs",
                        ],
                        root_cause=("No detection rule exists"),
                    )
                )
        return blind_spots

    async def prioritize_gaps(
        self,
        blind_spots: list[BlindSpot],
    ) -> list[GapPrioritization]:
        """Prioritize blind spots by risk."""
        logger.info(
            "gap_finder.prioritize_gaps",
            count=len(blind_spots),
        )
        prioritized: list[GapPrioritization] = []
        for i, spot in enumerate(blind_spots):
            score = 8.0
            if spot.outcome == DetectionOutcome.MISSED:
                score = 9.0
            elif spot.outcome == DetectionOutcome.FALSE_NEGATIVE:
                score = 8.5
            else:
                score = 6.0

            prioritized.append(
                GapPrioritization(
                    technique_id=spot.technique_id,
                    technique_name=spot.technique_name,
                    risk_score=score,
                    exploitability="moderate",
                    business_impact="High risk if exploited",
                    remediation_effort="medium",
                    priority_rank=i + 1,
                )
            )

        prioritized.sort(
            key=lambda g: g.risk_score,
            reverse=True,
        )
        for i, g in enumerate(prioritized):
            g.priority_rank = i + 1
        return prioritized
