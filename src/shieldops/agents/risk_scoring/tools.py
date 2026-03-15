"""Risk Scoring Agent — Tool functions for risk-based alerting."""

from __future__ import annotations

import time
from typing import Any

import structlog

logger = structlog.get_logger()


class RiskScoringToolkit:
    """Tools for risk-based alerting and scoring."""

    def __init__(
        self,
        siem_client: Any | None = None,
        threat_intel: Any | None = None,
        asset_inventory: Any | None = None,
    ) -> None:
        self._siem_client = siem_client
        self._threat_intel = threat_intel
        self._asset_inventory = asset_inventory

    async def collect_observations(
        self,
        time_window_hours: int = 24,
        entity: str = "",
    ) -> list[dict[str, Any]]:
        """Collect security observations from detection sources."""
        logger.info(
            "risk_scoring.collect_observations",
            window_hours=time_window_hours,
            entity=entity,
        )
        if self._siem_client is None:
            return []
        try:
            return await self._siem_client.query_observations(
                time_window_hours=time_window_hours,
                entity=entity,
            )
        except Exception:
            logger.exception("risk_scoring.collect_observations.error")
            return []

    async def enrich_with_mitre(
        self,
        observation: dict[str, Any],
    ) -> dict[str, Any]:
        """Enrich an observation with MITRE ATT&CK mapping."""
        enriched = {**observation}
        detection = observation.get("detection_name", "")

        # MITRE mapping heuristics
        mitre_map: dict[str, tuple[str, str]] = {
            "brute_force": ("credential_access", "T1110"),
            "phishing": ("initial_access", "T1566"),
            "powershell": ("execution", "T1059.001"),
            "scheduled_task": ("persistence", "T1053"),
            "token_theft": ("credential_access", "T1528"),
            "lateral": ("lateral_movement", "T1021"),
            "exfil": ("exfiltration", "T1041"),
            "c2_beacon": ("command_and_control", "T1071"),
            "privilege_escalation": ("privilege_escalation", "T1068"),
            "defense_evasion": ("defense_evasion", "T1562"),
        }
        for keyword, (tactic, technique) in mitre_map.items():
            if keyword in detection.lower():
                enriched["mitre_tactic"] = tactic
                enriched["mitre_technique"] = technique
                break

        return enriched

    async def get_entity_criticality(
        self,
        entity: str,
        entity_type: str = "host",
    ) -> dict[str, Any]:
        """Get the criticality rating of an entity from asset inventory."""
        logger.info(
            "risk_scoring.get_entity_criticality",
            entity=entity,
            entity_type=entity_type,
        )
        if self._asset_inventory is None:
            return {"entity": entity, "criticality": 0.5, "environment": "unknown"}
        try:
            return await self._asset_inventory.get_criticality(entity)
        except Exception:
            return {"entity": entity, "criticality": 0.5, "environment": "unknown"}

    async def check_threat_intel(
        self,
        indicator: str,
    ) -> dict[str, Any]:
        """Check an indicator against threat intelligence feeds."""
        logger.info("risk_scoring.check_threat_intel", indicator=indicator)
        if self._threat_intel is None:
            return {
                "indicator": indicator,
                "known_malicious": False,
                "confidence": 0.0,
            }
        try:
            return await self._threat_intel.lookup(indicator)
        except Exception:
            return {
                "indicator": indicator,
                "known_malicious": False,
                "confidence": 0.0,
            }

    def compute_composite_score(
        self,
        observations: list[dict[str, Any]],
        entity_criticality: float = 0.5,
    ) -> dict[str, Any]:
        """Compute composite risk score from aggregated observations."""
        if not observations:
            return {"composite_score": 0.0, "risk_level": "low", "factors": {}}

        # Factor 1: Kill chain breadth (unique tactics)
        tactics = {o.get("mitre_tactic", "") for o in observations if o.get("mitre_tactic")}
        tactic_score = min(len(tactics) / 5.0, 1.0)

        # Factor 2: Temporal clustering
        timestamps = [o.get("timestamp", 0.0) for o in observations if o.get("timestamp")]
        if len(timestamps) >= 2:
            time_span = max(timestamps) - min(timestamps)
            burst_score = 1.0 if time_span < 3600 else max(0.2, 1.0 - time_span / 86400)
        else:
            burst_score = 0.3

        # Factor 3: Source diversity
        sources = {o.get("source", "") for o in observations if o.get("source")}
        diversity_score = min(len(sources) / 3.0, 1.0)

        # Factor 4: Raw score average
        raw_scores = [o.get("raw_score", 0.0) for o in observations]
        avg_raw = sum(raw_scores) / len(raw_scores) if raw_scores else 0.0

        # Weighted composite
        composite = (
            tactic_score * 0.3
            + burst_score * 0.15
            + diversity_score * 0.15
            + avg_raw * 0.2
            + entity_criticality * 0.2
        )
        composite = round(min(composite, 1.0), 4)

        if composite >= 0.85:
            risk_level = "critical"
        elif composite >= 0.6:
            risk_level = "high"
        elif composite >= 0.3:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "composite_score": composite,
            "risk_level": risk_level,
            "factors": {
                "tactic_breadth": round(tactic_score, 4),
                "temporal_clustering": round(burst_score, 4),
                "source_diversity": round(diversity_score, 4),
                "avg_raw_score": round(avg_raw, 4),
                "entity_criticality": entity_criticality,
            },
            "observation_count": len(observations),
            "unique_tactics": sorted(tactics),
        }

    def decide_action(
        self,
        composite_score: float,
        autonomous_threshold: float = 0.85,
        approval_threshold: float = 0.5,
    ) -> dict[str, Any]:
        """Decide action based on composite risk score and thresholds."""
        if composite_score >= autonomous_threshold:
            decision = "autonomous"
            actions = ["auto_contain", "isolate_host", "block_ip"]
        elif composite_score >= approval_threshold:
            decision = "human_approval"
            actions = ["generate_alert", "request_review", "increase_monitoring"]
        elif composite_score >= 0.3:
            decision = "monitor"
            actions = ["add_watchlist", "increase_logging"]
        else:
            decision = "no_action"
            actions = ["update_baseline"]

        return {
            "decision": decision,
            "composite_score": composite_score,
            "recommended_actions": actions,
            "timestamp": time.time(),
        }
