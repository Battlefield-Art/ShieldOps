"""Tool functions for the Behavioral Threat Detector.

Bridges behavior collection, baseline building, deviation
detection, threat scoring, and alert generation to the
LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.behavioral_threat_detector.models import (
    BehaviorBaseline,
    BehaviorDeviation,
    BehaviorRecord,
    BehaviorSource,
    DeviationType,
    ThreatAlert,
    ThreatScore,
)

logger = structlog.get_logger()


class BehavioralThreatDetectorToolkit:
    """Tools for the behavioral threat detector agent."""

    def __init__(
        self,
        behavior_collector: Any | None = None,
        baseline_store: Any | None = None,
        deviation_engine: Any | None = None,
        threat_scorer: Any | None = None,
        alert_manager: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._behavior_collector = behavior_collector
        self._baseline_store = baseline_store
        self._deviation_engine = deviation_engine
        self._threat_scorer = threat_scorer
        self._alert_manager = alert_manager
        self._repository = repository
        self._metrics: list[dict[str, Any]] = []

    # ---- Behavior Collection ----

    async def collect_behaviors(
        self,
        tenant_id: str = "",
        sources: list[str] | None = None,
    ) -> list[BehaviorRecord]:
        """Collect behavioral data from configured sources."""
        records: list[BehaviorRecord] = []
        now = datetime.now(UTC)

        if self._behavior_collector is not None:
            try:
                raw = await self._behavior_collector.collect(tenant_id=tenant_id, sources=sources)
                for item in raw:
                    records.append(
                        BehaviorRecord(
                            record_id=item.get("id", f"bhr-{uuid4().hex[:8]}"),
                            entity_id=item.get("entity_id", ""),
                            entity_type=item.get("entity_type", "user"),
                            source=BehaviorSource(item.get("source", "user_activity")),
                            action=item.get("action", ""),
                            resource=item.get("resource", ""),
                            timestamp=item.get("timestamp", now),
                            metadata=item.get("metadata", {}),
                        )
                    )
            except Exception as e:
                logger.error(
                    "btd_behavior_collection_failed",
                    error=str(e),
                )
        else:
            # Mock behavioral data
            bsources = list(BehaviorSource)
            actions = [
                "login",
                "file_read",
                "file_write",
                "api_call",
                "query_db",
                "ssh_session",
                "download",
                "config_change",
                "privilege_use",
            ]
            resources = [
                "prod-db",
                "staging-api",
                "secrets-vault",
                "admin-console",
                "s3-bucket",
                "k8s-cluster",
            ]
            entity_count = random.randint(5, 15)  # noqa: S311
            entities = [f"entity-{uuid4().hex[:6]}" for _unused_i in range(entity_count)]
            for entity_id in entities:
                record_count = random.randint(3, 12)  # noqa: S311
                for _unused_j in range(record_count):
                    records.append(
                        BehaviorRecord(
                            record_id=f"bhr-{uuid4().hex[:8]}",
                            entity_id=entity_id,
                            entity_type=random.choice(  # noqa: S311
                                ["user", "service_account", "agent"]
                            ),
                            source=random.choice(bsources),  # noqa: S311
                            action=random.choice(actions),  # noqa: S311
                            resource=random.choice(resources),  # noqa: S311
                            timestamp=now,
                            metadata={"mock": True},
                            geo_location=random.choice(  # noqa: S311
                                [
                                    "us-east-1",
                                    "us-west-2",
                                    "eu-west-1",
                                    "ap-southeast-1",
                                ]
                            ),
                            session_id=f"sess-{uuid4().hex[:8]}",
                        )
                    )

        logger.info(
            "btd_behaviors_collected",
            tenant_id=tenant_id,
            count=len(records),
        )
        return records

    # ---- Baseline Building ----

    async def build_baselines(
        self,
        records: list[BehaviorRecord],
    ) -> list[BehaviorBaseline]:
        """Build behavioral baselines from collected records."""
        baselines: list[BehaviorBaseline] = []

        # Group by entity
        by_entity: dict[str, list[BehaviorRecord]] = {}
        for record in records:
            by_entity.setdefault(record.entity_id, []).append(record)

        for entity_id, entity_records in by_entity.items():
            sources_seen = {r.source for r in entity_records}
            for source in sources_seen:
                src_records = [r for r in entity_records if r.source == source]
                avg_rate = len(src_records) / max(1, 1)
                geos = list({r.geo_location for r in src_records if r.geo_location})
                resources = list({r.resource for r in src_records if r.resource})

                baselines.append(
                    BehaviorBaseline(
                        baseline_id=f"bsl-{uuid4().hex[:8]}",
                        entity_id=entity_id,
                        source=source,
                        avg_actions_per_hour=round(avg_rate, 2),
                        typical_hours=list(range(8, 18)),
                        typical_geos=geos,
                        typical_resources=resources,
                        std_deviation=round(
                            random.uniform(0.5, 3.0),  # noqa: S311
                            2,
                        ),
                        sample_count=len(src_records),
                    )
                )

        logger.info(
            "btd_baselines_built",
            entities=len(by_entity),
            baselines=len(baselines),
        )
        return baselines

    # ---- Deviation Detection ----

    async def detect_deviations(
        self,
        records: list[BehaviorRecord],
        baselines: list[BehaviorBaseline],
    ) -> list[BehaviorDeviation]:
        """Detect behavioral deviations from baselines."""
        deviations: list[BehaviorDeviation] = []

        baseline_map: dict[str, list[BehaviorBaseline]] = {}
        for bl in baselines:
            baseline_map.setdefault(bl.entity_id, []).append(bl)

        dev_types = list(DeviationType)
        severities = ["critical", "high", "medium", "low"]

        by_entity: dict[str, list[BehaviorRecord]] = {}
        for record in records:
            by_entity.setdefault(record.entity_id, []).append(record)

        for entity_id, entity_records in by_entity.items():
            entity_baselines = baseline_map.get(entity_id, [])
            if not entity_baselines:
                continue

            # Simulate deviation detection
            if random.random() > 0.4:  # noqa: S311
                dev_type = random.choice(dev_types)  # noqa: S311
                severity = random.choice(severities)  # noqa: S311
                confidence = round(
                    random.uniform(0.5, 0.99),  # noqa: S311
                    3,
                )
                deviations.append(
                    BehaviorDeviation(
                        deviation_id=f"dev-{uuid4().hex[:8]}",
                        entity_id=entity_id,
                        deviation_type=dev_type,
                        severity=severity,
                        confidence=confidence,
                        description=(f"{dev_type.value} detected for entity {entity_id}"),
                        baseline_value="within normal range",
                        observed_value="exceeds threshold",
                        evidence=[
                            f"records={len(entity_records)}",
                            f"baselines={len(entity_baselines)}",
                        ],
                    )
                )

        logger.info(
            "btd_deviations_detected",
            entities=len(by_entity),
            deviations=len(deviations),
        )
        return deviations

    # ---- Threat Scoring ----

    async def score_threats(
        self,
        deviations: list[BehaviorDeviation],
    ) -> list[ThreatScore]:
        """Score threat levels from detected deviations."""
        scores: list[ThreatScore] = []

        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
        }

        mitre_map = {
            DeviationType.PRIVILEGE_ESCALATION: ["T1548", "T1078"],
            DeviationType.DATA_EXFILTRATION: ["T1041", "T1567"],
            DeviationType.LATERAL_MOVEMENT: ["T1021", "T1550"],
            DeviationType.CREDENTIAL_ABUSE: ["T1110", "T1555"],
            DeviationType.FREQUENCY_SPIKE: ["T1499"],
            DeviationType.GEO_ANOMALY: ["T1078.004"],
            DeviationType.TIME_ANOMALY: ["T1053"],
            DeviationType.UNUSUAL_PROTOCOL: ["T1071"],
        }

        by_entity: dict[str, list[BehaviorDeviation]] = {}
        for dev in deviations:
            by_entity.setdefault(dev.entity_id, []).append(dev)

        for entity_id, entity_devs in by_entity.items():
            weighted_sum = sum(
                severity_weights.get(d.severity, 0.3) * d.confidence for d in entity_devs
            )
            overall = min(
                round(weighted_sum / max(len(entity_devs), 1), 3),
                1.0,
            )

            highest = max(
                entity_devs,
                key=lambda d: severity_weights.get(d.severity, 0),
            )

            techniques: list[str] = []
            for dev in entity_devs:
                techniques.extend(mitre_map.get(dev.deviation_type, []))

            if overall > 0.8:
                action = "isolate_and_investigate"
            elif overall > 0.6:
                action = "investigate"
            elif overall > 0.4:
                action = "monitor_closely"
            else:
                action = "log_and_track"

            scores.append(
                ThreatScore(
                    score_id=f"tsc-{uuid4().hex[:8]}",
                    entity_id=entity_id,
                    overall_score=overall,
                    deviation_count=len(entity_devs),
                    highest_severity=highest.severity,
                    contributing_factors=[d.deviation_type.value for d in entity_devs],
                    recommended_action=action,
                    mitre_techniques=list(set(techniques)),
                )
            )

        logger.info(
            "btd_threats_scored",
            entities=len(by_entity),
            scores=len(scores),
            high_risk=sum(1 for s in scores if s.overall_score > 0.7),
        )
        return scores

    # ---- Alert Generation ----

    async def generate_alerts(
        self,
        scores: list[ThreatScore],
    ) -> list[ThreatAlert]:
        """Generate alerts from threat scores."""
        alerts: list[ThreatAlert] = []
        now = datetime.now(UTC)

        for score in scores:
            if score.overall_score < 0.3:
                continue

            if score.overall_score > 0.8:
                severity = "critical"
            elif score.overall_score > 0.6:
                severity = "high"
            elif score.overall_score > 0.4:
                severity = "medium"
            else:
                severity = "low"

            alerts.append(
                ThreatAlert(
                    alert_id=f"alert-{uuid4().hex[:8]}",
                    entity_id=score.entity_id,
                    severity=severity,
                    title=(f"Behavioral Threat: {severity.upper()} risk for {score.entity_id}"),
                    description=(
                        f"Entity {score.entity_id} has threat "
                        f"score {score.overall_score:.2f} based "
                        f"on {score.deviation_count} deviations. "
                        f"Recommended: {score.recommended_action}."
                    ),
                    threat_score=score.overall_score,
                    deviations=score.contributing_factors,
                    recommended_actions=[score.recommended_action],
                    created_at=now,
                )
            )

        logger.info(
            "btd_alerts_generated",
            scores=len(scores),
            alerts=len(alerts),
        )
        return alerts

    # ---- Metrics ----

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a behavioral threat detector metric."""
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
