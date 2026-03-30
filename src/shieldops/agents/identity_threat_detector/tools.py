"""Tool functions for the Identity Threat Detector Agent."""

from __future__ import annotations

import random  # noqa: S311
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()


class IdentityThreatDetectorToolkit:
    """Toolkit for identity threat detection operations."""

    def __init__(
        self,
        iam_provider: Any | None = None,
        ueba_engine: Any | None = None,
        threat_intel: Any | None = None,
        response_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._iam_provider = iam_provider
        self._ueba_engine = ueba_engine
        self._threat_intel = threat_intel
        self._response_engine = response_engine
        self._policy_engine = policy_engine
        self._repository = repository

    async def collect_auth_events(
        self,
        detection_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Collect authentication events from IAM."""
        sources = detection_config.get(
            "sources",
            ["azure_ad"],
        )
        logger.info(
            "itd.collect_auth_events",
            sources=sources,
        )
        events: list[dict[str, Any]] = []
        for source in sources:
            count = random.randint(5, 20)  # noqa: S311
            for _i in range(count):
                events.append(
                    {
                        "event_id": f"e-{uuid4().hex[:8]}",
                        "user_id": f"user-{uuid4().hex[:6]}",
                        "event_type": random.choice(  # noqa: S311
                            ["login", "mfa_challenge", "token_grant"],
                        ),
                        "source_ip": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",  # noqa: S311, E501
                        "geo_location": random.choice(  # noqa: S311
                            ["US", "GB", "DE", "CN", "RU"],
                        ),
                        "device_id": f"dev-{uuid4().hex[:6]}",
                        "mfa_used": random.random() > 0.3,  # noqa: S311
                        "success": random.random() > 0.2,  # noqa: S311
                        "metadata": {"source": source},
                    }
                )
        return events

    async def analyze_behavior(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Analyze user behavior from auth events."""
        logger.info(
            "itd.analyze_behavior",
            event_count=len(events),
        )
        users: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            uid = event.get("user_id", "")
            users.setdefault(uid, []).append(event)

        profiles: list[dict[str, Any]] = []
        for uid, user_events in users.items():
            locations = list(set(e.get("geo_location", "") for e in user_events))
            profiles.append(
                {
                    "user_id": uid,
                    "typical_locations": locations[:2],
                    "typical_hours": [9, 10, 11, 14, 15],
                    "typical_devices": list(set(e.get("device_id", "") for e in user_events))[:3],
                    "avg_session_duration_min": round(
                        random.uniform(15, 120),  # noqa: S311
                        1,
                    ),
                    "risk_baseline": round(
                        random.uniform(0.1, 0.4),  # noqa: S311
                        2,
                    ),
                }
            )
        return profiles

    async def detect_anomalies(
        self,
        events: list[dict[str, Any]],
        profiles: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect identity anomalies."""
        logger.info(
            "itd.detect_anomalies",
            event_count=len(events),
            profile_count=len(profiles),
        )
        profile_map = {p.get("user_id", ""): p for p in profiles}
        anomalies: list[dict[str, Any]] = []
        for event in events:
            uid = event.get("user_id", "")
            profile = profile_map.get(uid, {})
            typical_locs = profile.get(
                "typical_locations",
                [],
            )
            geo = event.get("geo_location", "")

            # Impossible travel detection
            if geo and typical_locs and geo not in typical_locs:
                confidence = round(
                    random.uniform(0.5, 0.95),  # noqa: S311
                    2,
                )
                threat = random.choice(  # noqa: S311
                    [
                        "impossible_travel",
                        "credential_stuffing",
                        "account_takeover",
                    ]
                )
                anomalies.append(
                    {
                        "anomaly_id": f"an-{uuid4().hex[:8]}",
                        "user_id": uid,
                        "threat_type": threat,
                        "confidence": confidence,
                        "indicators": [
                            f"unusual_location:{geo}",
                        ],
                        "description": (f"Anomalous {threat} for {uid}"),
                    }
                )
        return anomalies

    async def assess_identity_risk(
        self,
        anomalies: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Assess risk for identity anomalies."""
        logger.info(
            "itd.assess_identity_risk",
            anomaly_count=len(anomalies),
        )
        assessments: list[dict[str, Any]] = []
        for anomaly in anomalies:
            confidence = anomaly.get("confidence", 0.0)
            score = round(
                confidence * 90
                + random.uniform(  # noqa: S311
                    0,
                    10,
                ),
                1,
            )
            level = (
                "critical"
                if score > 80
                else "high"
                if score > 60
                else "medium"
                if score > 40
                else "low"
            )
            assessments.append(
                {
                    "assessment_id": f"ra-{uuid4().hex[:8]}",
                    "anomaly_id": anomaly.get(
                        "anomaly_id",
                        "",
                    ),
                    "user_id": anomaly.get("user_id", ""),
                    "risk_level": level,
                    "risk_score": score,
                    "business_impact": ("high" if score > 70 else "medium"),
                    "reasoning": "",
                }
            )
        return assessments

    async def respond_to_threat(
        self,
        anomalies: list[dict[str, Any]],
        assessments: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Respond to identity threats."""
        logger.info(
            "itd.respond_to_threat",
            anomaly_count=len(anomalies),
        )
        assessment_map = {a.get("anomaly_id", ""): a for a in assessments}
        actions: list[dict[str, Any]] = []
        for anomaly in anomalies:
            assessment = assessment_map.get(
                anomaly.get("anomaly_id", ""),
                {},
            )
            risk_level = assessment.get(
                "risk_level",
                "medium",
            )
            if risk_level == "critical":
                action_type = "lock_account"
            elif risk_level == "high":
                action_type = "force_mfa_reset"
            else:
                action_type = "alert"
            actions.append(
                {
                    "action_id": f"act-{uuid4().hex[:8]}",
                    "anomaly_id": anomaly.get(
                        "anomaly_id",
                        "",
                    ),
                    "action_type": action_type,
                    "success": True,
                    "details": f"risk={risk_level}",
                }
            )
        return actions

    async def record_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record an identity threat detection metric."""
        logger.info(
            "itd.record_metric",
            metric_type=metric_type,
            value=value,
        )
