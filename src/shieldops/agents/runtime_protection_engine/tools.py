"""Tool functions for the Runtime Protection Engine.

Bridges telemetry collection, behavior analysis, anomaly
detection, policy enforcement, and alert generation to
the LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.runtime_protection_engine.models import (
    AlertOutput,
    AnomalyDetection,
    BehaviorCategory,
    BehaviorProfile,
    EnforcementAction,
    PolicyEnforcement,
    RuntimeTelemetry,
)

logger = structlog.get_logger()


class RuntimeProtectionEngineToolkit:
    """Tools for the runtime protection engine agent.

    Injected into nodes at graph construction time to
    decouple agent logic from runtime infrastructure.
    """

    def __init__(
        self,
        telemetry_collector: Any | None = None,
        behavior_analyzer: Any | None = None,
        anomaly_detector: Any | None = None,
        policy_engine: Any | None = None,
        alert_manager: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._telemetry_collector = telemetry_collector
        self._behavior_analyzer = behavior_analyzer
        self._anomaly_detector = anomaly_detector
        self._policy_engine = policy_engine
        self._alert_manager = alert_manager
        self._repository = repository
        self._metrics: list[dict[str, Any]] = []

    # ---- Telemetry Collection ----

    async def collect_telemetry(
        self,
        tenant_id: str = "",
        agent_ids: list[str] | None = None,
    ) -> list[RuntimeTelemetry]:
        """Collect runtime telemetry from AI agent executions.

        Args:
            tenant_id: Tenant for scoping queries.
            agent_ids: Specific agents to collect from.

        Returns:
            List of RuntimeTelemetry objects.
        """
        events: list[RuntimeTelemetry] = []
        now = datetime.now(UTC)

        if self._telemetry_collector is not None:
            try:
                raw_events = await self._telemetry_collector.collect(
                    tenant_id=tenant_id, agent_ids=agent_ids
                )
                for raw in raw_events:
                    events.append(
                        RuntimeTelemetry(
                            telemetry_id=raw.get("id", f"tel-{uuid4().hex[:8]}"),
                            agent_id=raw.get("agent_id", ""),
                            agent_name=raw.get("agent_name", ""),
                            tool_call=raw.get("tool_call", ""),
                            parameters=raw.get("parameters", {}),
                            timestamp=raw.get("timestamp", now),
                            latency_ms=raw.get("latency_ms", 0),
                            token_count=raw.get("token_count", 0),
                            resource_usage=raw.get("resource_usage", {}),
                            session_id=raw.get("session_id", ""),
                            metadata=raw.get("metadata", {}),
                        )
                    )
            except Exception as e:
                logger.error(
                    "rpe_telemetry_collection_failed",
                    error=str(e),
                )
        else:
            # Mock telemetry data
            tool_calls = [
                "read_file",
                "write_file",
                "execute_query",
                "send_request",
                "modify_config",
                "access_secret",
                "create_resource",
                "delete_resource",
            ]
            mock_agents = agent_ids or [
                f"agent-{uuid4().hex[:6]}"
                for _unused_i in range(random.randint(3, 8))  # noqa: S311
            ]
            for agent_id in mock_agents:
                for _unused_j in range(random.randint(5, 20)):  # noqa: S311
                    events.append(
                        RuntimeTelemetry(
                            telemetry_id=f"tel-{uuid4().hex[:8]}",
                            agent_id=agent_id,
                            agent_name=f"agent_{agent_id[-6:]}",
                            tool_call=random.choice(tool_calls),  # noqa: S311
                            parameters={"mock": True},
                            timestamp=now,
                            latency_ms=random.randint(10, 5000),  # noqa: S311
                            token_count=random.randint(100, 10000),  # noqa: S311
                            resource_usage={
                                "cpu_pct": round(random.uniform(1, 95), 1),  # noqa: S311
                                "memory_mb": random.randint(50, 2000),  # noqa: S311
                            },
                            session_id=f"sess-{uuid4().hex[:8]}",
                            metadata={"mock": True},
                        )
                    )

        logger.info(
            "rpe_telemetry_collected",
            tenant_id=tenant_id,
            event_count=len(events),
        )
        return events

    # ---- Behavior Analysis ----

    async def analyze_behavior(
        self,
        telemetry: list[RuntimeTelemetry],
    ) -> list[BehaviorProfile]:
        """Analyze agent behavior from collected telemetry.

        Args:
            telemetry: Collected runtime telemetry.

        Returns:
            List of BehaviorProfile objects.
        """
        profiles: list[BehaviorProfile] = []

        # Group telemetry by agent
        by_agent: dict[str, list[RuntimeTelemetry]] = {}
        for event in telemetry:
            by_agent.setdefault(event.agent_id, []).append(event)

        for agent_id, events in by_agent.items():
            avg_latency = sum(e.latency_ms for e in events) / max(len(events), 1)
            call_freq = len(events) / max(1, 60)  # per minute estimate

            # Calculate deviation (mock baseline comparison)
            deviation = min(
                abs(call_freq - 0.5) / 2.0 + abs(avg_latency - 500) / 5000,
                1.0,
            )

            # Assign category based on deviation
            if deviation > 0.8:
                category = BehaviorCategory.MALICIOUS
            elif deviation > 0.6:
                category = BehaviorCategory.ANOMALOUS
            elif deviation > 0.4:
                category = BehaviorCategory.SUSPICIOUS
            else:
                category = BehaviorCategory.NORMAL

            sensitive_calls = [
                e
                for e in events
                if e.tool_call in ("access_secret", "delete_resource", "modify_config")
            ]
            patterns = []
            if sensitive_calls:
                patterns.append(f"sensitive_access:{len(sensitive_calls)}")
            if avg_latency > 2000:
                patterns.append("high_latency")
            if len(events) > 15:
                patterns.append("high_volume")

            profiles.append(
                BehaviorProfile(
                    profile_id=f"bhv-{uuid4().hex[:8]}",
                    agent_id=agent_id,
                    category=category,
                    tool_call_frequency=round(call_freq, 3),
                    avg_latency_ms=round(avg_latency, 1),
                    resource_pattern="normal" if deviation < 0.4 else "elevated",
                    deviation_score=round(deviation, 3),
                    baseline_comparison={
                        "expected_freq": 0.5,
                        "expected_latency": 500,
                        "deviation": round(deviation, 3),
                    },
                    observed_patterns=patterns,
                )
            )

        logger.info(
            "rpe_behavior_analyzed",
            agents=len(profiles),
            suspicious=sum(
                1
                for p in profiles
                if p.category
                in (
                    BehaviorCategory.SUSPICIOUS,
                    BehaviorCategory.ANOMALOUS,
                    BehaviorCategory.MALICIOUS,
                )
            ),
        )
        return profiles

    # ---- Anomaly Detection ----

    async def detect_anomalies(
        self,
        profiles: list[BehaviorProfile],
    ) -> list[AnomalyDetection]:
        """Detect anomalies from behavior profiles.

        Args:
            profiles: Analyzed behavior profiles.

        Returns:
            List of AnomalyDetection objects.
        """
        anomalies: list[AnomalyDetection] = []

        severity_map = {
            BehaviorCategory.MALICIOUS: "critical",
            BehaviorCategory.ANOMALOUS: "high",
            BehaviorCategory.SUSPICIOUS: "medium",
            BehaviorCategory.POLICY_VIOLATION: "medium",
            BehaviorCategory.RATE_EXCEEDED: "low",
            BehaviorCategory.PRIVILEGE_ESCALATION: "critical",
            BehaviorCategory.DATA_EXFILTRATION: "critical",
        }

        action_map = {
            "critical": EnforcementAction.BLOCK,
            "high": EnforcementAction.QUARANTINE,
            "medium": EnforcementAction.ALERT_ONLY,
            "low": EnforcementAction.ALERT_ONLY,
        }

        for profile in profiles:
            if profile.category == BehaviorCategory.NORMAL:
                continue

            severity = severity_map.get(profile.category, "medium")
            confidence = profile.deviation_score

            evidence = [
                f"deviation_score={profile.deviation_score}",
                f"category={profile.category.value}",
            ]
            evidence.extend(profile.observed_patterns)

            anomalies.append(
                AnomalyDetection(
                    anomaly_id=f"anom-{uuid4().hex[:8]}",
                    agent_id=profile.agent_id,
                    anomaly_type=profile.category.value,
                    severity=severity,
                    confidence=round(confidence, 3),
                    description=(
                        f"Agent {profile.agent_id} exhibits "
                        f"{profile.category.value} behavior "
                        f"(deviation: {profile.deviation_score:.2f})"
                    ),
                    evidence=evidence,
                    mitre_technique=(
                        "T1071" if "sensitive_access" in str(profile.observed_patterns) else ""
                    ),
                    recommended_action=action_map.get(severity, EnforcementAction.ALERT_ONLY),
                )
            )

        logger.info(
            "rpe_anomalies_detected",
            profiles=len(profiles),
            anomalies=len(anomalies),
            critical=sum(1 for a in anomalies if a.severity == "critical"),
        )
        return anomalies

    # ---- Policy Enforcement ----

    async def enforce_policies(
        self,
        anomalies: list[AnomalyDetection],
    ) -> list[PolicyEnforcement]:
        """Enforce security policies on detected anomalies.

        Args:
            anomalies: Detected anomalies to enforce against.

        Returns:
            List of PolicyEnforcement objects.
        """
        enforcements: list[PolicyEnforcement] = []
        now = datetime.now(UTC)

        for anomaly in anomalies:
            action = anomaly.recommended_action

            # Apply policy overrides
            if anomaly.confidence < 0.5 and action == EnforcementAction.BLOCK:
                action = EnforcementAction.REQUIRE_APPROVAL

            enforcements.append(
                PolicyEnforcement(
                    enforcement_id=f"enf-{uuid4().hex[:8]}",
                    anomaly_id=anomaly.anomaly_id,
                    action=action,
                    policy_name=f"runtime_protection_{anomaly.severity}",
                    applied_at=now,
                    success=True,
                    details=(
                        f"Applied {action.value} for "
                        f"{anomaly.anomaly_type} anomaly "
                        f"(confidence: {anomaly.confidence:.2f})"
                    ),
                    rollback_available=action
                    in (
                        EnforcementAction.BLOCK,
                        EnforcementAction.QUARANTINE,
                        EnforcementAction.TERMINATE_SESSION,
                    ),
                )
            )

        logger.info(
            "rpe_policies_enforced",
            anomalies=len(anomalies),
            enforcements=len(enforcements),
            blocked=sum(1 for e in enforcements if e.action == EnforcementAction.BLOCK),
        )
        return enforcements

    # ---- Alert Generation ----

    async def generate_alerts(
        self,
        anomalies: list[AnomalyDetection],
        enforcements: list[PolicyEnforcement],
    ) -> list[AlertOutput]:
        """Generate security alerts from anomalies and enforcements.

        Args:
            anomalies: Detected anomalies.
            enforcements: Policy enforcement actions.

        Returns:
            List of AlertOutput objects.
        """
        alerts: list[AlertOutput] = []
        now = datetime.now(UTC)

        enforcement_map = {e.anomaly_id: e for e in enforcements}

        # Group anomalies by agent for unified alerts
        by_agent: dict[str, list[AnomalyDetection]] = {}
        for anomaly in anomalies:
            by_agent.setdefault(anomaly.agent_id, []).append(anomaly)

        for agent_id, agent_anomalies in by_agent.items():
            max_severity = max(
                agent_anomalies,
                key=lambda a: ["low", "medium", "high", "critical"].index(a.severity),
            )

            anomaly_ids = [a.anomaly_id for a in agent_anomalies]
            enforcement_ids = [
                enforcement_map[a_id].enforcement_id
                for a_id in anomaly_ids
                if a_id in enforcement_map
            ]

            actions = []
            for anomaly in agent_anomalies:
                enf = enforcement_map.get(anomaly.anomaly_id)
                if enf:
                    actions.append(f"{enf.action.value}: {anomaly.anomaly_type}")

            alerts.append(
                AlertOutput(
                    alert_id=f"alert-{uuid4().hex[:8]}",
                    severity=max_severity.severity,
                    title=(
                        f"Runtime Protection: {max_severity.severity.upper()} "
                        f"anomaly on agent {agent_id}"
                    ),
                    description=(
                        f"{len(agent_anomalies)} anomalies detected on "
                        f"agent {agent_id}. "
                        f"Highest severity: {max_severity.severity}."
                    ),
                    agent_id=agent_id,
                    anomaly_ids=anomaly_ids,
                    enforcement_ids=enforcement_ids,
                    recommended_actions=actions,
                    created_at=now,
                )
            )

        logger.info(
            "rpe_alerts_generated",
            anomalies=len(anomalies),
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
        """Record a runtime protection engine metric."""
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
