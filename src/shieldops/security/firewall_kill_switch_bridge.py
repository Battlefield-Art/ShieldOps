"""Firewall Kill Switch Bridge — connects behavioral firewall to the agent kill switch."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.security.agent_behavioral_firewall import AgentBehavioralFirewall
from shieldops.security.agent_kill_switch import AgentKillSwitch

logger = structlog.get_logger()


# --- Enums ---


class BridgeEvent(StrEnum):
    ANOMALY_DETECTED = "anomaly_detected"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    KILL_SWITCH_TRIPPED = "kill_switch_tripped"
    RECOVERY_INITIATED = "recovery_initiated"
    CIRCUIT_RESET = "circuit_reset"


class EscalationLevel(StrEnum):
    MONITOR = "monitor"
    WARN = "warn"
    RESTRICT = "restrict"
    KILL = "kill"


# --- Models ---


class BridgeEventRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    event_type: BridgeEvent = BridgeEvent.ANOMALY_DETECTED
    risk_score: float = 0.0
    anomaly_count_window: int = 0
    escalation_level: EscalationLevel = EscalationLevel.MONITOR
    action_taken: str = ""
    timestamp: float = Field(default_factory=time.time)


class EscalationConfig(BaseModel):
    monitor_threshold: float = 0.3
    warn_threshold: float = 0.5
    restrict_threshold: float = 0.7
    kill_threshold: float = 0.85
    window_minutes: int = 5
    min_anomalies_to_escalate: int = 3


class BridgeReport(BaseModel):
    total_events: int = 0
    escalations_by_level: dict[str, int] = Field(default_factory=dict)
    agents_currently_restricted: list[str] = Field(default_factory=list)
    auto_kills_triggered: int = 0
    avg_time_to_kill_seconds: float = 0.0
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class FirewallKillSwitchBridge:
    """Connects the Agent Behavioral Firewall to the Agent Kill Switch.

    Monitors firewall anomalies and automatically escalates through
    monitor -> warn -> restrict -> kill based on risk scores and anomaly
    frequency within a configurable time window.
    """

    def __init__(
        self,
        config: EscalationConfig | None = None,
        max_records: int = 200000,
    ) -> None:
        self._config = config or EscalationConfig()
        self._max_records = max_records
        self._records: list[BridgeEventRecord] = []
        self._agent_levels: dict[str, EscalationLevel] = {}
        self._agent_anomaly_times: dict[str, list[float]] = {}
        self._agent_first_anomaly: dict[str, float] = {}
        self._kill_timestamps: dict[str, float] = {}
        logger.info(
            "firewall_kill_switch_bridge.initialized",
            kill_threshold=self._config.kill_threshold,
            window_minutes=self._config.window_minutes,
        )

    # -- core operations ---------------------------------------------------

    def evaluate_and_escalate(
        self,
        agent_id: str,
        firewall: AgentBehavioralFirewall,
        kill_switch: AgentKillSwitch,
    ) -> BridgeEventRecord:
        """Check firewall risk for an agent and escalate appropriately.

        Queries the firewall for the agent's risk summary, determines the
        correct escalation level, and trips the kill switch if needed.
        """
        summary = firewall.get_agent_risk_summary(agent_id)
        risk_score = summary.get("avg_risk_score", 0.0)
        anomaly_count = self._count_recent_anomalies(agent_id)
        level = self._determine_level(risk_score, anomaly_count)

        action_taken = f"escalation_level={level.value}"
        event_type = BridgeEvent.ANOMALY_DETECTED

        previous_level = self._agent_levels.get(agent_id, EscalationLevel.MONITOR)

        if level == EscalationLevel.KILL:
            tripped = kill_switch.check_auto_trip(agent_id, risk_score)
            if tripped:
                event_type = BridgeEvent.KILL_SWITCH_TRIPPED
                action_taken = "kill_switch_tripped"
                self._kill_timestamps[agent_id] = time.time()
            else:
                # Already tripped or risk lowered — still record
                event_type = BridgeEvent.THRESHOLD_EXCEEDED
                action_taken = "kill_threshold_exceeded_already_open"
        elif _level_order(level) > _level_order(previous_level):
            event_type = BridgeEvent.THRESHOLD_EXCEEDED
            action_taken = f"escalated_{previous_level.value}_to_{level.value}"

        self._agent_levels[agent_id] = level

        record = BridgeEventRecord(
            agent_id=agent_id,
            event_type=event_type,
            risk_score=round(risk_score, 4),
            anomaly_count_window=anomaly_count,
            escalation_level=level,
            action_taken=action_taken,
        )
        self._append_record(record)

        logger.info(
            "firewall_kill_switch_bridge.evaluated",
            agent_id=agent_id,
            risk_score=risk_score,
            escalation_level=level.value,
            action=action_taken,
        )
        return record

    def on_anomaly_detected(
        self,
        agent_id: str,
        anomaly_type: str,
        risk_score: float,
    ) -> BridgeEventRecord:
        """Called by the firewall when an anomaly is found."""
        now = time.time()

        # Track anomaly times for windowed counting
        if agent_id not in self._agent_anomaly_times:
            self._agent_anomaly_times[agent_id] = []
            self._agent_first_anomaly[agent_id] = now
        self._agent_anomaly_times[agent_id].append(now)

        anomaly_count = self._count_recent_anomalies(agent_id)
        level = self._determine_level(risk_score, anomaly_count)
        self._agent_levels[agent_id] = level

        record = BridgeEventRecord(
            agent_id=agent_id,
            event_type=BridgeEvent.ANOMALY_DETECTED,
            risk_score=round(risk_score, 4),
            anomaly_count_window=anomaly_count,
            escalation_level=level,
            action_taken=f"anomaly_{anomaly_type}_level_{level.value}",
        )
        self._append_record(record)

        logger.info(
            "firewall_kill_switch_bridge.anomaly",
            agent_id=agent_id,
            anomaly_type=anomaly_type,
            risk_score=risk_score,
            anomaly_count=anomaly_count,
            level=level.value,
        )
        return record

    def on_policy_violation(
        self,
        agent_id: str,
        violation_severity: float,
    ) -> BridgeEventRecord:
        """Called by the firewall on a policy violation."""
        # Policy violations are treated as high-signal anomalies
        boosted_score = min(violation_severity * 1.2, 1.0)
        now = time.time()

        if agent_id not in self._agent_anomaly_times:
            self._agent_anomaly_times[agent_id] = []
            self._agent_first_anomaly[agent_id] = now
        self._agent_anomaly_times[agent_id].append(now)

        anomaly_count = self._count_recent_anomalies(agent_id)
        level = self._determine_level(boosted_score, anomaly_count)
        self._agent_levels[agent_id] = level

        record = BridgeEventRecord(
            agent_id=agent_id,
            event_type=BridgeEvent.THRESHOLD_EXCEEDED,
            risk_score=round(boosted_score, 4),
            anomaly_count_window=anomaly_count,
            escalation_level=level,
            action_taken=f"policy_violation_severity_{violation_severity:.2f}",
        )
        self._append_record(record)

        logger.info(
            "firewall_kill_switch_bridge.policy_violation",
            agent_id=agent_id,
            severity=violation_severity,
            boosted_score=boosted_score,
            level=level.value,
        )
        return record

    def get_escalation_level(self, agent_id: str) -> EscalationLevel:
        """Return the current escalation level for an agent."""
        return self._agent_levels.get(agent_id, EscalationLevel.MONITOR)

    # -- report / stats ----------------------------------------------------

    def generate_bridge_report(self) -> BridgeReport:
        """Generate a summary report of bridge activity."""
        escalations: dict[str, int] = {}
        kill_count = 0
        kill_times: list[float] = []

        for r in self._records:
            key = r.escalation_level.value
            escalations[key] = escalations.get(key, 0) + 1
            if r.event_type == BridgeEvent.KILL_SWITCH_TRIPPED:
                kill_count += 1
                first = self._agent_first_anomaly.get(r.agent_id, r.timestamp)
                kill_times.append(r.timestamp - first)

        restricted = [
            aid
            for aid, lvl in self._agent_levels.items()
            if lvl in (EscalationLevel.RESTRICT, EscalationLevel.KILL)
        ]

        avg_ttk = round(sum(kill_times) / len(kill_times), 2) if kill_times else 0.0

        return BridgeReport(
            total_events=len(self._records),
            escalations_by_level=escalations,
            agents_currently_restricted=restricted,
            auto_kills_triggered=kill_count,
            avg_time_to_kill_seconds=avg_ttk,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return bridge statistics."""
        level_dist: dict[str, int] = {}
        for lvl in self._agent_levels.values():
            level_dist[lvl.value] = level_dist.get(lvl.value, 0) + 1
        return {
            "total_events": len(self._records),
            "unique_agents": len({r.agent_id for r in self._records}),
            "level_distribution": level_dist,
            "agents_tracked": len(self._agent_levels),
        }

    def clear_data(self) -> dict[str, str]:
        """Clear all bridge state."""
        self._records.clear()
        self._agent_levels.clear()
        self._agent_anomaly_times.clear()
        self._agent_first_anomaly.clear()
        self._kill_timestamps.clear()
        logger.info("firewall_kill_switch_bridge.cleared")
        return {"status": "cleared"}

    # -- private helpers ---------------------------------------------------

    def _count_recent_anomalies(self, agent_id: str) -> int:
        """Count anomalies within the configured time window."""
        times = self._agent_anomaly_times.get(agent_id, [])
        if not times:
            return 0
        cutoff = time.time() - (self._config.window_minutes * 60)
        recent = [t for t in times if t >= cutoff]
        # Prune old entries
        self._agent_anomaly_times[agent_id] = recent
        return len(recent)

    def _determine_level(
        self,
        risk_score: float,
        anomaly_count: int,
    ) -> EscalationLevel:
        """Determine escalation level from risk score and anomaly count."""
        cfg = self._config

        # Kill requires both high risk AND sufficient anomaly count
        if risk_score >= cfg.kill_threshold and anomaly_count >= cfg.min_anomalies_to_escalate:
            return EscalationLevel.KILL

        if risk_score >= cfg.restrict_threshold:
            return EscalationLevel.RESTRICT

        if risk_score >= cfg.warn_threshold:
            return EscalationLevel.WARN

        if risk_score >= cfg.monitor_threshold:
            return EscalationLevel.MONITOR

        return EscalationLevel.MONITOR

    def _append_record(self, record: BridgeEventRecord) -> None:
        """Append a record with ring-buffer eviction."""
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]


def _level_order(level: EscalationLevel) -> int:
    """Numeric ordering for escalation comparison."""
    return {
        EscalationLevel.MONITOR: 0,
        EscalationLevel.WARN: 1,
        EscalationLevel.RESTRICT: 2,
        EscalationLevel.KILL: 3,
    }.get(level, 0)
