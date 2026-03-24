"""NHIPostureMonitor — Track posture signals and enforce policies for NHIs."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PostureSignal(StrEnum):
    PERMISSION_CHANGE = "permission_change"
    CREDENTIAL_ROTATION = "credential_rotation"
    ACCESS_ANOMALY = "access_anomaly"
    OWNERSHIP_CHANGE = "ownership_change"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DORMANCY_ALERT = "dormancy_alert"


class PostureStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    AT_RISK = "at_risk"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class MonitorAction(StrEnum):
    ALERT = "alert"
    RESTRICT = "restrict"
    ROTATE = "rotate"
    REVOKE = "revoke"
    INVESTIGATE = "investigate"


# --- Models ---


class PostureRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nhi_id: str = ""
    signal_type: PostureSignal = PostureSignal.PERMISSION_CHANGE
    previous_state: str = ""
    current_state: str = ""
    severity: float = 0.0
    timestamp: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


class PosturePolicy(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nhi_type: str = ""
    max_idle_days: int = 90
    max_permissions: int = 10
    require_owner: bool = True
    require_rotation_days: int = 90
    created_at: float = Field(default_factory=time.time)


class PostureReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_policies: int = 0
    gap_count: int = 0
    avg_severity: float = 0.0
    by_signal_type: dict[str, int] = Field(default_factory=dict)
    by_posture_status: dict[str, int] = Field(default_factory=dict)
    by_monitor_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Signal severity weights ---

_SIGNAL_SEVERITY: dict[PostureSignal, float] = {
    PostureSignal.PERMISSION_CHANGE: 40.0,
    PostureSignal.CREDENTIAL_ROTATION: 20.0,
    PostureSignal.ACCESS_ANOMALY: 70.0,
    PostureSignal.OWNERSHIP_CHANGE: 30.0,
    PostureSignal.PRIVILEGE_ESCALATION: 85.0,
    PostureSignal.DORMANCY_ALERT: 50.0,
}


# --- Engine ---


class NHIPostureMonitor:
    """Track posture changes and enforce policies for non-human identities."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PostureRecord] = []
        self._policies: list[PosturePolicy] = []
        logger.info(
            "nhi_posture_monitor.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / policy -----------------------------------------------------

    def record_signal(
        self,
        nhi_id: str,
        signal_type: PostureSignal = PostureSignal.PERMISSION_CHANGE,
        previous_state: str = "",
        current_state: str = "",
        severity: float = 0.0,
    ) -> PostureRecord:
        if severity <= 0.0:
            severity = _SIGNAL_SEVERITY.get(signal_type, 30.0)
        record = PostureRecord(
            nhi_id=nhi_id,
            signal_type=signal_type,
            previous_state=previous_state,
            current_state=current_state,
            severity=severity,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "nhi_posture_monitor.signal_recorded",
            record_id=record.id,
            nhi_id=nhi_id,
            signal_type=signal_type.value,
            severity=severity,
        )
        return record

    def add_policy(
        self,
        nhi_type: str = "",
        max_idle_days: int = 90,
        max_permissions: int = 10,
        require_owner: bool = True,
        require_rotation_days: int = 90,
    ) -> PosturePolicy:
        policy = PosturePolicy(
            nhi_type=nhi_type,
            max_idle_days=max_idle_days,
            max_permissions=max_permissions,
            require_owner=require_owner,
            require_rotation_days=require_rotation_days,
        )
        self._policies.append(policy)
        logger.info(
            "nhi_posture_monitor.policy_added",
            nhi_type=nhi_type,
            max_idle_days=max_idle_days,
        )
        return policy

    # -- domain operations ---------------------------------------------------

    def evaluate_posture(self, nhi_id: str) -> dict[str, Any]:
        """Evaluate the current posture of an NHI based on signal history."""
        signals = [r for r in self._records if r.nhi_id == nhi_id]
        if not signals:
            return {"nhi_id": nhi_id, "status": PostureStatus.UNKNOWN.value, "signals": []}

        avg_severity = sum(s.severity for s in signals) / len(signals)
        max_severity = max(s.severity for s in signals)

        if max_severity >= 80:
            status = PostureStatus.CRITICAL
        elif max_severity >= 60 or avg_severity >= 50:
            status = PostureStatus.AT_RISK
        elif avg_severity >= 30:
            status = PostureStatus.DEGRADED
        else:
            status = PostureStatus.HEALTHY

        actions: list[str] = []
        if status == PostureStatus.CRITICAL:
            actions.extend([MonitorAction.REVOKE.value, MonitorAction.INVESTIGATE.value])
        elif status == PostureStatus.AT_RISK:
            actions.extend([MonitorAction.RESTRICT.value, MonitorAction.ALERT.value])
        elif status == PostureStatus.DEGRADED:
            actions.append(MonitorAction.ALERT.value)

        return {
            "nhi_id": nhi_id,
            "status": status.value,
            "signal_count": len(signals),
            "avg_severity": round(avg_severity, 1),
            "max_severity": round(max_severity, 1),
            "recommended_actions": actions,
            "latest_signal": signals[-1].signal_type.value,
        }

    def enforce_policy(
        self,
        nhi_id: str,
        policy: PosturePolicy,
    ) -> dict[str, Any]:
        """Check an NHI against a posture policy and return compliance result."""
        signals = [r for r in self._records if r.nhi_id == nhi_id]
        violations: list[str] = []

        # Check for recent privilege escalation signals
        escalations = [s for s in signals if s.signal_type == PostureSignal.PRIVILEGE_ESCALATION]
        if escalations:
            violations.append(f"{len(escalations)} privilege escalation events detected")

        # Check for dormancy alerts exceeding policy
        dormancy = [s for s in signals if s.signal_type == PostureSignal.DORMANCY_ALERT]
        if dormancy:
            violations.append(f"Dormancy alert(s) detected — max idle: {policy.max_idle_days} days")

        # Check credential rotation compliance
        rotations = [s for s in signals if s.signal_type == PostureSignal.CREDENTIAL_ROTATION]
        if not rotations and signals:
            violations.append(
                f"No credential rotation within {policy.require_rotation_days}-day window"
            )

        compliant = len(violations) == 0
        return {
            "nhi_id": nhi_id,
            "policy_id": policy.id,
            "compliant": compliant,
            "violations": violations,
            "signal_count": len(signals),
        }

    def detect_credential_age_violations(
        self,
        max_age_days: int = 90,
    ) -> list[dict[str, Any]]:
        """Identify NHIs with stale credentials based on rotation signals."""
        now = time.time()
        cutoff = now - max_age_days * 86400

        nhi_last_rotation: dict[str, float] = {}
        for r in self._records:
            if r.signal_type == PostureSignal.CREDENTIAL_ROTATION:
                current = nhi_last_rotation.get(r.nhi_id, 0.0)
                if r.timestamp > current:
                    nhi_last_rotation[r.nhi_id] = r.timestamp

        # NHIs with signals but no rotation
        all_nhis = {r.nhi_id for r in self._records}
        violations: list[dict[str, Any]] = []
        for nhi_id in all_nhis:
            last_rot = nhi_last_rotation.get(nhi_id, 0.0)
            if last_rot < cutoff:
                age_days = int((now - last_rot) / 86400) if last_rot > 0 else max_age_days + 1
                violations.append(
                    {
                        "nhi_id": nhi_id,
                        "last_rotation_days_ago": age_days,
                        "max_age_days": max_age_days,
                        "action": MonitorAction.ROTATE.value,
                    }
                )
        return sorted(violations, key=lambda x: x["last_rotation_days_ago"], reverse=True)

    # -- standard methods ----------------------------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.nhi_id == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        severities = [r.severity for r in matched]
        avg = round(sum(severities) / len(severities), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_severity": avg,
            "above_threshold": sum(1 for s in severities if s >= self._threshold),
        }

    def generate_report(self) -> PostureReport:
        by_signal: dict[str, int] = {}
        for r in self._records:
            by_signal[r.signal_type.value] = by_signal.get(r.signal_type.value, 0) + 1

        # Compute posture status for all known NHIs
        all_nhis = {r.nhi_id for r in self._records}
        posture_counts: dict[str, int] = {}
        action_counts: dict[str, int] = {}
        for nhi_id in all_nhis:
            posture = self.evaluate_posture(nhi_id)
            s = posture["status"]
            posture_counts[s] = posture_counts.get(s, 0) + 1
            for a in posture.get("recommended_actions", []):
                action_counts[a] = action_counts.get(a, 0) + 1

        severities = [r.severity for r in self._records]
        avg_sev = round(sum(severities) / len(severities), 2) if severities else 0.0
        gap_count = sum(1 for s in severities if s >= self._threshold)

        critical_nhis = [
            nhi
            for nhi in all_nhis
            if self.evaluate_posture(nhi)["status"] == PostureStatus.CRITICAL.value
        ]
        top_gaps = list(critical_nhis[:5])

        recs: list[str] = []
        if critical_nhis:
            recs.append(f"{len(critical_nhis)} NHI(s) in critical posture — revoke or investigate")
        cred_violations = self.detect_credential_age_violations()
        if cred_violations:
            recs.append(f"{len(cred_violations)} NHI(s) need credential rotation")
        if not recs:
            recs.append("NHI posture is healthy across all monitored identities")

        return PostureReport(
            total_records=len(self._records),
            total_policies=len(self._policies),
            gap_count=gap_count,
            avg_severity=avg_sev,
            by_signal_type=by_signal,
            by_posture_status=posture_counts,
            by_monitor_action=action_counts,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._policies.clear()
        logger.info("nhi_posture_monitor.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        signal_dist: dict[str, int] = {}
        for r in self._records:
            signal_dist[r.signal_type.value] = signal_dist.get(r.signal_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_policies": len(self._policies),
            "threshold": self._threshold,
            "signal_type_distribution": signal_dist,
            "unique_nhis": len({r.nhi_id for r in self._records}),
        }
