"""SOC Situation Engine — AI-curated, outcome-centric security situations."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SituationSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SituationStatus(StrEnum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    REMEDIATED = "remediated"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class ActionType(StrEnum):
    INVESTIGATE = "investigate"
    CONTAIN = "contain"
    REMEDIATE = "remediate"
    ESCALATE = "escalate"
    DISMISS = "dismiss"
    MONITOR = "monitor"


# --- Models ---


class SituationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    severity: SituationSeverity = SituationSeverity.MEDIUM
    status: SituationStatus = SituationStatus.NEW
    finding_ids: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)
    vendors: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    description: str = ""
    assigned_to: str = ""
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    timestamps: dict[str, float] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class RecommendedAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    situation_id: str = ""
    action_type: ActionType = ActionType.INVESTIGATE
    description: str = ""
    confidence: float = 0.0
    priority: int = 1
    target_connector: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class SituationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_situations: int = 0
    open_situations: int = 0
    resolved_situations: int = 0
    false_positives: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    avg_risk_score: float = 0.0
    mttd_seconds: float = 0.0
    mtta_seconds: float = 0.0
    mttr_seconds: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Status transition rules ---

_VALID_TRANSITIONS: dict[SituationStatus, list[SituationStatus]] = {
    SituationStatus.NEW: [SituationStatus.TRIAGING, SituationStatus.FALSE_POSITIVE],
    SituationStatus.TRIAGING: [
        SituationStatus.INVESTIGATING,
        SituationStatus.FALSE_POSITIVE,
        SituationStatus.CLOSED,
    ],
    SituationStatus.INVESTIGATING: [
        SituationStatus.CONTAINING,
        SituationStatus.REMEDIATED,
        SituationStatus.FALSE_POSITIVE,
    ],
    SituationStatus.CONTAINING: [SituationStatus.REMEDIATED, SituationStatus.INVESTIGATING],
    SituationStatus.REMEDIATED: [SituationStatus.CLOSED, SituationStatus.INVESTIGATING],
    SituationStatus.CLOSED: [],
    SituationStatus.FALSE_POSITIVE: [],
}

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 1.0,
}


# --- Engine ---


class SOCSituationEngine:
    """Create and manage AI-curated SOC situations — outcome-centric, cross-vendor."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._situations: list[SituationRecord] = []
        self._actions: list[RecommendedAction] = []
        logger.info("soc_situation_engine.initialized", max_records=max_records)

    # -- create / get / list -----------------------------------------------

    def create_situation(
        self,
        title: str,
        findings: list[dict[str, Any]],
        severity: SituationSeverity = SituationSeverity.MEDIUM,
        description: str = "",
    ) -> SituationRecord:
        """Create a new SOC situation from correlated findings."""
        finding_ids = [f.get("id", "") for f in findings]
        entity_ids = sorted({f.get("entity_id", "") for f in findings if f.get("entity_id")})
        vendors = sorted({f.get("vendor", "") for f in findings if f.get("vendor")})
        techniques: list[str] = []
        for f in findings:
            techniques.extend(f.get("mitre_techniques", []))

        risk = sum(_SEVERITY_WEIGHT.get(f.get("severity", "medium"), 1.0) for f in findings)
        vendor_mult = 1.0 + (len(vendors) - 1) * 0.3
        risk_score = round(risk * vendor_mult + len(set(techniques)) * 2.0, 2)

        situation = SituationRecord(
            title=title,
            severity=severity,
            status=SituationStatus.NEW,
            finding_ids=finding_ids,
            entity_ids=entity_ids,
            vendors=vendors,
            mitre_techniques=sorted(set(techniques)),
            risk_score=risk_score,
            description=description,
            timestamps={"created": time.time()},
        )
        self._situations.append(situation)
        if len(self._situations) > self._max_records:
            self._situations = self._situations[-self._max_records :]
        logger.info(
            "soc_situation_engine.situation_created",
            situation_id=situation.id,
            severity=severity.value,
            risk_score=risk_score,
            finding_count=len(finding_ids),
        )
        return situation

    def get_situation(self, situation_id: str) -> SituationRecord | None:
        for s in self._situations:
            if s.id == situation_id:
                return s
        return None

    def list_situations(
        self,
        severity: SituationSeverity | None = None,
        status: SituationStatus | None = None,
        limit: int = 50,
    ) -> list[SituationRecord]:
        results = list(self._situations)
        if severity is not None:
            results = [s for s in results if s.severity == severity]
        if status is not None:
            results = [s for s in results if s.status == status]
        return results[-limit:]

    # -- recommend actions -------------------------------------------------

    def recommend_actions(self, situation_id: str) -> list[RecommendedAction]:
        """Generate AI-recommended actions for a situation based on severity and context."""
        situation = self.get_situation(situation_id)
        if not situation:
            return []

        actions: list[RecommendedAction] = []
        sev = situation.severity

        # Always recommend investigation first
        actions.append(
            RecommendedAction(
                situation_id=situation_id,
                action_type=ActionType.INVESTIGATE,
                description=f"Investigate {len(situation.finding_ids)} findings across "
                f"{', '.join(situation.vendors) or 'vendors'}",
                confidence=0.95,
                priority=1,
            )
        )

        # Containment for high/critical
        if sev in (SituationSeverity.HIGH, SituationSeverity.CRITICAL):
            for entity_id in situation.entity_ids[:5]:
                connector = self._infer_connector(situation.vendors)
                actions.append(
                    RecommendedAction(
                        situation_id=situation_id,
                        action_type=ActionType.CONTAIN,
                        description=f"Contain entity {entity_id} via {connector}",
                        confidence=0.85 if sev == SituationSeverity.CRITICAL else 0.70,
                        priority=2,
                        target_connector=connector,
                        parameters={"entity_id": entity_id},
                    )
                )

        # Remediation for medium+
        if sev in (SituationSeverity.MEDIUM, SituationSeverity.HIGH, SituationSeverity.CRITICAL):
            actions.append(
                RecommendedAction(
                    situation_id=situation_id,
                    action_type=ActionType.REMEDIATE,
                    description="Apply automated remediation playbook",
                    confidence=0.65 if sev == SituationSeverity.MEDIUM else 0.80,
                    priority=3,
                    parameters={"mitre_techniques": situation.mitre_techniques},
                )
            )

        # Escalation for critical
        if sev == SituationSeverity.CRITICAL:
            actions.append(
                RecommendedAction(
                    situation_id=situation_id,
                    action_type=ActionType.ESCALATE,
                    description="Escalate to SOC Tier-3 / Incident Commander",
                    confidence=0.90,
                    priority=1,
                )
            )

        # Monitor for low/info
        if sev in (SituationSeverity.LOW, SituationSeverity.INFO):
            actions.append(
                RecommendedAction(
                    situation_id=situation_id,
                    action_type=ActionType.MONITOR,
                    description="Continue monitoring; no immediate action required",
                    confidence=0.90,
                    priority=4,
                )
            )

        self._actions.extend(actions)
        logger.info(
            "soc_situation_engine.actions_recommended",
            situation_id=situation_id,
            action_count=len(actions),
        )
        return actions

    # -- execute / update --------------------------------------------------

    def execute_action(
        self,
        situation_id: str,
        action_type: ActionType,
        result: str = "completed",
    ) -> SituationRecord | None:
        """Record execution of an action on a situation."""
        situation = self.get_situation(situation_id)
        if not situation:
            return None
        situation.actions_taken.append(
            {
                "action_type": action_type.value,
                "result": result,
                "executed_at": time.time(),
            }
        )
        # Auto-transition status based on action
        if action_type == ActionType.INVESTIGATE and situation.status == SituationStatus.NEW:
            situation.status = SituationStatus.INVESTIGATING
            situation.timestamps["investigating"] = time.time()
        elif action_type == ActionType.CONTAIN:
            situation.status = SituationStatus.CONTAINING
            situation.timestamps["containing"] = time.time()
        elif action_type == ActionType.REMEDIATE:
            situation.status = SituationStatus.REMEDIATED
            situation.timestamps["remediated"] = time.time()
        elif action_type == ActionType.DISMISS:
            situation.status = SituationStatus.FALSE_POSITIVE
            situation.timestamps["dismissed"] = time.time()
        logger.info(
            "soc_situation_engine.action_executed",
            situation_id=situation_id,
            action_type=action_type.value,
        )
        return situation

    def update_status(
        self,
        situation_id: str,
        new_status: SituationStatus,
    ) -> SituationRecord | None:
        """Update situation status with workflow transition validation."""
        situation = self.get_situation(situation_id)
        if not situation:
            return None
        allowed = _VALID_TRANSITIONS.get(situation.status, [])
        if new_status not in allowed:
            logger.warning(
                "soc_situation_engine.invalid_transition",
                situation_id=situation_id,
                from_status=situation.status.value,
                to_status=new_status.value,
            )
            return None
        situation.status = new_status
        situation.timestamps[new_status.value] = time.time()
        logger.info(
            "soc_situation_engine.status_updated",
            situation_id=situation_id,
            new_status=new_status.value,
        )
        return situation

    # -- metrics -----------------------------------------------------------

    def calculate_metrics(self) -> dict[str, float]:
        """Calculate MTTD, MTTA, MTTR per situation."""
        mttd_vals: list[float] = []
        mtta_vals: list[float] = []
        mttr_vals: list[float] = []

        for s in self._situations:
            ts = s.timestamps
            created = ts.get("created", s.created_at)

            # MTTD: time from first finding to situation creation (proxy)
            if "created" in ts:
                mttd_vals.append(0.0)  # Situation creation is detection proxy

            # MTTA: time from creation to first investigation/triage
            first_ack = ts.get("investigating") or ts.get("triaging")
            if first_ack:
                mtta_vals.append(first_ack - created)

            # MTTR: time from creation to remediation/close
            resolved = ts.get("remediated") or ts.get("closed") or ts.get("dismissed")
            if resolved:
                mttr_vals.append(resolved - created)

        def _avg(vals: list[float]) -> float:
            return round(sum(vals) / len(vals), 2) if vals else 0.0

        return {
            "mttd_seconds": _avg(mttd_vals),
            "mtta_seconds": _avg(mtta_vals),
            "mttr_seconds": _avg(mttr_vals),
            "situations_measured": len(self._situations),
        }

    # -- domain methods ----------------------------------------------------

    def get_active_situations(self) -> list[dict[str, Any]]:
        """Return all non-terminal situations ordered by risk score."""
        terminal = {SituationStatus.CLOSED, SituationStatus.FALSE_POSITIVE}
        active = [s for s in self._situations if s.status not in terminal]
        active.sort(key=lambda x: x.risk_score, reverse=True)
        return [
            {
                "situation_id": s.id,
                "title": s.title,
                "severity": s.severity.value,
                "status": s.status.value,
                "risk_score": s.risk_score,
                "vendors": s.vendors,
                "entity_count": len(s.entity_ids),
                "finding_count": len(s.finding_ids),
            }
            for s in active
        ]

    def get_severity_distribution(self) -> dict[str, int]:
        """Distribution of situations by severity."""
        dist: dict[str, int] = {}
        for s in self._situations:
            dist[s.severity.value] = dist.get(s.severity.value, 0) + 1
        return dist

    def get_vendor_involvement(self) -> list[dict[str, Any]]:
        """Analyze which vendors appear in situations and their frequency."""
        vendor_counts: dict[str, int] = {}
        vendor_severities: dict[str, dict[str, int]] = {}
        for s in self._situations:
            for v in s.vendors:
                vendor_counts[v] = vendor_counts.get(v, 0) + 1
                bucket = vendor_severities.setdefault(v, {})
                bucket[s.severity.value] = bucket.get(s.severity.value, 0) + 1
        results = [
            {
                "vendor": v,
                "situation_count": vendor_counts[v],
                "severity_breakdown": vendor_severities.get(v, {}),
            }
            for v in sorted(vendor_counts, key=vendor_counts.get, reverse=True)  # type: ignore[arg-type]
        ]
        return results

    # -- report / stats / clear --------------------------------------------

    def generate_report(self) -> SituationReport:
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        open_count = resolved = fp_count = 0
        terminal = {
            SituationStatus.CLOSED,
            SituationStatus.FALSE_POSITIVE,
            SituationStatus.REMEDIATED,
        }

        for s in self._situations:
            by_severity[s.severity.value] = by_severity.get(s.severity.value, 0) + 1
            by_status[s.status.value] = by_status.get(s.status.value, 0) + 1
            if s.status not in terminal:
                open_count += 1
            if s.status in (SituationStatus.CLOSED, SituationStatus.REMEDIATED):
                resolved += 1
            if s.status == SituationStatus.FALSE_POSITIVE:
                fp_count += 1

        avg_risk = (
            round(sum(s.risk_score for s in self._situations) / len(self._situations), 2)
            if self._situations
            else 0.0
        )
        metrics = self.calculate_metrics()

        recs: list[str] = []
        critical = by_severity.get("critical", 0)
        if critical > 0:
            recs.append(f"{critical} critical situation(s) — prioritize containment")
        if open_count > 10:
            recs.append(f"{open_count} open situations — review staffing and automation")
        if fp_count > 0:
            recs.append(f"{fp_count} false positive(s) — tune detection rules to reduce noise")
        if not recs:
            recs.append("SOC situation pipeline healthy; all situations managed")

        return SituationReport(
            total_situations=len(self._situations),
            open_situations=open_count,
            resolved_situations=resolved,
            false_positives=fp_count,
            by_severity=by_severity,
            by_status=by_status,
            avg_risk_score=avg_risk,
            mttd_seconds=metrics["mttd_seconds"],
            mtta_seconds=metrics["mtta_seconds"],
            mttr_seconds=metrics["mttr_seconds"],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for s in self._situations:
            status_dist[s.status.value] = status_dist.get(s.status.value, 0) + 1
        return {
            "total_situations": len(self._situations),
            "total_actions": len(self._actions),
            "status_distribution": status_dist,
            "unique_vendors": len({v for s in self._situations for v in s.vendors}),
            "unique_entities": len({e for s in self._situations for e in s.entity_ids}),
        }

    def clear_data(self) -> dict[str, str]:
        self._situations.clear()
        self._actions.clear()
        logger.info("soc_situation_engine.cleared")
        return {"status": "cleared"}

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _infer_connector(vendors: list[str]) -> str:
        """Infer the best connector for containment based on vendor list."""
        priority = ["crowdstrike", "microsoft_defender", "sentinel", "palo_alto"]
        for p in priority:
            if p in vendors:
                return p
        return vendors[0] if vendors else "unknown"
