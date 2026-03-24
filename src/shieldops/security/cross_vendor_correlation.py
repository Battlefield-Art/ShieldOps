"""Cross-Vendor Correlator — correlate findings across CrowdStrike, Defender, Wiz, and others."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CorrelationType(StrEnum):
    TEMPORAL = "temporal"
    ENTITY_BASED = "entity_based"
    TECHNIQUE_BASED = "technique_based"
    CAMPAIGN = "campaign"
    KILL_CHAIN = "kill_chain"


class ConfidenceLevel(StrEnum):
    SPECULATIVE = "speculative"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class CorrelationStatus(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


# --- Models ---


class CorrelationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor: str = ""
    finding_id: str = ""
    entity_id: str = ""
    entity_type: str = ""
    severity: str = ""
    title: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    kill_chain_phase: str = ""
    raw_finding: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class CorrelationRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    correlation_type: CorrelationType = CorrelationType.TEMPORAL
    conditions: dict[str, Any] = Field(default_factory=dict)
    min_vendor_count: int = 2
    time_window_seconds: float = 300.0
    enabled: bool = True
    created_at: float = Field(default_factory=time.time)


class CorrelationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_findings: int = 0
    total_situations: int = 0
    confirmed_count: int = 0
    escalated_count: int = 0
    by_vendor: dict[str, int] = Field(default_factory=dict)
    by_correlation_type: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=dict)
    avg_situation_score: float = 0.0
    multi_vendor_entities: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Situation model (internal) ---


class _Situation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    correlation_type: CorrelationType = CorrelationType.TEMPORAL
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    status: CorrelationStatus = CorrelationStatus.PENDING
    finding_ids: list[str] = Field(default_factory=list)
    vendors: list[str] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    created_at: float = Field(default_factory=time.time)


# --- Engine ---

_KILL_CHAIN_ORDER = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
]

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 1.0,
}


class CrossVendorCorrelator:
    """Correlate security findings across CrowdStrike, Defender, Wiz, and other vendors."""

    def __init__(
        self,
        max_records: int = 200000,
        default_time_window: float = 300.0,
    ) -> None:
        self._max_records = max_records
        self._default_time_window = default_time_window
        self._findings: list[CorrelationRecord] = []
        self._situations: list[_Situation] = []
        self._rules: list[CorrelationRule] = []
        logger.info(
            "cross_vendor_correlator.initialized",
            max_records=max_records,
            default_time_window=default_time_window,
        )

    # -- ingest ------------------------------------------------------------

    def add_finding(
        self,
        vendor: str,
        finding: dict[str, Any],
    ) -> CorrelationRecord:
        """Ingest a normalized finding from any vendor."""
        record = CorrelationRecord(
            vendor=vendor,
            finding_id=finding.get("id", ""),
            entity_id=finding.get("entity_id", ""),
            entity_type=finding.get("entity_type", ""),
            severity=finding.get("severity", "medium"),
            title=finding.get("title", ""),
            mitre_techniques=finding.get("mitre_techniques", []),
            kill_chain_phase=finding.get("kill_chain_phase", ""),
            raw_finding=finding,
        )
        self._findings.append(record)
        if len(self._findings) > self._max_records:
            self._findings = self._findings[-self._max_records :]
        logger.info(
            "cross_vendor_correlator.finding_added",
            record_id=record.id,
            vendor=vendor,
            entity_id=record.entity_id,
        )
        return record

    # -- correlation -------------------------------------------------------

    def correlate(
        self,
        time_window: float | None = None,
        entity_filter: str | None = None,
    ) -> list[_Situation]:
        """Run correlation rules across all findings, creating situations."""
        tw = time_window or self._default_time_window
        findings = self._findings
        if entity_filter:
            findings = [f for f in findings if f.entity_id == entity_filter]

        new_situations: list[_Situation] = []

        # 1) Entity-based: same entity, multiple vendors
        entity_groups: dict[str, list[CorrelationRecord]] = {}
        for f in findings:
            if f.entity_id:
                entity_groups.setdefault(f.entity_id, []).append(f)
        for entity_id, group in entity_groups.items():
            vendors = list({f.vendor for f in group})
            if len(vendors) >= 2:
                new_situations.append(
                    self._build_situation(
                        group,
                        CorrelationType.ENTITY_BASED,
                        f"Multi-vendor findings on entity {entity_id}",
                    )
                )

        # 2) Technique-based: same MITRE technique across vendors
        technique_groups: dict[str, list[CorrelationRecord]] = {}
        for f in findings:
            for tech in f.mitre_techniques:
                technique_groups.setdefault(tech, []).append(f)
        for tech, group in technique_groups.items():
            vendors = list({f.vendor for f in group})
            if len(vendors) >= 2:
                new_situations.append(
                    self._build_situation(
                        group,
                        CorrelationType.TECHNIQUE_BASED,
                        f"MITRE technique {tech} seen across {', '.join(vendors)}",
                    )
                )

        # 3) Temporal: findings within time window across vendors
        sorted_findings = sorted(findings, key=lambda x: x.created_at)
        i = 0
        while i < len(sorted_findings):
            base = sorted_findings[i]
            cluster = [base]
            for j in range(i + 1, len(sorted_findings)):
                if sorted_findings[j].created_at - base.created_at <= tw:
                    cluster.append(sorted_findings[j])
                else:
                    break
            cluster_vendors = {f.vendor for f in cluster}
            if len(cluster_vendors) >= 2 and len(cluster) >= 3:
                new_situations.append(
                    self._build_situation(
                        cluster,
                        CorrelationType.TEMPORAL,
                        f"Temporal cluster: {len(cluster)} findings in {tw}s window",
                    )
                )
            i += max(1, len(cluster) // 2)

        # 4) Kill-chain: progression across phases
        kc_phases: dict[str, list[CorrelationRecord]] = {}
        for f in findings:
            if f.kill_chain_phase:
                kc_phases.setdefault(f.kill_chain_phase, []).append(f)
        observed_phases = [p for p in _KILL_CHAIN_ORDER if p in kc_phases]
        if len(observed_phases) >= 3:
            chain_findings = []
            for p in observed_phases:
                chain_findings.extend(kc_phases[p])
            new_situations.append(
                self._build_situation(
                    chain_findings,
                    CorrelationType.KILL_CHAIN,
                    f"Kill-chain progression: {' -> '.join(observed_phases)}",
                )
            )

        self._situations.extend(new_situations)
        logger.info(
            "cross_vendor_correlator.correlation_complete",
            new_situations=len(new_situations),
            total_situations=len(self._situations),
        )
        return new_situations

    def create_situation(self, correlated_findings: list[CorrelationRecord]) -> _Situation:
        """Manually group correlated findings into a situation."""
        situation = self._build_situation(
            correlated_findings,
            CorrelationType.CAMPAIGN,
            f"Manual situation: {len(correlated_findings)} findings",
        )
        self._situations.append(situation)
        return situation

    def score_situation(self, situation_id: str) -> float:
        """Risk-score a situation based on MITRE coverage, entity count, and vendor agreement."""
        situation = self._get_situation(situation_id)
        if not situation:
            return 0.0

        # Base score from finding severities
        related = [f for f in self._findings if f.id in situation.finding_ids]
        severity_score = sum(_SEVERITY_WEIGHT.get(f.severity, 1.0) for f in related)

        # Multiplier for vendor diversity
        vendor_multiplier = 1.0 + (len(situation.vendors) - 1) * 0.3

        # Bonus for MITRE technique coverage
        technique_bonus = len(situation.mitre_techniques) * 2.0

        # Bonus for entity spread
        entity_bonus = len(situation.entities) * 1.5

        score = round((severity_score * vendor_multiplier) + technique_bonus + entity_bonus, 2)
        situation.risk_score = score

        # Set confidence based on vendor count and finding count
        finding_count = len(situation.finding_ids)
        if len(situation.vendors) >= 3 and finding_count >= 5:
            situation.confidence = ConfidenceLevel.CONFIRMED
        elif len(situation.vendors) >= 2 and finding_count >= 3:
            situation.confidence = ConfidenceLevel.HIGH
        elif len(situation.vendors) >= 2:
            situation.confidence = ConfidenceLevel.MEDIUM
        else:
            situation.confidence = ConfidenceLevel.LOW

        logger.info(
            "cross_vendor_correlator.situation_scored",
            situation_id=situation_id,
            score=score,
            confidence=situation.confidence.value,
        )
        return score

    # -- domain methods ----------------------------------------------------

    def get_high_confidence_situations(self) -> list[dict[str, Any]]:
        """Return situations with HIGH or CONFIRMED confidence."""
        return [
            {
                "situation_id": s.id,
                "title": s.title,
                "confidence": s.confidence.value,
                "risk_score": s.risk_score,
                "vendors": s.vendors,
                "finding_count": len(s.finding_ids),
            }
            for s in self._situations
            if s.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED)
        ]

    def get_vendor_coverage_gaps(self) -> list[dict[str, Any]]:
        """Identify entities seen by only one vendor (potential blind spots)."""
        entity_vendors: dict[str, set[str]] = {}
        for f in self._findings:
            if f.entity_id:
                entity_vendors.setdefault(f.entity_id, set()).add(f.vendor)
        gaps = [
            {
                "entity_id": eid,
                "sole_vendor": list(vendors)[0],
                "finding_count": sum(1 for f in self._findings if f.entity_id == eid),
            }
            for eid, vendors in entity_vendors.items()
            if len(vendors) == 1
        ]
        gaps.sort(key=lambda x: x["finding_count"], reverse=True)
        return gaps

    def get_attack_timeline(self) -> list[dict[str, Any]]:
        """Build a chronological timeline of findings across vendors."""
        sorted_findings = sorted(self._findings, key=lambda x: x.created_at)
        return [
            {
                "timestamp": f.created_at,
                "vendor": f.vendor,
                "title": f.title,
                "severity": f.severity,
                "entity_id": f.entity_id,
                "mitre_techniques": f.mitre_techniques,
                "kill_chain_phase": f.kill_chain_phase,
            }
            for f in sorted_findings[-200:]
        ]

    # -- report / stats / clear --------------------------------------------

    def generate_report(self) -> CorrelationReport:
        by_vendor: dict[str, int] = {}
        by_corr_type: dict[str, int] = {}
        by_confidence: dict[str, int] = {}
        confirmed = escalated = 0

        for f in self._findings:
            by_vendor[f.vendor] = by_vendor.get(f.vendor, 0) + 1
        for s in self._situations:
            by_corr_type[s.correlation_type.value] = (
                by_corr_type.get(s.correlation_type.value, 0) + 1
            )
            by_confidence[s.confidence.value] = by_confidence.get(s.confidence.value, 0) + 1
            if s.status == CorrelationStatus.CONFIRMED:
                confirmed += 1
            elif s.status == CorrelationStatus.ESCALATED:
                escalated += 1

        avg_score = (
            round(sum(s.risk_score for s in self._situations) / len(self._situations), 2)
            if self._situations
            else 0.0
        )

        entity_vendors: dict[str, set[str]] = {}
        for f in self._findings:
            if f.entity_id:
                entity_vendors.setdefault(f.entity_id, set()).add(f.vendor)
        multi_vendor = sum(1 for v in entity_vendors.values() if len(v) >= 2)

        recs: list[str] = []
        if escalated > 0:
            recs.append(f"{escalated} situation(s) escalated — require immediate review")
        if multi_vendor > 0:
            recs.append(f"{multi_vendor} entit(ies) seen across multiple vendors")
        if not recs:
            recs.append("Cross-vendor correlation nominal; no critical situations")

        return CorrelationReport(
            total_findings=len(self._findings),
            total_situations=len(self._situations),
            confirmed_count=confirmed,
            escalated_count=escalated,
            by_vendor=by_vendor,
            by_correlation_type=by_corr_type,
            by_confidence=by_confidence,
            avg_situation_score=avg_score,
            multi_vendor_entities=multi_vendor,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for s in self._situations:
            status_dist[s.status.value] = status_dist.get(s.status.value, 0) + 1
        return {
            "total_findings": len(self._findings),
            "total_situations": len(self._situations),
            "unique_vendors": len({f.vendor for f in self._findings}),
            "unique_entities": len({f.entity_id for f in self._findings if f.entity_id}),
            "situation_status_distribution": status_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._findings.clear()
        self._situations.clear()
        self._rules.clear()
        logger.info("cross_vendor_correlator.cleared")
        return {"status": "cleared"}

    # -- internal helpers --------------------------------------------------

    def _build_situation(
        self,
        findings: list[CorrelationRecord],
        corr_type: CorrelationType,
        title: str,
    ) -> _Situation:
        vendors = sorted({f.vendor for f in findings})
        entities = sorted({f.entity_id for f in findings if f.entity_id})
        techniques: list[str] = []
        for f in findings:
            techniques.extend(f.mitre_techniques)
        return _Situation(
            title=title,
            correlation_type=corr_type,
            finding_ids=[f.id for f in findings],
            vendors=vendors,
            entities=entities,
            mitre_techniques=sorted(set(techniques)),
        )

    def _get_situation(self, situation_id: str) -> _Situation | None:
        for s in self._situations:
            if s.id == situation_id:
                return s
        return None
