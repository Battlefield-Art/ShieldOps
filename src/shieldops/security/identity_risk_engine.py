"""Identity Risk Engine — unified risk scoring across all identity types.

Enhanced with Phase 3 CrowdStrike disruption capabilities: risk factor
decomposition, entity-type-aware scoring, and actionable recommendations
for zero-trust enforcement.
"""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RiskFactor(StrEnum):
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    NO_MFA = "no_mfa"
    STALE_CREDENTIALS = "stale_credentials"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"


class EntityType(StrEnum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    AI_AGENT = "ai_agent"
    FEDERATED_IDENTITY = "federated_identity"
    GUEST = "guest"
    EXTERNAL_CONTRACTOR = "external_contractor"


class RiskAction(StrEnum):
    MONITOR = "monitor"
    RESTRICT = "restrict"
    REQUIRE_MFA = "require_mfa"
    REVOKE = "revoke"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"


# --- Models ---


class IdentityRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    identity_id: str = ""
    identity_name: str = ""
    entity_type: EntityType = EntityType.HUMAN
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    composite_risk_score: float = 0.0
    recommended_action: RiskAction = RiskAction.MONITOR
    details: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskSignal(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    identity_id: str = ""
    risk_factor: RiskFactor = RiskFactor.EXCESSIVE_PERMISSIONS
    severity: float = 0.0
    evidence: str = ""
    source: str = ""
    detected_at: float = Field(default_factory=time.time)


class IdentityRiskReport(BaseModel):
    total_identities: int = 0
    total_signals: int = 0
    high_risk_count: int = 0
    by_entity_type: dict[str, int] = Field(default_factory=dict)
    by_risk_factor: dict[str, int] = Field(default_factory=dict)
    action_recommendations: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---

_RISK_FACTOR_WEIGHTS: dict[RiskFactor, float] = {
    RiskFactor.EXCESSIVE_PERMISSIONS: 15.0,
    RiskFactor.NO_MFA: 25.0,
    RiskFactor.STALE_CREDENTIALS: 10.0,
    RiskFactor.IMPOSSIBLE_TRAVEL: 30.0,
    RiskFactor.PRIVILEGE_ESCALATION: 35.0,
    RiskFactor.LATERAL_MOVEMENT: 40.0,
}


class IdentityRiskEngine:
    """Unified risk scoring across all identity types."""

    def __init__(self, max_records: int = 200000, high_risk_threshold: float = 60.0) -> None:
        self._max_records = max_records
        self._high_risk_threshold = high_risk_threshold
        self._records: list[IdentityRiskRecord] = []
        self._signals: list[RiskSignal] = []
        logger.info(
            "identity_risk_engine.initialized",
            max_records=max_records,
            high_risk_threshold=high_risk_threshold,
        )

    # -- record --------------------------------------------------------------

    def add_risk_signal(
        self,
        identity_id: str,
        risk_factor: RiskFactor = RiskFactor.EXCESSIVE_PERMISSIONS,
        severity: float = 0.0,
        evidence: str = "",
        source: str = "",
    ) -> RiskSignal:
        signal = RiskSignal(
            identity_id=identity_id,
            risk_factor=risk_factor,
            severity=severity,
            evidence=evidence,
            source=source,
        )
        self._signals.append(signal)
        if len(self._signals) > self._max_records:
            self._signals = self._signals[-self._max_records :]
        logger.info(
            "identity_risk_engine.signal_added",
            identity_id=identity_id,
            risk_factor=risk_factor.value,
            severity=severity,
        )
        return signal

    # -- domain operations ---------------------------------------------------

    def calculate_composite_risk(self, identity_id: str) -> IdentityRiskRecord:
        """Calculate composite risk score from all signals for an identity."""
        signals = [s for s in self._signals if s.identity_id == identity_id]
        if not signals:
            return IdentityRiskRecord(identity_id=identity_id, composite_risk_score=0.0)

        # Weighted sum of unique risk factors, capped at 100
        factor_max: dict[RiskFactor, float] = {}
        for s in signals:
            existing = factor_max.get(s.risk_factor, 0.0)
            factor_max[s.risk_factor] = max(existing, s.severity)

        score = 0.0
        factors_present: list[RiskFactor] = []
        for factor, max_severity in factor_max.items():
            weight = _RISK_FACTOR_WEIGHTS.get(factor, 10.0)
            score += weight * (max_severity / 100.0)
            factors_present.append(factor)
        score = min(score, 100.0)

        # Determine recommended action
        action = RiskAction.MONITOR
        if score >= 80:
            action = RiskAction.QUARANTINE
        elif score >= 60:
            action = RiskAction.REVOKE
        elif score >= 40:
            action = RiskAction.RESTRICT
        elif score >= 20:
            action = RiskAction.REQUIRE_MFA

        record = IdentityRiskRecord(
            identity_id=identity_id,
            risk_factors=factors_present,
            composite_risk_score=round(score, 2),
            recommended_action=action,
            details=f"{len(signals)} signals across {len(factors_present)} risk factors",
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        return record

    def detect_anomalous_access(self) -> list[dict[str, Any]]:
        """Find identities with impossible travel or lateral movement signals."""
        anomalous_factors = {RiskFactor.IMPOSSIBLE_TRAVEL, RiskFactor.LATERAL_MOVEMENT}
        identity_signals: dict[str, list[RiskSignal]] = {}
        for s in self._signals:
            if s.risk_factor in anomalous_factors:
                identity_signals.setdefault(s.identity_id, []).append(s)

        results: list[dict[str, Any]] = []
        for identity_id, sigs in identity_signals.items():
            results.append(
                {
                    "identity_id": identity_id,
                    "anomalous_signals": len(sigs),
                    "factors": list({s.risk_factor.value for s in sigs}),
                    "max_severity": max(s.severity for s in sigs),
                    "evidence": [s.evidence for s in sigs[:5]],
                }
            )
        results.sort(key=lambda x: x["max_severity"], reverse=True)
        return results

    def recommend_actions(self) -> list[dict[str, Any]]:
        """Generate action recommendations for all assessed identities."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.recommended_action != RiskAction.MONITOR:
                results.append(
                    {
                        "identity_id": r.identity_id,
                        "identity_name": r.identity_name,
                        "entity_type": r.entity_type.value,
                        "risk_score": r.composite_risk_score,
                        "recommended_action": r.recommended_action.value,
                        "risk_factors": [f.value for f in r.risk_factors],
                    }
                )
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results

    # -- report / stats ------------------------------------------------------

    def generate_risk_report(self) -> IdentityRiskReport:
        by_entity: dict[str, int] = {}
        by_factor: dict[str, int] = {}
        action_recs: dict[str, int] = {}

        for r in self._records:
            by_entity[r.entity_type.value] = by_entity.get(r.entity_type.value, 0) + 1
            action_recs[r.recommended_action.value] = (
                action_recs.get(r.recommended_action.value, 0) + 1
            )
            for f in r.risk_factors:
                by_factor[f.value] = by_factor.get(f.value, 0) + 1

        high_risk = sum(
            1 for r in self._records if r.composite_risk_score >= self._high_risk_threshold
        )

        recs: list[str] = []
        anomalous = self.detect_anomalous_access()
        if anomalous:
            recs.append(f"{len(anomalous)} identities with anomalous access patterns")
        if high_risk:
            recs.append(f"{high_risk} high-risk identities require immediate attention")
        if not recs:
            recs.append("Identity risk posture meets targets")

        return IdentityRiskReport(
            total_identities=len(self._records),
            total_signals=len(self._signals),
            high_risk_count=high_risk,
            by_entity_type=by_entity,
            by_risk_factor=by_factor,
            action_recommendations=action_recs,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        factor_dist: dict[str, int] = {}
        for s in self._signals:
            factor_dist[s.risk_factor.value] = factor_dist.get(s.risk_factor.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_signals": len(self._signals),
            "high_risk_threshold": self._high_risk_threshold,
            "risk_factor_distribution": factor_dist,
            "unique_identities": len({s.identity_id for s in self._signals}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._signals.clear()
        logger.info("identity_risk_engine.cleared")
        return {"status": "cleared"}
