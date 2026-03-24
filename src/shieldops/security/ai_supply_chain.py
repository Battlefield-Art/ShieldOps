"""AI Supply Chain Scanner — verify integrity and provenance of AI components."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ComponentType(StrEnum):
    MODEL_WEIGHTS = "model_weights"
    TOKENIZER = "tokenizer"
    EMBEDDING_MODEL = "embedding_model"
    VECTOR_DB = "vector_db"
    RAG_PIPELINE = "rag_pipeline"
    PLUGIN = "plugin"
    TOOL_INTEGRATION = "tool_integration"


class RiskLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SupplyChainStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    DEPRECATED = "deprecated"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


# --- Models ---


class AIComponentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    version: str = ""
    component_type: ComponentType = ComponentType.PLUGIN
    risk_level: RiskLevel = RiskLevel.LOW
    status: SupplyChainStatus = SupplyChainStatus.UNVERIFIED
    integrity_hash: str = ""
    provider: str = ""
    app_id: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class VulnerabilityFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    component_id: str = ""
    cve_id: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    description: str = ""
    remediation: str = ""
    exploitable: bool = False
    created_at: float = Field(default_factory=time.time)


class SupplyChainReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_components: int = 0
    total_vulnerabilities: int = 0
    verified_count: int = 0
    compromised_count: int = 0
    avg_risk_score: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    critical_findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Risk scoring weights ---

_RISK_WEIGHTS: dict[RiskLevel, float] = {
    RiskLevel.NONE: 0.0,
    RiskLevel.LOW: 0.2,
    RiskLevel.MEDIUM: 0.5,
    RiskLevel.HIGH: 0.8,
    RiskLevel.CRITICAL: 1.0,
}

_COMPONENT_BASE_RISK: dict[ComponentType, RiskLevel] = {
    ComponentType.MODEL_WEIGHTS: RiskLevel.HIGH,
    ComponentType.TOKENIZER: RiskLevel.MEDIUM,
    ComponentType.EMBEDDING_MODEL: RiskLevel.MEDIUM,
    ComponentType.VECTOR_DB: RiskLevel.MEDIUM,
    ComponentType.RAG_PIPELINE: RiskLevel.HIGH,
    ComponentType.PLUGIN: RiskLevel.CRITICAL,
    ComponentType.TOOL_INTEGRATION: RiskLevel.HIGH,
}


# --- Engine ---


class AISupplyChainScanner:
    """Verify integrity and provenance of AI supply chain components."""

    def __init__(
        self,
        max_records: int = 200000,
        auto_quarantine_compromised: bool = True,
    ) -> None:
        self._max_records = max_records
        self._auto_quarantine = auto_quarantine_compromised
        self._components: list[AIComponentRecord] = []
        self._vulnerabilities: list[VulnerabilityFinding] = []
        logger.info(
            "ai_supply_chain_scanner.initialized",
            max_records=max_records,
            auto_quarantine=auto_quarantine_compromised,
        )

    # -- registration / query --------------------------------------------------

    def register_component(
        self,
        name: str,
        version: str = "",
        component_type: ComponentType = ComponentType.PLUGIN,
        risk_level: RiskLevel = RiskLevel.LOW,
        status: SupplyChainStatus = SupplyChainStatus.UNVERIFIED,
        integrity_hash: str = "",
        provider: str = "",
        app_id: str = "",
        description: str = "",
    ) -> AIComponentRecord:
        component = AIComponentRecord(
            name=name,
            version=version,
            component_type=component_type,
            risk_level=risk_level,
            status=status,
            integrity_hash=integrity_hash,
            provider=provider,
            app_id=app_id,
            description=description,
        )
        self._components.append(component)
        if len(self._components) > self._max_records:
            self._components = self._components[-self._max_records :]
        logger.info(
            "ai_supply_chain_scanner.component_registered",
            component_id=component.id,
            name=name,
            component_type=component_type.value,
        )
        return component

    # -- domain operations -----------------------------------------------------

    def scan_component(self, component_id: str) -> dict[str, Any]:
        """Scan a component for known vulnerabilities."""
        component = next((c for c in self._components if c.id == component_id), None)
        if component is None:
            return {"error": "component_not_found", "component_id": component_id}

        base_risk = _COMPONENT_BASE_RISK.get(component.component_type, RiskLevel.MEDIUM)
        risk_weight = _RISK_WEIGHTS[base_risk]

        # Adjust risk based on status
        if component.status == SupplyChainStatus.COMPROMISED:
            risk_weight = 1.0
        elif component.status == SupplyChainStatus.VERIFIED:
            risk_weight *= 0.5
        elif component.status == SupplyChainStatus.DEPRECATED:
            risk_weight = min(1.0, risk_weight + 0.2)

        return {
            "component_id": component_id,
            "name": component.name,
            "base_risk": base_risk.value,
            "adjusted_risk_score": round(risk_weight, 2),
            "status": component.status.value,
            "integrity_hash": component.integrity_hash,
            "vulnerabilities_found": len(
                [v for v in self._vulnerabilities if v.component_id == component_id]
            ),
        }

    def check_integrity(self, component_id: str, expected_hash: str) -> dict[str, Any]:
        """Verify component integrity against expected hash."""
        component = next((c for c in self._components if c.id == component_id), None)
        if component is None:
            return {"error": "component_not_found", "component_id": component_id}

        matches = component.integrity_hash == expected_hash if expected_hash else False
        if not matches and self._auto_quarantine:
            component.status = SupplyChainStatus.QUARANTINED
            logger.warning(
                "ai_supply_chain_scanner.integrity_mismatch",
                component_id=component_id,
                quarantined=True,
            )
        return {
            "component_id": component_id,
            "name": component.name,
            "integrity_valid": matches,
            "status": component.status.value,
        }

    def detect_backdoor_indicators(self) -> list[dict[str, Any]]:
        """Detect potential backdoor indicators in registered components."""
        indicators: list[dict[str, Any]] = []
        for component in self._components:
            risk_signals: list[str] = []
            if component.status == SupplyChainStatus.UNVERIFIED:
                risk_signals.append("unverified_provenance")
            if (
                component.component_type
                in (
                    ComponentType.MODEL_WEIGHTS,
                    ComponentType.PLUGIN,
                )
                and not component.integrity_hash
            ):
                risk_signals.append("missing_integrity_hash")
            if component.status == SupplyChainStatus.DEPRECATED:
                risk_signals.append("deprecated_component")

            if risk_signals:
                indicators.append(
                    {
                        "component_id": component.id,
                        "name": component.name,
                        "type": component.component_type.value,
                        "risk_signals": risk_signals,
                        "signal_count": len(risk_signals),
                        "risk_level": "high" if len(risk_signals) >= 2 else "medium",
                    }
                )
        return indicators

    def verify_provenance(self, component_id: str) -> dict[str, Any]:
        """Verify the provenance chain for a component."""
        component = next((c for c in self._components if c.id == component_id), None)
        if component is None:
            return {"error": "component_not_found"}

        checks: dict[str, bool] = {
            "has_provider": bool(component.provider),
            "has_version": bool(component.version),
            "has_integrity_hash": bool(component.integrity_hash),
            "is_verified": component.status == SupplyChainStatus.VERIFIED,
        }
        passed = sum(1 for v in checks.values() if v)
        total = len(checks)

        if passed == total:
            component.status = SupplyChainStatus.VERIFIED
        return {
            "component_id": component_id,
            "name": component.name,
            "provenance_checks": checks,
            "passed": passed,
            "total": total,
            "provenance_score": round(passed / total * 100, 1),
            "status": component.status.value,
        }

    # -- report / stats --------------------------------------------------------

    def generate_report(self) -> SupplyChainReport:
        by_type: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for c in self._components:
            by_type[c.component_type.value] = by_type.get(c.component_type.value, 0) + 1
            by_risk[c.risk_level.value] = by_risk.get(c.risk_level.value, 0) + 1
            by_status[c.status.value] = by_status.get(c.status.value, 0) + 1

        verified = sum(1 for c in self._components if c.status == SupplyChainStatus.VERIFIED)
        compromised = sum(1 for c in self._components if c.status == SupplyChainStatus.COMPROMISED)
        avg_risk = (
            round(
                sum(_RISK_WEIGHTS.get(c.risk_level, 0.5) for c in self._components)
                / len(self._components),
                2,
            )
            if self._components
            else 0.0
        )

        critical = [
            f"{v.cve_id}: {v.description}"
            for v in self._vulnerabilities
            if v.risk_level == RiskLevel.CRITICAL
        ][:5]

        recs: list[str] = []
        if compromised > 0:
            recs.append(f"{compromised} compromised component(s) — quarantine immediately")
        unverified = sum(1 for c in self._components if c.status == SupplyChainStatus.UNVERIFIED)
        if unverified > 0:
            recs.append(f"{unverified} unverified component(s) — run provenance verification")
        if not recs:
            recs.append("AI supply chain integrity is healthy")

        return SupplyChainReport(
            total_components=len(self._components),
            total_vulnerabilities=len(self._vulnerabilities),
            verified_count=verified,
            compromised_count=compromised,
            avg_risk_score=avg_risk,
            by_type=by_type,
            by_risk=by_risk,
            by_status=by_status,
            critical_findings=critical,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for c in self._components:
            key = c.component_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_components": len(self._components),
            "total_vulnerabilities": len(self._vulnerabilities),
            "auto_quarantine": self._auto_quarantine,
            "type_distribution": type_dist,
            "unique_providers": len({c.provider for c in self._components}),
            "unique_apps": len({c.app_id for c in self._components}),
        }

    def clear_data(self) -> dict[str, str]:
        self._components.clear()
        self._vulnerabilities.clear()
        logger.info("ai_supply_chain_scanner.cleared")
        return {"status": "cleared"}
