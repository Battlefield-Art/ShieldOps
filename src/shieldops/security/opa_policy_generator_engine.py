"""OPA Policy Generator Engine — track and analyze OPA Rego policy generation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PolicyDomain(StrEnum):
    ACCESS_CONTROL = "access_control"
    AGENT_BEHAVIOR = "agent_behavior"
    DATA_PROTECTION = "data_protection"
    NETWORK = "network"
    COMPLIANCE = "compliance"


class GenerationMethod(StrEnum):
    TEMPLATE = "template"
    LLM_GENERATED = "llm_generated"
    MANUAL = "manual"
    IMPORTED = "imported"
    DERIVED = "derived"


class ValidationResult(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"
    UNTESTED = "untested"
    DEPRECATED = "deprecated"


# --- Models ---


class OPAPolicyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str = ""
    policy_domain: PolicyDomain = PolicyDomain.ACCESS_CONTROL
    generation_method: GenerationMethod = GenerationMethod.TEMPLATE
    validation_result: ValidationResult = ValidationResult.UNTESTED
    requirements_covered: int = 0
    rego_lines: int = 0
    complexity_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OPAPolicyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str = ""
    policy_domain: PolicyDomain = PolicyDomain.ACCESS_CONTROL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OPAPolicyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_complexity: float = 0.0
    by_policy_domain: dict[str, int] = Field(default_factory=dict)
    by_generation_method: dict[str, int] = Field(default_factory=dict)
    by_validation_result: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OPAPolicyGeneratorEngine:
    """Track and analyze OPA Rego policy generation."""

    def __init__(
        self,
        max_records: int = 200000,
        coverage_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = coverage_threshold
        self._records: list[OPAPolicyRecord] = []
        self._analyses: list[OPAPolicyAnalysis] = []
        logger.info(
            "opa_policy_generator_engine.initialized",
            max_records=max_records,
            coverage_threshold=coverage_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        policy_id: str,
        policy_domain: PolicyDomain = PolicyDomain.ACCESS_CONTROL,
        generation_method: GenerationMethod = GenerationMethod.TEMPLATE,
        validation_result: ValidationResult = ValidationResult.UNTESTED,
        requirements_covered: int = 0,
        rego_lines: int = 0,
        complexity_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> OPAPolicyRecord:
        record = OPAPolicyRecord(
            policy_id=policy_id,
            policy_domain=policy_domain,
            generation_method=generation_method,
            validation_result=validation_result,
            requirements_covered=requirements_covered,
            rego_lines=rego_lines,
            complexity_score=complexity_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "opa_policy_generator_engine.record_added",
            record_id=record.id,
            policy_id=policy_id,
            policy_domain=policy_domain.value,
            validation_result=validation_result.value,
        )
        return record

    def get_record(self, record_id: str) -> OPAPolicyRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        policy_domain: PolicyDomain | None = None,
        validation_result: ValidationResult | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OPAPolicyRecord]:
        results = list(self._records)
        if policy_domain is not None:
            results = [r for r in results if r.policy_domain == policy_domain]
        if validation_result is not None:
            results = [r for r in results if r.validation_result == validation_result]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        policy_id: str,
        policy_domain: PolicyDomain = PolicyDomain.ACCESS_CONTROL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OPAPolicyAnalysis:
        analysis = OPAPolicyAnalysis(
            policy_id=policy_id,
            policy_domain=policy_domain,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "opa_policy_generator_engine.analysis_added",
            policy_id=policy_id,
            policy_domain=policy_domain.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_policy_coverage(self) -> dict[str, Any]:
        """Analyze policy coverage across domains and validation status."""
        domain_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.policy_domain.value
            domain_data.setdefault(key, {})
            vr = r.validation_result.value
            domain_data[key][vr] = domain_data[key].get(vr, 0) + 1
        all_domains = {d.value for d in PolicyDomain}
        covered = set(domain_data.keys())
        result: dict[str, Any] = {
            "covered_domains": len(covered),
            "total_domains": len(all_domains),
            "missing_domains": list(all_domains - covered),
            "coverage_pct": round(len(covered) / len(all_domains) * 100, 2),
            "by_domain": {},
        }
        for domain, statuses in domain_data.items():
            total = sum(statuses.values())
            valid_ct = statuses.get("valid", 0)
            valid_pct = round(valid_ct / total * 100, 2) if total else 0.0
            result["by_domain"][domain] = {
                "total": total,
                "statuses": statuses,
                "valid_pct": valid_pct,
                "below_threshold": valid_pct < self._threshold,
            }
        return result

    def identify_untested_policies(self) -> list[dict[str, Any]]:
        """Identify untested, invalid, or deprecated policies."""
        untested: list[dict[str, Any]] = []
        for r in self._records:
            if r.validation_result in (
                ValidationResult.UNTESTED,
                ValidationResult.INVALID,
                ValidationResult.DEPRECATED,
            ):
                untested.append(
                    {
                        "record_id": r.id,
                        "policy_id": r.policy_id,
                        "policy_domain": r.policy_domain.value,
                        "generation_method": r.generation_method.value,
                        "validation_result": r.validation_result.value,
                        "requirements_covered": r.requirements_covered,
                        "rego_lines": r.rego_lines,
                        "complexity_score": r.complexity_score,
                        "service": r.service,
                    }
                )
        return sorted(untested, key=lambda x: x["complexity_score"], reverse=True)

    def detect_generation_trends(self) -> list[dict[str, Any]]:
        """Detect trends in policy generation over time."""
        buckets: dict[str, list[OPAPolicyRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            llm_ct = sum(
                1 for r in records if r.generation_method == GenerationMethod.LLM_GENERATED
            )
            valid_ct = sum(1 for r in records if r.validation_result == ValidationResult.VALID)
            trends.append(
                {
                    "date": day,
                    "total_policies": len(records),
                    "llm_generated": llm_ct,
                    "validated": valid_ct,
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> OPAPolicyReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.policy_domain.value] = by_e1.get(r.policy_domain.value, 0) + 1
            by_e2[r.generation_method.value] = by_e2.get(r.generation_method.value, 0) + 1
            by_e3[r.validation_result.value] = by_e3.get(r.validation_result.value, 0) + 1
        scores = [r.complexity_score for r in self._records]
        avg_complexity = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(
            1
            for r in self._records
            if r.validation_result
            in (
                ValidationResult.UNTESTED,
                ValidationResult.INVALID,
                ValidationResult.DEPRECATED,
            )
        )
        gap_list = self.identify_untested_policies()
        top_gaps = [o["policy_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} untested/invalid/deprecated policy(ies) found")
        if not recs:
            recs.append("OPA Policy Generator Engine is healthy")
        return OPAPolicyReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_complexity=avg_complexity,
            by_policy_domain=by_e1,
            by_generation_method=by_e2,
            by_validation_result=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("opa_policy_generator_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.policy_domain.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "policy_domain_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
