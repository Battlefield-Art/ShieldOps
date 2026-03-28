"""Agent Code Generator — generate and validate agent code."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TemplateType(StrEnum):
    INVESTIGATION = "investigation"
    REMEDIATION = "remediation"
    SECURITY = "security"
    LEARNING = "learning"
    CUSTOM = "custom"


class CodeQuality(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    POOR = "poor"
    FAILING = "failing"


class SecurityCheck(StrEnum):
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"


# --- Models ---


class CodeGenRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    template: TemplateType = TemplateType.CUSTOM
    quality: CodeQuality = CodeQuality.GOOD
    security: SecurityCheck = SecurityCheck.PASSED
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CodeGenAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    template: TemplateType = TemplateType.CUSTOM
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CodeGenReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_template: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    by_security: dict[str, int] = Field(default_factory=dict)
    failed_checks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentCodeGenerator:
    """Generate, validate, and check agent code."""

    def __init__(
        self,
        max_records: int = 200000,
        quality_threshold: float = 70.0,
    ) -> None:
        self._max = max_records
        self._quality_threshold = quality_threshold
        self._records: list[CodeGenRecord] = []
        self._analyses: list[CodeGenAnalysis] = []
        logger.info(
            "agent_code_generator.initialized",
            max_records=max_records,
        )

    def record_item(
        self,
        agent_name: str = "",
        template: TemplateType = TemplateType.CUSTOM,
        quality: CodeQuality = CodeQuality.GOOD,
        security: SecurityCheck = SecurityCheck.PASSED,
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CodeGenRecord:
        rec = CodeGenRecord(
            agent_name=agent_name,
            template=template,
            quality=quality,
            security=security,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "agent_code_generator.item_recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> CodeGenAnalysis:
        matches = [r for r in self._records if r.agent_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = CodeGenAnalysis(
            agent_name=key,
            analysis_score=round(avg, 2),
            threshold=self._quality_threshold,
            breached=avg < self._quality_threshold,
            description=(f"Generated {len(matches)} agents"),
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def generate_from_template(
        self,
        name: str,
        template: TemplateType = (TemplateType.CUSTOM),
    ) -> dict[str, Any]:
        """Generate agent scaffold from template."""
        return {
            "agent_name": name,
            "template": template.value,
            "files": [
                "models.py",
                "tools.py",
                "nodes.py",
                "graph.py",
                "runner.py",
            ],
            "status": "generated",
        }

    def validate_code(
        self,
    ) -> dict[str, Any]:
        """Validate quality across generated code."""
        if not self._records:
            return {"validated": 0, "pass_rate": 0.0}
        good = sum(
            1 for r in self._records if r.quality in (CodeQuality.EXCELLENT, CodeQuality.GOOD)
        )
        return {
            "validated": len(self._records),
            "pass_rate": round(good / len(self._records), 4),
        }

    def check_security(
        self,
    ) -> list[dict[str, Any]]:
        """Find records with failed security checks."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.security == SecurityCheck.FAILED:
                results.append(
                    {
                        "id": r.id,
                        "agent": r.agent_name,
                        "quality": r.quality.value,
                        "score": r.score,
                    }
                )
        return results

    # -- report / stats ---

    def generate_report(self) -> CodeGenReport:
        by_template: dict[str, int] = {}
        by_quality: dict[str, int] = {}
        by_security: dict[str, int] = {}
        for r in self._records:
            tp = r.template.value
            by_template[tp] = by_template.get(tp, 0) + 1
            q = r.quality.value
            by_quality[q] = by_quality.get(q, 0) + 1
            sc = r.security.value
            by_security[sc] = by_security.get(sc, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        failed = [r.agent_name for r in self._records if r.security == SecurityCheck.FAILED][:5]
        recs: list[str] = []
        if failed:
            recs.append(f"{len(failed)} agent(s) failed security check")
        if not recs:
            recs.append("All agents pass checks")
        return CodeGenReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_template=by_template,
            by_quality=by_quality,
            by_security=by_security,
            failed_checks=failed,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.template.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "quality_threshold": (self._quality_threshold),
            "template_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_code_generator.cleared")
        return {"status": "cleared"}
