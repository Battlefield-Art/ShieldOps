"""AI Guardrail Engine — enforce and monitor guardrails."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class GuardrailType(StrEnum):
    INPUT_VALIDATION = "input_validation"
    OUTPUT_FILTERING = "output_filtering"
    RATE_LIMITING = "rate_limiting"
    CONTENT_SAFETY = "content_safety"
    TOOL_RESTRICTION = "tool_restriction"


class EnforcementResult(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    MODIFIED = "modified"
    WARNED = "warned"
    ESCALATED = "escalated"


class BypassAttempt(StrEnum):
    NONE = "none"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ENCODING_EVASION = "encoding_evasion"
    CONTEXT_MANIPULATION = "context_manipulation"


# --- Models ---


class AIGuardrailRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    guardrail_type: GuardrailType = GuardrailType.INPUT_VALIDATION
    result: EnforcementResult = EnforcementResult.ALLOWED
    bypass_attempt: BypassAttempt = BypassAttempt.NONE
    agent_id: str = ""
    model_id: str = ""
    confidence: float = 0.0
    details: str = ""
    created_at: float = Field(default_factory=time.time)


class AIGuardrailAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    guardrail_type: GuardrailType = GuardrailType.INPUT_VALIDATION
    effectiveness_pct: float = 0.0
    bypass_count: int = 0
    total_evaluations: int = 0
    analyzed_at: float = Field(default_factory=time.time)


class AIGuardrailReport(BaseModel):
    total_evaluations: int = 0
    blocked_count: int = 0
    bypass_attempts: int = 0
    effectiveness_pct: float = 0.0
    by_type: dict[str, int] = Field(
        default_factory=dict,
    )
    by_result: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AIGuardrailEngine:
    """Enforce and monitor AI guardrails."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[AIGuardrailRecord] = []
        logger.info(
            "ai_guardrail.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def add_record(
        self,
        **kwargs: Any,
    ) -> AIGuardrailRecord:
        record = AIGuardrailRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "ai_guardrail.record_added",
            record_id=record.id,
        )
        return record

    def process(self, key: str) -> AIGuardrailAnalysis:
        matches = [r for r in self._records if r.guardrail_type.value == key]
        if not matches:
            return AIGuardrailAnalysis()
        blocked = sum(1 for r in matches if r.result == EnforcementResult.BLOCKED)
        bypasses = sum(1 for r in matches if r.bypass_attempt != BypassAttempt.NONE)
        eff = (
            round(
                blocked / len(matches) * 100,
                2,
            )
            if matches
            else 0.0
        )
        return AIGuardrailAnalysis(
            guardrail_type=matches[0].guardrail_type,
            effectiveness_pct=eff,
            bypass_count=bypasses,
            total_evaluations=len(matches),
        )

    def generate_report(self) -> AIGuardrailReport:
        by_type: dict[str, int] = {}
        by_result: dict[str, int] = {}
        blocked = 0
        bypass_attempts = 0
        for r in self._records:
            gt = r.guardrail_type.value
            by_type[gt] = by_type.get(gt, 0) + 1
            rv = r.result.value
            by_result[rv] = by_result.get(rv, 0) + 1
            if r.result == EnforcementResult.BLOCKED:
                blocked += 1
            if r.bypass_attempt != BypassAttempt.NONE:
                bypass_attempts += 1
        total = len(self._records)
        eff = (
            round(
                blocked / total * 100,
                2,
            )
            if total
            else 0.0
        )
        recs: list[str] = []
        if bypass_attempts > 0:
            recs.append(f"{bypass_attempts} bypass attempt(s)")
        if eff < 50 and total > 0:
            recs.append("Low guardrail effectiveness")
        if not recs:
            recs.append("Guardrails operating normally")
        return AIGuardrailReport(
            total_evaluations=total,
            blocked_count=blocked,
            bypass_attempts=bypass_attempts,
            effectiveness_pct=eff,
            by_type=by_type,
            by_result=by_result,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("ai_guardrail.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def enforce_guardrail(
        self,
        guardrail_type: GuardrailType,
        content: str = "",
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Enforce a guardrail check on content."""
        suspicious = any(
            kw in content.lower()
            for kw in [
                "ignore instructions",
                "bypass",
                "jailbreak",
            ]
        )
        result = EnforcementResult.BLOCKED if suspicious else EnforcementResult.ALLOWED
        bypass = BypassAttempt.PROMPT_INJECTION if suspicious else BypassAttempt.NONE
        record = self.add_record(
            guardrail_type=guardrail_type,
            result=result,
            bypass_attempt=bypass,
            agent_id=agent_id,
            confidence=0.9 if suspicious else 0.1,
        )
        return {
            "record_id": record.id,
            "result": result.value,
            "bypass_detected": suspicious,
        }

    def detect_bypass(
        self,
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Detect bypass attempts for an agent."""
        matches = [
            r
            for r in self._records
            if r.agent_id == agent_id and r.bypass_attempt != BypassAttempt.NONE
        ]
        return {
            "agent_id": agent_id,
            "bypass_count": len(matches),
            "types": list({r.bypass_attempt.value for r in matches}),
        }

    def measure_effectiveness(
        self,
        guardrail_type: GuardrailType | None = None,
    ) -> dict[str, Any]:
        """Measure guardrail effectiveness."""
        subset = self._records
        if guardrail_type is not None:
            subset = [r for r in subset if r.guardrail_type == guardrail_type]
        total = len(subset)
        if total == 0:
            return {
                "total": 0,
                "effectiveness_pct": 0.0,
            }
        blocked = sum(1 for r in subset if r.result == EnforcementResult.BLOCKED)
        return {
            "total": total,
            "blocked": blocked,
            "effectiveness_pct": round(
                blocked / total * 100,
                2,
            ),
        }
