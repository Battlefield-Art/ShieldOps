"""AI Prompt Guard Engine — classify and block attacks."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AttackCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXTRACTION = "data_extraction"
    ROLE_HIJACK = "role_hijack"
    BENIGN = "benign"


class DetectionLayer(StrEnum):
    INPUT_FILTER = "input_filter"
    SEMANTIC_ANALYSIS = "semantic_analysis"
    PATTERN_MATCH = "pattern_match"
    ML_CLASSIFIER = "ml_classifier"
    ENSEMBLE = "ensemble"


class BlockAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    ALERT = "alert"
    QUARANTINE = "quarantine"


# --- Models ---


class AIPromptGuardRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    category: AttackCategory = AttackCategory.BENIGN
    layer: DetectionLayer = DetectionLayer.INPUT_FILTER
    action: BlockAction = BlockAction.ALLOW
    prompt_hash: str = ""
    agent_id: str = ""
    confidence: float = 0.0
    blocked: bool = False
    created_at: float = Field(default_factory=time.time)


class AIPromptGuardAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    category: AttackCategory = AttackCategory.BENIGN
    attack_count: int = 0
    block_rate_pct: float = 0.0
    avg_confidence: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class AIPromptGuardReport(BaseModel):
    total_prompts: int = 0
    attacks_detected: int = 0
    blocked_count: int = 0
    block_rate_pct: float = 0.0
    by_category: dict[str, int] = Field(
        default_factory=dict,
    )
    by_action: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AIPromptGuardEngine:
    """Classify and defend against prompt attacks."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[AIPromptGuardRecord] = []
        logger.info(
            "ai_prompt_guard.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def add_record(
        self,
        **kwargs: Any,
    ) -> AIPromptGuardRecord:
        record = AIPromptGuardRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "ai_prompt_guard.record_added",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> AIPromptGuardAnalysis:
        matches = [r for r in self._records if r.category.value == key]
        if not matches:
            return AIPromptGuardAnalysis()
        blocked = sum(1 for r in matches if r.blocked)
        avg_conf = round(
            sum(r.confidence for r in matches) / len(matches),
            4,
        )
        return AIPromptGuardAnalysis(
            category=matches[0].category,
            attack_count=len(matches),
            block_rate_pct=round(
                blocked / len(matches) * 100,
                2,
            ),
            avg_confidence=avg_conf,
        )

    def generate_report(self) -> AIPromptGuardReport:
        by_cat: dict[str, int] = {}
        by_action: dict[str, int] = {}
        attacks = 0
        blocked = 0
        for r in self._records:
            c = r.category.value
            by_cat[c] = by_cat.get(c, 0) + 1
            a = r.action.value
            by_action[a] = by_action.get(a, 0) + 1
            if r.category != AttackCategory.BENIGN:
                attacks += 1
            if r.blocked:
                blocked += 1
        total = len(self._records)
        rate = (
            round(
                blocked / total * 100,
                2,
            )
            if total
            else 0.0
        )
        recs: list[str] = []
        if attacks > 0:
            recs.append(f"{attacks} attack(s) detected")
        if rate < 80 and attacks > 0:
            recs.append("Block rate below 80%")
        if not recs:
            recs.append("No prompt attacks detected")
        return AIPromptGuardReport(
            total_prompts=total,
            attacks_detected=attacks,
            blocked_count=blocked,
            block_rate_pct=rate,
            by_category=by_cat,
            by_action=by_action,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("ai_prompt_guard.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def classify_attack(
        self,
        prompt_text: str = "",
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Classify a prompt as attack or benign."""
        keywords = {
            "ignore": AttackCategory.PROMPT_INJECTION,
            "bypass": AttackCategory.JAILBREAK,
            "extract": AttackCategory.DATA_EXTRACTION,
            "pretend": AttackCategory.ROLE_HIJACK,
        }
        category = AttackCategory.BENIGN
        confidence = 0.1
        for kw, cat in keywords.items():
            if kw in prompt_text.lower():
                category = cat
                confidence = 0.85
                break
        is_attack = category != AttackCategory.BENIGN
        action = BlockAction.BLOCK if is_attack else BlockAction.ALLOW
        record = self.add_record(
            category=category,
            action=action,
            agent_id=agent_id,
            confidence=confidence,
            blocked=is_attack,
        )
        return {
            "record_id": record.id,
            "category": category.value,
            "action": action.value,
            "confidence": confidence,
        }

    def apply_defense_layer(
        self,
        layer: DetectionLayer,
        prompt_text: str = "",
    ) -> dict[str, Any]:
        """Apply a specific defense layer."""
        result = self.classify_attack(
            prompt_text=prompt_text,
        )
        return {
            "layer": layer.value,
            "classification": result,
        }

    def track_attack_evolution(
        self,
    ) -> dict[str, Any]:
        """Track how attacks evolve over time."""
        by_cat: dict[str, int] = {}
        for r in self._records:
            if r.category != AttackCategory.BENIGN:
                c = r.category.value
                by_cat[c] = by_cat.get(c, 0) + 1
        total_attacks = sum(by_cat.values())
        return {
            "total_attacks": total_attacks,
            "by_category": by_cat,
            "trend": ("increasing" if total_attacks > 10 else "stable"),
        }
