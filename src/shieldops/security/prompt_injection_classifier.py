"""PromptInjectionClassifier — multi-layer injection detection."""

from __future__ import annotations

import re
import time
import uuid
from collections import Counter
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class InjectionType(StrEnum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    RECURSIVE = "recursive"
    ENCODED = "encoded"
    MULTI_TURN = "multi_turn"


class DetectionLayer(StrEnum):
    REGEX = "regex"
    SEMANTIC = "semantic"
    BEHAVIORAL = "behavioral"
    LLM_BASED = "llm_based"


class ClassificationResult(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    INJECTION_DETECTED = "injection_detected"
    BLOCKED = "blocked"


# --- Models ---


class InjectionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    prompt_text: str = ""
    source_app: str = ""
    user_id: str = ""
    injection_type: InjectionType = InjectionType.DIRECT
    detection_layer: DetectionLayer = DetectionLayer.REGEX
    result: ClassificationResult = ClassificationResult.CLEAN
    confidence: float = 0.0
    risk_score: float = 0.0
    matched_patterns: list[str] = Field(default_factory=list)
    prompt_length: int = 0
    is_encoded: bool = False
    encoding_type: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class InjectionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str = ""
    total_prompts: int = 0
    injection_count: int = 0
    injection_rate: float = 0.0
    type_distribution: dict[str, int] = Field(default_factory=dict)
    layer_distribution: dict[str, int] = Field(default_factory=dict)
    avg_risk_score: float = 0.0
    top_patterns: list[str] = Field(default_factory=list)
    blocked_count: int = 0
    recommendations: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class InjectionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    unique_sources: int = 0
    total_injections: int = 0
    total_blocked: int = 0
    detection_rate: float = 0.0
    type_breakdown: dict[str, int] = Field(default_factory=dict)
    result_breakdown: dict[str, int] = Field(default_factory=dict)
    top_attacked_sources: list[dict[str, Any]] = Field(default_factory=list)
    risk_distribution: dict[str, int] = Field(default_factory=dict)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


# Common prompt injection patterns (regex-based first layer)
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(previous|above|all)\s+(instructions|prompts|rules)", "ignore_instructions"),
    (r"you\s+are\s+now\s+", "role_override"),
    (r"system\s*:\s*", "system_prompt_inject"),
    (r"<\|.*?\|>", "special_token_inject"),
    (r"(forget|disregard)\s+(everything|all|your)", "memory_wipe"),
    (r"pretend\s+(you|to)\s+", "pretend_attack"),
    (r"act\s+as\s+(if|a|an)\s+", "role_play_inject"),
    (r"reveal\s+(your|the|system)\s+(prompt|instructions)", "prompt_extraction"),
    (r"repeat\s+(the|your)\s+(above|system|initial)", "prompt_leak"),
    (r"translate.*to\s+(base64|hex|rot13|binary)", "encoding_exfil"),
]

_ENCODED_PATTERNS: list[tuple[str, str]] = [
    (r"[A-Za-z0-9+/]{20,}={0,2}", "base64_content"),
    (r"(%[0-9A-Fa-f]{2}){5,}", "url_encoded"),
    (r"(\\x[0-9A-Fa-f]{2}){5,}", "hex_encoded"),
    (r"(\\u[0-9A-Fa-f]{4}){3,}", "unicode_escaped"),
]


class PromptInjectionClassifier:
    """Classifies and tracks prompt injection attempts with multi-layer detection."""

    def __init__(self, max_records: int = 10000) -> None:
        self._records: list[InjectionRecord] = []
        self._max = max_records
        logger.info("prompt_injection_classifier.initialized", max_records=max_records)

    # -- core methods --

    def add_record(self, **kwargs: Any) -> InjectionRecord:
        """Add a prompt classification record."""
        rec = InjectionRecord(**kwargs)
        if rec.prompt_length == 0 and rec.prompt_text:
            rec.prompt_length = len(rec.prompt_text)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.debug(
            "prompt_injection_classifier.record_added",
            source_app=rec.source_app,
            result=rec.result,
            risk_score=rec.risk_score,
        )
        return rec

    def process(self, source: str) -> InjectionAnalysis:
        """Analyze injection patterns for a specific source application."""
        filtered = [r for r in self._records if r.source_app == source]
        if not filtered:
            return InjectionAnalysis(source=source)

        type_dist: Counter[str] = Counter()
        layer_dist: Counter[str] = Counter()
        all_patterns: Counter[str] = Counter()
        injection_count = 0
        blocked_count = 0
        total_risk = 0.0

        for r in filtered:
            if r.result in (ClassificationResult.INJECTION_DETECTED, ClassificationResult.BLOCKED):
                injection_count += 1
                type_dist[r.injection_type.value] += 1
                layer_dist[r.detection_layer.value] += 1
                for p in r.matched_patterns:
                    all_patterns[p] += 1
            if r.result == ClassificationResult.BLOCKED:
                blocked_count += 1
            total_risk += r.risk_score

        injection_rate = round(injection_count / len(filtered), 3) if filtered else 0.0
        avg_risk = round(total_risk / len(filtered), 3) if filtered else 0.0
        top_patterns = [p for p, _ in all_patterns.most_common(10)]

        recommendations: list[str] = []
        if injection_rate > 0.1:
            recommendations.append(
                f"Source '{source}' has {round(injection_rate * 100, 1)}% injection rate — "
                f"add input sanitization"
            )
        if type_dist.get(InjectionType.ENCODED, 0) > 0:
            recommendations.append("Encoded injections detected — enable decode-then-scan pipeline")
        if type_dist.get(InjectionType.MULTI_TURN, 0) > 0:
            recommendations.append(
                "Multi-turn injection attempts — enable conversation history analysis"
            )
        if blocked_count < injection_count:
            recommendations.append(
                f"{injection_count - blocked_count} injections detected but not blocked — "
                f"switch to enforce mode"
            )

        return InjectionAnalysis(
            source=source,
            total_prompts=len(filtered),
            injection_count=injection_count,
            injection_rate=injection_rate,
            type_distribution=dict(type_dist),
            layer_distribution=dict(layer_dist),
            avg_risk_score=avg_risk,
            top_patterns=top_patterns,
            blocked_count=blocked_count,
            recommendations=recommendations,
        )

    def generate_report(self) -> InjectionReport:
        """Generate a comprehensive injection detection report."""
        if not self._records:
            return InjectionReport()

        type_bk: Counter[str] = Counter()
        result_bk: Counter[str] = Counter()
        source_attacks: Counter[str] = Counter()
        total_injections = 0
        total_blocked = 0

        for r in self._records:
            result_bk[r.result.value] += 1
            if r.result in (ClassificationResult.INJECTION_DETECTED, ClassificationResult.BLOCKED):
                total_injections += 1
                type_bk[r.injection_type.value] += 1
                source_attacks[r.source_app] += 1
            if r.result == ClassificationResult.BLOCKED:
                total_blocked += 1

        detection_rate = round(total_injections / len(self._records), 3) if self._records else 0.0

        top_sources = [
            {"source": src, "injection_count": cnt} for src, cnt in source_attacks.most_common(10)
        ]

        # Risk distribution buckets
        risk_dist: Counter[str] = Counter()
        for r in self._records:
            if r.risk_score >= 0.8:
                risk_dist["critical"] += 1
            elif r.risk_score >= 0.6:
                risk_dist["high"] += 1
            elif r.risk_score >= 0.3:
                risk_dist["medium"] += 1
            else:
                risk_dist["low"] += 1

        return InjectionReport(
            total_records=len(self._records),
            unique_sources=len({r.source_app for r in self._records}),
            total_injections=total_injections,
            total_blocked=total_blocked,
            detection_rate=detection_rate,
            type_breakdown=dict(type_bk),
            result_breakdown=dict(result_bk),
            top_attacked_sources=top_sources,
            risk_distribution=dict(risk_dist),
        )

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics."""
        injections = sum(
            1
            for r in self._records
            if r.result in (ClassificationResult.INJECTION_DETECTED, ClassificationResult.BLOCKED)
        )
        return {
            "total_records": len(self._records),
            "unique_sources": len({r.source_app for r in self._records}),
            "total_injections": injections,
            "total_blocked": sum(
                1 for r in self._records if r.result == ClassificationResult.BLOCKED
            ),
        }

    def clear_data(self) -> None:
        """Clear all stored records."""
        self._records.clear()
        logger.info("prompt_injection_classifier.cleared")

    # -- domain methods --

    def classify_prompt(self, prompt_text: str, source_app: str = "") -> dict[str, Any]:
        """Classify a prompt through multi-layer detection pipeline."""
        matched: list[str] = []
        injection_type = InjectionType.DIRECT
        detection_layer = DetectionLayer.REGEX
        text_lower = prompt_text.lower()

        # Layer 1: Regex pattern matching
        for pattern, name in _INJECTION_PATTERNS:
            if re.search(pattern, text_lower):
                matched.append(name)

        # Layer 2: Check for encoded content
        is_encoded = False
        encoding_type = ""
        encoded_result = self.detect_encoded_injection(prompt_text)
        if encoded_result.get("is_encoded"):
            is_encoded = True
            encoding_type = encoded_result.get("encoding_type", "")
            injection_type = InjectionType.ENCODED
            matched.extend(encoded_result.get("patterns", []))

        # Determine classification result
        risk_score = self.calculate_risk_score(prompt_text, matched)

        if risk_score >= 0.8:
            result = ClassificationResult.BLOCKED
            detection_layer = DetectionLayer.SEMANTIC
        elif risk_score >= 0.5:
            result = ClassificationResult.INJECTION_DETECTED
        elif risk_score >= 0.2:
            result = ClassificationResult.SUSPICIOUS
        else:
            result = ClassificationResult.CLEAN

        confidence = min(risk_score * 1.2, 1.0) if matched else 0.0

        # Store the record
        rec = self.add_record(
            prompt_text=prompt_text[:500],  # Truncate for storage
            source_app=source_app,
            injection_type=injection_type,
            detection_layer=detection_layer,
            result=result,
            confidence=round(confidence, 3),
            risk_score=round(risk_score, 3),
            matched_patterns=matched,
            is_encoded=is_encoded,
            encoding_type=encoding_type,
        )

        return {
            "record_id": rec.id,
            "result": result.value,
            "risk_score": round(risk_score, 3),
            "confidence": round(confidence, 3),
            "matched_patterns": matched,
            "is_encoded": is_encoded,
            "injection_type": injection_type.value,
        }

    def detect_encoded_injection(self, text: str) -> dict[str, Any]:
        """Detect injections hidden via encoding (base64, URL, hex, unicode)."""
        patterns_found: list[str] = []
        encoding_type = ""

        for pattern, name in _ENCODED_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                patterns_found.append(name)
                if not encoding_type:
                    encoding_type = name

        # Check for suspicious Unicode characters (homoglyph attacks)
        non_ascii_ratio = sum(1 for c in text if ord(c) > 127) / max(len(text), 1)
        if non_ascii_ratio > 0.15:
            patterns_found.append("high_unicode_ratio")
            if not encoding_type:
                encoding_type = "unicode_homoglyph"

        # Check for zero-width characters
        zero_width = sum(1 for c in text if ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF))
        if zero_width > 0:
            patterns_found.append("zero_width_chars")
            if not encoding_type:
                encoding_type = "zero_width_steganography"

        return {
            "is_encoded": len(patterns_found) > 0,
            "encoding_type": encoding_type,
            "patterns": patterns_found,
            "non_ascii_ratio": round(non_ascii_ratio, 4),
            "zero_width_count": zero_width,
        }

    def calculate_risk_score(self, prompt_text: str, matched_patterns: list[str]) -> float:
        """Calculate composite risk score for a prompt based on multiple signals."""
        if not prompt_text:
            return 0.0

        score = 0.0
        text_lower = prompt_text.lower()

        # Pattern match weight (0.0 - 0.4)
        pattern_weight = min(len(matched_patterns) * 0.15, 0.4)
        score += pattern_weight

        # Length anomaly (very long prompts are more suspicious) (0.0 - 0.1)
        if len(prompt_text) > 2000:
            score += 0.1
        elif len(prompt_text) > 1000:
            score += 0.05

        # Instruction override keywords (0.0 - 0.2)
        override_keywords = [
            "ignore",
            "override",
            "bypass",
            "forget",
            "disregard",
            "new instructions",
            "admin mode",
            "developer mode",
            "jailbreak",
        ]
        keyword_hits = sum(1 for kw in override_keywords if kw in text_lower)
        score += min(keyword_hits * 0.05, 0.2)

        # Special character density (0.0 - 0.15)
        special_chars = sum(1 for c in prompt_text if c in r"{}[]<>|\\`~")
        special_ratio = special_chars / max(len(prompt_text), 1)
        if special_ratio > 0.1:
            score += 0.15
        elif special_ratio > 0.05:
            score += 0.08

        # Repetition detection (0.0 - 0.15)
        words = text_lower.split()
        if len(words) > 5:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.3:
                score += 0.15
            elif unique_ratio < 0.5:
                score += 0.08

        return round(min(score, 1.0), 3)
