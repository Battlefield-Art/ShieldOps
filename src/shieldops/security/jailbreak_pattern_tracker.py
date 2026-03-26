"""JailbreakPatternTracker — tracks jailbreak attempt patterns and evolving techniques."""

from __future__ import annotations

import time
import uuid
from collections import Counter
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class JailbreakCategory(StrEnum):
    ROLE_PLAY = "role_play"
    SYSTEM_OVERRIDE = "system_override"
    ENCODING_BYPASS = "encoding_bypass"
    CONTEXT_MANIPULATION = "context_manipulation"


class EvolutionStage(StrEnum):
    NOVEL = "novel"
    EMERGING = "emerging"
    ESTABLISHED = "established"
    MITIGATED = "mitigated"


class DefenseStatus(StrEnum):
    UNDEFENDED = "undefended"
    PARTIAL = "partial"
    DEFENDED = "defended"
    HARDENED = "hardened"


# --- Models ---


class JailbreakRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pattern_text: str = ""
    pattern_hash: str = ""
    category: JailbreakCategory = JailbreakCategory.ROLE_PLAY
    evolution_stage: EvolutionStage = EvolutionStage.NOVEL
    defense_status: DefenseStatus = DefenseStatus.UNDEFENDED
    success: bool = False
    target_model: str = ""
    source: str = ""
    similarity_score: float = 0.0
    technique_tags: list[str] = Field(default_factory=list)
    bypass_method: str = ""
    blocked_by: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class JailbreakAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""
    total_attempts: int = 0
    success_rate: float = 0.0
    evolution_stage: EvolutionStage = EvolutionStage.NOVEL
    defense_status: DefenseStatus = DefenseStatus.UNDEFENDED
    unique_patterns: int = 0
    top_techniques: list[str] = Field(default_factory=list)
    trend: str = ""
    avg_similarity: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class JailbreakReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    unique_patterns: int = 0
    total_successful: int = 0
    overall_success_rate: float = 0.0
    category_breakdown: dict[str, int] = Field(default_factory=dict)
    evolution_breakdown: dict[str, int] = Field(default_factory=dict)
    defense_breakdown: dict[str, int] = Field(default_factory=dict)
    novel_patterns: int = 0
    defense_rules: list[dict[str, Any]] = Field(default_factory=list)
    trend_summary: dict[str, Any] = Field(default_factory=dict)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


_EVOLUTION_THRESHOLDS = {
    "novel_to_emerging": 3,  # seen >= 3 times
    "emerging_to_established": 10,  # seen >= 10 times
}

_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    JailbreakCategory.ROLE_PLAY: [
        "pretend",
        "act as",
        "you are now",
        "roleplay",
        "imagine you",
        "character",
        "persona",
        "DAN",
        "do anything now",
    ],
    JailbreakCategory.SYSTEM_OVERRIDE: [
        "system:",
        "override",
        "admin",
        "developer mode",
        "maintenance mode",
        "debug mode",
        "root access",
        "sudo",
        "privilege",
    ],
    JailbreakCategory.ENCODING_BYPASS: [
        "base64",
        "rot13",
        "hex",
        "morse",
        "pig latin",
        "backwards",
        "reverse",
        "decode",
        "translate to",
    ],
    JailbreakCategory.CONTEXT_MANIPULATION: [
        "hypothetical",
        "academic",
        "research purposes",
        "fiction",
        "creative writing",
        "thought experiment",
        "what if",
        "scenario",
    ],
}


class JailbreakPatternTracker:
    """Tracks jailbreak attempt patterns and evolving techniques."""

    def __init__(self, max_records: int = 10000) -> None:
        self._records: list[JailbreakRecord] = []
        self._max = max_records
        logger.info("jailbreak_pattern_tracker.initialized", max_records=max_records)

    # -- core methods --

    def add_record(self, **kwargs: Any) -> JailbreakRecord:
        """Add a jailbreak attempt record."""
        rec = JailbreakRecord(**kwargs)
        # Auto-generate pattern hash if not provided
        if not rec.pattern_hash and rec.pattern_text:
            rec.pattern_hash = str(hash(rec.pattern_text.lower().strip()))
        # Auto-classify evolution stage based on pattern frequency
        similar = [
            r
            for r in self._records
            if r.pattern_hash == rec.pattern_hash or r.category == rec.category
        ]
        count = len(similar)
        if count >= _EVOLUTION_THRESHOLDS["emerging_to_established"]:
            rec.evolution_stage = EvolutionStage.ESTABLISHED
        elif count >= _EVOLUTION_THRESHOLDS["novel_to_emerging"]:
            rec.evolution_stage = EvolutionStage.EMERGING
        # Check if any prior similar pattern was defended
        defended = [
            r
            for r in similar
            if r.defense_status in (DefenseStatus.DEFENDED, DefenseStatus.HARDENED)
            and not r.success
        ]
        if defended:
            rec.evolution_stage = EvolutionStage.MITIGATED

        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.debug(
            "jailbreak_pattern_tracker.record_added",
            category=rec.category,
            evolution_stage=rec.evolution_stage,
            success=rec.success,
        )
        return rec

    def process(self, category: str) -> JailbreakAnalysis:
        """Analyze jailbreak patterns for a specific category."""
        filtered = [r for r in self._records if r.category.value == category]
        if not filtered:
            return JailbreakAnalysis(category=category)

        successes = sum(1 for r in filtered if r.success)
        success_rate = round(successes / len(filtered), 3) if filtered else 0.0

        unique_hashes = {r.pattern_hash for r in filtered if r.pattern_hash}
        technique_counter: Counter[str] = Counter()
        total_sim = 0.0

        for r in filtered:
            for tag in r.technique_tags:
                technique_counter[tag] += 1
            total_sim += r.similarity_score

        top_techniques = [t for t, _ in technique_counter.most_common(5)]
        avg_sim = round(total_sim / len(filtered), 3) if filtered else 0.0

        # Determine overall evolution stage for the category
        stage_counts: Counter[str] = Counter(r.evolution_stage.value for r in filtered)
        most_common_stage = (
            stage_counts.most_common(1)[0][0] if stage_counts else EvolutionStage.NOVEL.value
        )

        # Determine defense status
        defense_counts: Counter[str] = Counter(r.defense_status.value for r in filtered)
        most_common_defense = (
            defense_counts.most_common(1)[0][0]
            if defense_counts
            else DefenseStatus.UNDEFENDED.value
        )

        # Trend detection: compare recent vs older attempts
        midpoint = len(filtered) // 2
        if midpoint > 0:
            old_rate = sum(1 for r in filtered[:midpoint] if r.success) / midpoint
            new_rate = sum(1 for r in filtered[midpoint:] if r.success) / (len(filtered) - midpoint)
            if new_rate > old_rate * 1.5:
                trend = "increasing_success"
            elif new_rate < old_rate * 0.5:
                trend = "decreasing_success"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"

        recommendations: list[str] = []
        if success_rate > 0.3:
            recommendations.append(
                f"Category '{category}' has {round(success_rate * 100)}% success rate — "
                f"strengthen defenses"
            )
        if trend == "increasing_success":
            recommendations.append(
                f"Jailbreak success rate is increasing for '{category}' — update defense rules"
            )
        if most_common_defense == DefenseStatus.UNDEFENDED.value:
            recommendations.append(f"Category '{category}' is largely undefended — deploy rules")

        return JailbreakAnalysis(
            category=category,
            total_attempts=len(filtered),
            success_rate=success_rate,
            evolution_stage=EvolutionStage(most_common_stage),
            defense_status=DefenseStatus(most_common_defense),
            unique_patterns=len(unique_hashes),
            top_techniques=top_techniques,
            trend=trend,
            avg_similarity=avg_sim,
            recommendations=recommendations,
        )

    def generate_report(self) -> JailbreakReport:
        """Generate a comprehensive jailbreak tracking report."""
        if not self._records:
            return JailbreakReport()

        cat_bk: Counter[str] = Counter()
        evo_bk: Counter[str] = Counter()
        def_bk: Counter[str] = Counter()
        total_success = 0

        for r in self._records:
            cat_bk[r.category.value] += 1
            evo_bk[r.evolution_stage.value] += 1
            def_bk[r.defense_status.value] += 1
            if r.success:
                total_success += 1

        overall_rate = round(total_success / len(self._records), 3) if self._records else 0.0
        novel = sum(1 for r in self._records if r.evolution_stage == EvolutionStage.NOVEL)

        defense_rules = self.generate_defense_rules()
        evolution_info = self.track_pattern_evolution()

        return JailbreakReport(
            total_records=len(self._records),
            unique_patterns=len({r.pattern_hash for r in self._records if r.pattern_hash}),
            total_successful=total_success,
            overall_success_rate=overall_rate,
            category_breakdown=dict(cat_bk),
            evolution_breakdown=dict(evo_bk),
            defense_breakdown=dict(def_bk),
            novel_patterns=novel,
            defense_rules=defense_rules,
            trend_summary=evolution_info,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics."""
        return {
            "total_records": len(self._records),
            "unique_patterns": len({r.pattern_hash for r in self._records if r.pattern_hash}),
            "total_successful": sum(1 for r in self._records if r.success),
            "novel_patterns": sum(
                1 for r in self._records if r.evolution_stage == EvolutionStage.NOVEL
            ),
        }

    def clear_data(self) -> None:
        """Clear all stored records."""
        self._records.clear()
        logger.info("jailbreak_pattern_tracker.cleared")

    # -- domain methods --

    def identify_novel_patterns(self) -> list[dict[str, Any]]:
        """Identify novel jailbreak patterns not yet seen or defended against."""
        novel_records = [r for r in self._records if r.evolution_stage == EvolutionStage.NOVEL]
        # Group by pattern hash
        pattern_groups: dict[str, list[JailbreakRecord]] = {}
        for r in novel_records:
            key = r.pattern_hash or r.id
            pattern_groups.setdefault(key, []).append(r)

        novel_patterns: list[dict[str, Any]] = []
        for phash, recs in pattern_groups.items():
            representative = recs[0]
            success_count = sum(1 for r in recs if r.success)
            novel_patterns.append(
                {
                    "pattern_hash": phash,
                    "category": representative.category.value,
                    "first_seen": min(r.created_at for r in recs),
                    "occurrence_count": len(recs),
                    "success_count": success_count,
                    "success_rate": round(success_count / len(recs), 3),
                    "sample_text": representative.pattern_text[:200]
                    if representative.pattern_text
                    else "",
                    "technique_tags": list({t for r in recs for t in r.technique_tags}),
                    "defense_status": representative.defense_status.value,
                }
            )

        return sorted(novel_patterns, key=lambda p: p["success_rate"], reverse=True)

    def track_pattern_evolution(self) -> dict[str, Any]:
        """Track how jailbreak patterns evolve over time."""
        if not self._records:
            return {"patterns_tracked": 0, "evolution_events": []}

        # Group by pattern hash and sort by time
        pattern_timeline: dict[str, list[JailbreakRecord]] = {}
        for r in self._records:
            key = r.pattern_hash or r.id
            pattern_timeline.setdefault(key, []).append(r)

        evolution_events: list[dict[str, Any]] = []
        for phash, recs in pattern_timeline.items():
            sorted_recs = sorted(recs, key=lambda r: r.created_at)
            if len(sorted_recs) < 2:
                continue

            stages_seen = [r.evolution_stage.value for r in sorted_recs]
            unique_stages = list(dict.fromkeys(stages_seen))  # preserve order, deduplicate

            # Check if the pattern has progressed through evolution stages
            if len(unique_stages) > 1:
                evolution_events.append(
                    {
                        "pattern_hash": phash,
                        "category": sorted_recs[0].category.value,
                        "stages": unique_stages,
                        "first_seen": sorted_recs[0].created_at,
                        "last_seen": sorted_recs[-1].created_at,
                        "total_observations": len(sorted_recs),
                        "current_stage": sorted_recs[-1].evolution_stage.value,
                    }
                )

        # Category-level trends
        category_trends: dict[str, dict[str, int]] = {}
        now = time.time()
        day_sec = 86400
        for r in self._records:
            cat = r.category.value
            if cat not in category_trends:
                category_trends[cat] = {"last_24h": 0, "last_7d": 0, "total": 0}
            category_trends[cat]["total"] += 1
            age = now - r.created_at
            if age <= day_sec:
                category_trends[cat]["last_24h"] += 1
            if age <= day_sec * 7:
                category_trends[cat]["last_7d"] += 1

        return {
            "patterns_tracked": len(pattern_timeline),
            "evolution_events": evolution_events[:20],
            "category_trends": category_trends,
        }

    def generate_defense_rules(self) -> list[dict[str, Any]]:
        """Generate defense rules based on observed successful jailbreak patterns."""
        successful = [r for r in self._records if r.success]
        if not successful:
            return []

        # Group successful attacks by category
        category_patterns: dict[str, list[JailbreakRecord]] = {}
        for r in successful:
            category_patterns.setdefault(r.category.value, []).append(r)

        rules: list[dict[str, Any]] = []
        rule_id = 1

        for cat, recs in category_patterns.items():
            # Extract common technique tags
            tag_counter: Counter[str] = Counter()
            for r in recs:
                for t in r.technique_tags:
                    tag_counter[t] += 1
            top_tags = [t for t, _ in tag_counter.most_common(3)]

            # Extract keyword patterns from the category definition
            keywords = _CATEGORY_KEYWORDS.get(cat, [])

            rule = {
                "rule_id": f"JB-{rule_id:04d}",
                "category": cat,
                "description": (
                    f"Block {cat} jailbreak attempts based on {len(recs)} observed successes"
                ),
                "keywords": keywords[:5],
                "technique_tags": top_tags,
                "action": "block",
                "confidence_threshold": 0.7,
                "success_count_basis": len(recs),
                "priority": "high" if len(recs) >= 5 else "medium",
            }
            rules.append(rule)
            rule_id += 1

        # Add rules for novel undefended patterns
        novel = self.identify_novel_patterns()
        for p in novel[:5]:
            if p["success_rate"] > 0.5 and p["defense_status"] == DefenseStatus.UNDEFENDED.value:
                rules.append(
                    {
                        "rule_id": f"JB-{rule_id:04d}",
                        "category": p["category"],
                        "description": f"Block novel pattern (hash: {p['pattern_hash'][:12]}...) "
                        f"with {round(p['success_rate'] * 100)}% success rate",
                        "keywords": [],
                        "technique_tags": p["technique_tags"],
                        "action": "block",
                        "confidence_threshold": 0.6,
                        "success_count_basis": p["success_count"],
                        "priority": "critical",
                    }
                )
                rule_id += 1

        return sorted(rules, key=lambda r: r.get("success_count_basis", 0), reverse=True)
