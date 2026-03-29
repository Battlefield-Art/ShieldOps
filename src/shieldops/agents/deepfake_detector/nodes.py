"""Deepfake Detector Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ArtifactAnalysis,
    DetectionStage,
    MediaSubmission,
    ProvenanceRecord,
)
from .tools import DeepfakeDetectorToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def ingest_media(
    state: dict[str, Any],
    toolkit: DeepfakeDetectorToolkit,
) -> dict[str, Any]:
    """Ingest submitted media for deepfake analysis."""
    logger.info("deepfake_detector.node.ingest_media")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    submissions_raw = state.get("submissions", [])
    session_start = time.time()

    submissions = await toolkit.ingest_media(
        tenant_id=tenant_id,
        submissions=submissions_raw,
    )
    sub_dicts = [s.model_dump() for s in submissions]

    return {
        "submissions": sub_dicts,
        "media_count": len(sub_dicts),
        "stage": DetectionStage.INGEST_MEDIA.value,
        "session_start": session_start,
        "current_step": "ingest_media",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Ingested {len(submissions)} media items for deepfake analysis"],
    }


async def analyze_artifacts(
    state: dict[str, Any],
    toolkit: DeepfakeDetectorToolkit,
) -> dict[str, Any]:
    """Run forensic artifact analysis on ingested media."""
    logger.info("deepfake_detector.node.analyze_artifacts")
    state = _to_dict(state)
    raw_subs = state.get("submissions", [])

    submissions = [MediaSubmission(**s) if isinstance(s, dict) else s for s in raw_subs]

    analyses = await toolkit.analyze_artifacts(submissions)
    analysis_dicts = [a.model_dump() for a in analyses]

    reasoning_note = f"Artifact analysis of {len(analyses)} media items"

    # LLM enhancement: deeper forensic analysis
    try:
        from .prompts import SYSTEM_ANALYZE, AnalyzeOutput

        context = json.dumps(
            {
                "media_count": len(analyses),
                "analyses": analysis_dicts[:10],
                "total_gan_fingerprints": sum(len(a.gan_fingerprints) for a in analyses),
                "total_diffusion_artifacts": sum(len(a.diffusion_artifacts) for a in analyses),
                "avg_artifact_score": (
                    sum(a.artifact_score for a in analyses) / max(len(analyses), 1)
                ),
            },
            default=str,
        )
        llm_result = cast(
            AnalyzeOutput,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Forensic artifact data:\n{context}",
                schema=AnalyzeOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="deepfake_detector",
            node="analyze_artifacts",
        )
        reasoning_note = f"{llm_result.summary} [suspicion={llm_result.suspicion_level}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="deepfake_detector",
            node="analyze_artifacts",
        )

    return {
        "artifact_analyses": analysis_dicts,
        "stage": DetectionStage.ANALYZE_ARTIFACTS.value,
        "current_step": "analyze_artifacts",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def check_provenance(
    state: dict[str, Any],
    toolkit: DeepfakeDetectorToolkit,
) -> dict[str, Any]:
    """Verify C2PA provenance and metadata for each media item."""
    logger.info("deepfake_detector.node.check_provenance")
    state = _to_dict(state)
    raw_subs = state.get("submissions", [])

    submissions = [MediaSubmission(**s) if isinstance(s, dict) else s for s in raw_subs]

    records = await toolkit.check_provenance(submissions)
    record_dicts = [r.model_dump() for r in records]

    c2pa_count = sum(1 for r in records if r.has_c2pa_manifest)
    valid_count = sum(1 for r in records if r.c2pa_valid_signature)
    reasoning_note = (
        f"Provenance check: {c2pa_count}/{len(records)} with C2PA, {valid_count} valid signatures"
    )

    return {
        "provenance_records": record_dicts,
        "stage": DetectionStage.CHECK_PROVENANCE.value,
        "current_step": "check_provenance",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def classify_authenticity(
    state: dict[str, Any],
    toolkit: DeepfakeDetectorToolkit,
) -> dict[str, Any]:
    """Classify media authenticity using combined signals."""
    logger.info("deepfake_detector.node.classify_authenticity")
    state = _to_dict(state)
    raw_subs = state.get("submissions", [])
    raw_artifacts = state.get("artifact_analyses", [])
    raw_provenance = state.get("provenance_records", [])

    submissions = [MediaSubmission(**s) if isinstance(s, dict) else s for s in raw_subs]
    artifacts = [ArtifactAnalysis(**a) if isinstance(a, dict) else a for a in raw_artifacts]
    provenance = [ProvenanceRecord(**p) if isinstance(p, dict) else p for p in raw_provenance]

    classifications = await toolkit.classify_authenticity(submissions, artifacts, provenance)
    class_dicts = [c.model_dump() for c in classifications]

    reasoning_note = f"Classified {len(classifications)} media items"

    # LLM classification enhancement
    try:
        from .prompts import SYSTEM_ANALYZE, AnalyzeOutput

        for i, cls in enumerate(classifications):
            art_dict = artifacts[i].model_dump() if i < len(artifacts) else {}
            prov_dict = provenance[i].model_dump() if i < len(provenance) else {}
            context = json.dumps(
                {
                    "artifact_analysis": art_dict,
                    "provenance_record": prov_dict,
                    "rule_verdict": cls.verdict.value,
                    "rule_confidence": cls.confidence_score,
                    "artifact_score": cls.artifact_score,
                    "provenance_score": cls.provenance_score,
                },
                default=str,
            )
            llm_result = cast(
                AnalyzeOutput,
                await llm_structured(
                    system_prompt=SYSTEM_ANALYZE,
                    user_prompt=f"Classify this media item:\n{context}",
                    schema=AnalyzeOutput,
                ),
            )
            class_dicts[i]["llm_reasoning"] = llm_result.summary
            if llm_result.suspicion_level == "high" and cls.confidence_score < 0.7:
                class_dicts[i]["confidence_score"] = min(cls.confidence_score + 0.1, 0.99)

        logger.info(
            "llm_enhanced",
            agent="deepfake_detector",
            node="classify_authenticity",
        )
        verdicts = [c.get("verdict", "") for c in class_dicts]
        reasoning_note = f"LLM classified {len(class_dicts)} items: {', '.join(verdicts)}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="deepfake_detector",
            node="classify_authenticity",
        )

    # Synthetic rate
    synthetic_count = sum(
        1
        for c in class_dicts
        if c.get("verdict")
        in (
            "synthetic",
            "likely_synthetic",
        )
    )
    total = max(len(class_dicts), 1)
    synthetic_rate = synthetic_count / total

    return {
        "classifications": class_dicts,
        "synthetic_rate": round(synthetic_rate, 4),
        "stage": DetectionStage.CLASSIFY_AUTHENTICITY.value,
        "current_step": "classify_authenticity",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_evidence(
    state: dict[str, Any],
    toolkit: DeepfakeDetectorToolkit,
) -> dict[str, Any]:
    """Generate forensic evidence packages for flagged media."""
    logger.info("deepfake_detector.node.generate_evidence")
    state = _to_dict(state)
    raw_subs = state.get("submissions", [])
    raw_classifications = state.get("classifications", [])
    raw_artifacts = state.get("artifact_analyses", [])

    submissions = [MediaSubmission(**s) if isinstance(s, dict) else s for s in raw_subs]
    from .models import AuthenticityClassification

    classifications = [
        AuthenticityClassification(**c) if isinstance(c, dict) else c for c in raw_classifications
    ]
    artifacts = [ArtifactAnalysis(**a) if isinstance(a, dict) else a for a in raw_artifacts]

    evidence = await toolkit.generate_evidence(submissions, classifications, artifacts)
    evidence_dicts = [e.model_dump() for e in evidence]

    return {
        "evidence_packages": evidence_dicts,
        "stage": DetectionStage.GENERATE_EVIDENCE.value,
        "current_step": "generate_evidence",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated {len(evidence)} evidence packages"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: DeepfakeDetectorToolkit,
) -> dict[str, Any]:
    """Generate final deepfake detection report."""
    logger.info("deepfake_detector.node.generate_report")
    state = _to_dict(state)

    submissions = state.get("submissions", [])
    classifications = state.get("classifications", [])
    evidence = state.get("evidence_packages", [])
    session_start = state.get("session_start", time.time())

    duration_ms = (time.time() - session_start) * 1000
    total_media = max(len(submissions), 1)

    # Verdict distribution
    verdict_dist: dict[str, int] = {}
    model_dist: dict[str, int] = {}
    for c in classifications:
        v = c.get("verdict", "unknown")
        verdict_dist[v] = verdict_dist.get(v, 0) + 1
        m = c.get("generation_model_guess", "")
        if m:
            model_dist[m] = model_dist.get(m, 0) + 1

    # Media type distribution
    media_type_dist: dict[str, int] = {}
    for s in submissions:
        mt = s.get("media_type", "unknown")
        media_type_dist[mt] = media_type_dist.get(mt, 0) + 1

    synthetic_count = sum(
        1 for c in classifications if c.get("verdict") in ("synthetic", "likely_synthetic")
    )
    synthetic_rate = synthetic_count / total_media

    avg_confidence = sum(c.get("confidence_score", 0.0) for c in classifications) / total_media

    # LLM report enhancement
    report_summary = ""
    try:
        from .prompts import SYSTEM_REPORT, ReportOutput

        context = json.dumps(
            {
                "total_media": len(submissions),
                "synthetic_count": synthetic_count,
                "verdict_distribution": verdict_dist,
                "model_distribution": model_dist,
                "evidence_count": len(evidence),
                "avg_confidence": round(avg_confidence, 3),
            },
            default=str,
        )
        llm_result = cast(
            ReportOutput,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Detection results:\n{context}",
                schema=ReportOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="deepfake_detector",
            node="generate_report",
        )
        report_summary = llm_result.executive_summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="deepfake_detector",
            node="generate_report",
        )

    findings: list[dict[str, Any]] = []
    for c in classifications:
        if c.get("verdict") in ("synthetic", "likely_synthetic"):
            findings.append(
                {
                    "media_id": c.get("media_id", ""),
                    "verdict": c.get("verdict", ""),
                    "confidence": c.get("confidence_score", 0.0),
                    "model_guess": c.get("generation_model_guess", ""),
                    "techniques": c.get("manipulation_techniques", []),
                }
            )

    stats = {
        "total_media": len(submissions),
        "synthetic_rate": round(synthetic_rate, 4),
        "avg_confidence": round(avg_confidence, 4),
        "verdict_distribution": verdict_dist,
        "model_distribution": model_dist,
        "media_type_distribution": media_type_dist,
        "evidence_packages_generated": len(evidence),
        "analysis_duration_ms": round(duration_ms, 2),
        "report_summary": report_summary,
    }

    return {
        "stats": stats,
        "findings": findings,
        "synthetic_rate": round(synthetic_rate, 4),
        "avg_confidence": round(avg_confidence, 4),
        "stage": DetectionStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: {len(submissions)} media, "
            f"{synthetic_count} synthetic, "
            f"avg confidence {avg_confidence:.1%}"
        ],
    }
