"""Bandwidth Anomaly Detector Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    AnomalyAlert,
    BaselineProfile,
    DetectionStage,
)
from .prompts import (
    SYSTEM_BASELINE,
    SYSTEM_CLASSIFY,
    SYSTEM_REPORT,
    BandwidthReportResult,
    BaselineAnalysisResult,
    TrafficClassificationResult,
)
from .tools import BandwidthAnomalyDetectorToolkit

logger = structlog.get_logger()


async def collect_samples(
    state: dict[str, Any],
    toolkit: BandwidthAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Collect bandwidth samples from network sources."""
    logger.info("bandwidth_anomaly.node.collect_samples")

    tenant_id = state.get("tenant_id", "")
    samples = await toolkit.collect_samples(tenant_id)

    return {
        "stage": DetectionStage.BUILD_BASELINES.value,
        "samples": samples,
        "total_samples": len(samples),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(samples)} bandwidth samples"],
    }


async def build_baselines(
    state: dict[str, Any],
    toolkit: BandwidthAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Build traffic baselines from collected samples."""
    logger.info("bandwidth_anomaly.node.build_baselines")

    samples = state.get("samples", [])
    baselines = await toolkit.build_baselines(samples)
    baselines_data = [b.model_dump(mode="json") for b in baselines]

    reasoning_note = f"Built {len(baselines)} baseline profiles"

    if baselines_data:
        try:
            context = json.dumps(
                {
                    "baseline_count": len(baselines_data),
                    "baselines": [
                        {
                            "entity": b.get("entity", ""),
                            "avg_bytes_per_hour": b.get("avg_bytes_per_hour", 0),
                            "stddev_bytes": b.get("stddev_bytes", 0),
                        }
                        for b in baselines_data[:20]
                    ],
                },
                default=str,
            )
            result = cast(
                BaselineAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_BASELINE,
                    user_prompt=(f"Baseline data:\n{context}"),
                    schema=BaselineAnalysisResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug(
                "llm_fallback",
                agent="bandwidth_anomaly_detector",
                node="build_baselines",
            )

    return {
        "stage": DetectionStage.DETECT_ANOMALIES.value,
        "baselines": baselines_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: BandwidthAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Run anomaly detection against baselines."""
    logger.info("bandwidth_anomaly.node.detect_anomalies")

    samples = state.get("samples", [])
    raw_baselines = state.get("baselines", [])
    baselines = [BaselineProfile(**b) for b in raw_baselines]

    alerts = await toolkit.detect_anomalies(samples, baselines)
    anomalies_data = [a.model_dump(mode="json") for a in alerts]

    return {
        "stage": DetectionStage.CLASSIFY_TRAFFIC.value,
        "anomalies": anomalies_data,
        "total_anomalies": len(anomalies_data),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Detected {len(anomalies_data)} anomalies from {len(samples)} samples"],
    }


async def classify_traffic(
    state: dict[str, Any],
    toolkit: BandwidthAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Classify anomalous traffic using LLM analysis."""
    logger.info("bandwidth_anomaly.node.classify_traffic")

    raw_anomalies = state.get("anomalies", [])
    reasoning_note = f"Classified {len(raw_anomalies)} anomalies"

    classifications: list[dict[str, Any]] = []
    if raw_anomalies:
        try:
            context = json.dumps(
                {
                    "anomaly_count": len(raw_anomalies),
                    "anomalies": [
                        {
                            "alert_id": a.get("alert_id", ""),
                            "entity": a.get("entity", ""),
                            "category": a.get("category", ""),
                            "current_bytes": a.get("current_bytes", 0),
                            "deviation_sigma": a.get("deviation_sigma", 0),
                            "direction": a.get("direction", ""),
                        }
                        for a in raw_anomalies[:20]
                    ],
                },
                default=str,
            )
            result = cast(
                TrafficClassificationResult,
                await llm_structured(
                    system_prompt=SYSTEM_CLASSIFY,
                    user_prompt=(f"Traffic anomaly data:\n{context}"),
                    schema=TrafficClassificationResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
            for i, cat in enumerate(result.categories):
                classifications.append({"index": i, "category": cat})
        except Exception:
            logger.debug(
                "llm_fallback",
                agent="bandwidth_anomaly_detector",
                node="classify_traffic",
            )

    return {
        "stage": DetectionStage.ALERT.value,
        "classifications": classifications,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def send_alerts(
    state: dict[str, Any],
    toolkit: BandwidthAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Send alerts for high-severity bandwidth anomalies."""
    logger.info("bandwidth_anomaly.node.send_alerts")

    raw_anomalies = state.get("anomalies", [])
    alerts: list[dict[str, Any]] = []

    for raw in raw_anomalies:
        severity = raw.get("severity", "info")
        if severity in ("critical", "high"):
            anomaly = AnomalyAlert(**raw)
            alert = await toolkit.send_alert(anomaly)
            alerts.append(alert)

    return {
        "stage": DetectionStage.REPORT.value,
        "alerts": alerts,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Sent {len(alerts)} alerts for critical/high severity anomalies"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: BandwidthAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Generate final bandwidth anomaly report."""
    logger.info("bandwidth_anomaly.node.generate_report")

    total_samples = state.get("total_samples", 0)
    total_anomalies = state.get("total_anomalies", 0)
    alerts = state.get("alerts", [])
    summary = (
        f"Analyzed {total_samples} bandwidth samples, "
        f"detected {total_anomalies} anomalies, "
        f"sent {len(alerts)} alerts"
    )

    try:
        context = json.dumps(
            {
                "total_samples": total_samples,
                "total_anomalies": total_anomalies,
                "alerts_sent": len(alerts),
                "anomalies": state.get("anomalies", [])[:10],
                "baselines": state.get("baselines", [])[:5],
            },
            default=str,
        )
        result = cast(
            BandwidthReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Report context:\n{context}",
                schema=BandwidthReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="bandwidth_anomaly_detector",
            node="generate_report",
        )

    return {
        "stage": DetectionStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
