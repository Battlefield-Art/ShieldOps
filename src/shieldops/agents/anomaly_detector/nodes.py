"""Anomaly Detector Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import Anomaly, AnomalySeverity, DetectionStage
from .prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_CORRELATE,
    SYSTEM_REPORT,
    AnomalyClassificationResult,
    AnomalyReportResult,
    CorrelationAnalysisResult,
)
from .tools import AnomalyDetectorToolkit

logger = structlog.get_logger()


async def collect_data(
    state: dict[str, Any], toolkit: AnomalyDetectorToolkit
) -> dict[str, Any]:
    """Collect telemetry data from metrics, logs, and traces."""
    logger.info("anomaly_detector.node.collect_data")

    tenant_id = state.get("tenant_id", "")
    metrics = await toolkit.collect_metrics(tenant_id)
    logs = await toolkit.collect_logs(tenant_id)

    all_data = metrics + logs
    return {
        "stage": DetectionStage.DETECT_ANOMALIES.value,
        "data_points": all_data,
        "total_data_points": len(all_data),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(all_data)} data points ({len(metrics)} metrics, {len(logs)} logs)"],
    }


async def detect_anomalies(
    state: dict[str, Any], toolkit: AnomalyDetectorToolkit
) -> dict[str, Any]:
    """Run anomaly detection on collected data."""
    logger.info("anomaly_detector.node.detect_anomalies")

    data_points = state.get("data_points", [])
    anomalies = await toolkit.detect_anomalies(data_points)
    anomalies_data = [a.model_dump(mode="json") for a in anomalies]

    return {
        "stage": DetectionStage.CLASSIFY.value,
        "anomalies": anomalies_data,
        "total_anomalies": len(anomalies),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Detected {len(anomalies)} anomalies from {len(data_points)} data points"],
    }


async def classify_anomalies(
    state: dict[str, Any], toolkit: AnomalyDetectorToolkit
) -> dict[str, Any]:
    """Classify anomalies using LLM-assisted analysis."""
    logger.info("anomaly_detector.node.classify")

    raw_anomalies = state.get("anomalies", [])
    reasoning_note = f"Classified {len(raw_anomalies)} anomalies"

    if raw_anomalies:
        try:
            context = json.dumps(
                {
                    "anomaly_count": len(raw_anomalies),
                    "anomalies": [
                        {
                            "id": a.get("id", ""),
                            "metric_name": a.get("metric_name", ""),
                            "anomaly_type": a.get("anomaly_type", ""),
                            "deviation_sigma": a.get("deviation_sigma", 0),
                            "severity": a.get("severity", ""),
                        }
                        for a in raw_anomalies[:20]
                    ],
                },
                default=str,
            )
            result = cast(
                AnomalyClassificationResult,
                await llm_structured(
                    system_prompt=SYSTEM_CLASSIFY,
                    user_prompt=f"Anomaly data:\n{context}",
                    schema=AnomalyClassificationResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="anomaly_detector", node="classify")

    return {
        "stage": DetectionStage.CORRELATE.value,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def correlate_anomalies(
    state: dict[str, Any], toolkit: AnomalyDetectorToolkit
) -> dict[str, Any]:
    """Correlate anomalies across sources."""
    logger.info("anomaly_detector.node.correlate")

    raw_anomalies = state.get("anomalies", [])
    anomalies = [Anomaly(**a) for a in raw_anomalies]
    correlations = await toolkit.correlate_anomalies(anomalies)
    correlations_data = [c.model_dump() for c in correlations]

    reasoning_note = f"Found {len(correlations)} correlation groups"

    if raw_anomalies:
        try:
            context = json.dumps(
                {
                    "anomaly_count": len(raw_anomalies),
                    "correlation_count": len(correlations),
                    "anomalies_summary": [
                        {"id": a.get("id"), "metric": a.get("metric_name")}
                        for a in raw_anomalies[:20]
                    ],
                },
                default=str,
            )
            result = cast(
                CorrelationAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_CORRELATE,
                    user_prompt=f"Correlation context:\n{context}",
                    schema=CorrelationAnalysisResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="anomaly_detector", node="correlate")

    return {
        "stage": DetectionStage.ALERT.value,
        "correlations": correlations_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def send_alerts(
    state: dict[str, Any], toolkit: AnomalyDetectorToolkit
) -> dict[str, Any]:
    """Send alerts for high-severity anomalies."""
    logger.info("anomaly_detector.node.alert")

    raw_anomalies = state.get("anomalies", [])
    alerts: list[dict[str, Any]] = []

    for raw in raw_anomalies:
        severity = raw.get("severity", "info")
        if severity in (
            AnomalySeverity.CRITICAL.value,
            AnomalySeverity.HIGH.value,
        ):
            anomaly = Anomaly(**raw)
            alert = await toolkit.send_alert(anomaly)
            alerts.append(alert)

    return {
        "stage": DetectionStage.REPORT.value,
        "alerts": alerts,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Sent {len(alerts)} alerts for critical/high severity anomalies"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: AnomalyDetectorToolkit
) -> dict[str, Any]:
    """Generate final anomaly detection report."""
    logger.info("anomaly_detector.node.report")

    total_dp = state.get("total_data_points", 0)
    total_anomalies = state.get("total_anomalies", 0)
    alerts = state.get("alerts", [])
    summary = (
        f"Analyzed {total_dp} data points, detected {total_anomalies} anomalies, "
        f"sent {len(alerts)} alerts"
    )

    try:
        context = json.dumps(
            {
                "total_data_points": total_dp,
                "total_anomalies": total_anomalies,
                "alerts_sent": len(alerts),
                "anomalies": state.get("anomalies", [])[:10],
                "correlations": state.get("correlations", [])[:5],
            },
            default=str,
        )
        result = cast(
            AnomalyReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Report context:\n{context}",
                schema=AnomalyReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="anomaly_detector", node="report")

    return {
        "stage": DetectionStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
