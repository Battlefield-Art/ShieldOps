"""EbpfTelemetryEngine — eBPF-based telemetry collection tracking."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EbpfProbeType(StrEnum):
    KPROBE = "kprobe"
    UPROBE = "uprobe"
    TRACEPOINT = "tracepoint"
    XDP = "xdp"
    TC = "tc"


class KernelMetric(StrEnum):
    SYSCALL_LATENCY = "syscall_latency"
    NETWORK_FLOW = "network_flow"
    FILE_IO = "file_io"
    PROCESS_LIFECYCLE = "process_lifecycle"


class ProbeStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERRORED = "errored"
    RATE_LIMITED = "rate_limited"


# --- Models ---


class EbpfTelemetryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ebpf_probe_type: EbpfProbeType = EbpfProbeType.KPROBE
    kernel_metric: KernelMetric = KernelMetric.SYSCALL_LATENCY
    probe_status: ProbeStatus = ProbeStatus.INACTIVE
    score: float = 0.0
    cpu_overhead: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class EbpfTelemetryAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ebpf_probe_type: EbpfProbeType = EbpfProbeType.KPROBE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EbpfTelemetryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_ebpf_probe_type: dict[str, int] = Field(default_factory=dict)
    by_kernel_metric: dict[str, int] = Field(default_factory=dict)
    by_probe_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class EbpfTelemetryEngine:
    """eBPF Telemetry Engine — kernel-level metrics, syscall tracing, network flow visibility."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[EbpfTelemetryRecord] = []
        self._analyses: list[EbpfTelemetryAnalysis] = []
        logger.info(
            "ebpf_telemetry_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        ebpf_probe_type: EbpfProbeType = EbpfProbeType.KPROBE,
        kernel_metric: KernelMetric = KernelMetric.SYSCALL_LATENCY,
        probe_status: ProbeStatus = ProbeStatus.INACTIVE,
        score: float = 0.0,
        cpu_overhead: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> EbpfTelemetryRecord:
        record = EbpfTelemetryRecord(
            name=name,
            ebpf_probe_type=ebpf_probe_type,
            kernel_metric=kernel_metric,
            probe_status=probe_status,
            score=score,
            cpu_overhead=cpu_overhead,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ebpf_telemetry_engine.record_added",
            record_id=record.id,
            name=name,
            ebpf_probe_type=ebpf_probe_type.value,
            kernel_metric=kernel_metric.value,
        )
        return record

    def get_record(self, record_id: str) -> EbpfTelemetryRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        ebpf_probe_type: EbpfProbeType | None = None,
        kernel_metric: KernelMetric | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[EbpfTelemetryRecord]:
        results = list(self._records)
        if ebpf_probe_type is not None:
            results = [r for r in results if r.ebpf_probe_type == ebpf_probe_type]
        if kernel_metric is not None:
            results = [r for r in results if r.kernel_metric == kernel_metric]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        ebpf_probe_type: EbpfProbeType = EbpfProbeType.KPROBE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> EbpfTelemetryAnalysis:
        analysis = EbpfTelemetryAnalysis(
            name=name,
            ebpf_probe_type=ebpf_probe_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ebpf_telemetry_engine.analysis_added",
            name=name,
            ebpf_probe_type=ebpf_probe_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.ebpf_probe_type.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "ebpf_probe_type": r.ebpf_probe_type.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def detect_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    def identify_high_overhead_probes(
        self,
        cpu_threshold: float = 5.0,
    ) -> list[dict[str, Any]]:
        """Find probes consuming excessive CPU overhead."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.cpu_overhead > cpu_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "ebpf_probe_type": r.ebpf_probe_type.value,
                        "cpu_overhead": r.cpu_overhead,
                        "probe_status": r.probe_status.value,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["cpu_overhead"], reverse=True)

    def recommend_probe_configuration(self) -> list[dict[str, Any]]:
        """Suggest optimal probe set per workload based on current records."""
        svc_probes: dict[str, list[EbpfTelemetryRecord]] = {}
        for r in self._records:
            svc_probes.setdefault(r.service, []).append(r)
        recommendations: list[dict[str, Any]] = []
        for svc, probes in svc_probes.items():
            active = [p for p in probes if p.probe_status == ProbeStatus.ACTIVE]
            errored = [p for p in probes if p.probe_status == ProbeStatus.ERRORED]
            high_overhead = [p for p in probes if p.cpu_overhead > 5.0]
            actions: list[str] = []
            if errored:
                actions.append(f"Fix {len(errored)} errored probe(s)")
            if high_overhead:
                actions.append(f"Reduce overhead on {len(high_overhead)} probe(s)")
            if not active:
                actions.append("No active probes — enable at least one")
            metrics_covered = {p.kernel_metric for p in probes}
            missing = set(KernelMetric) - metrics_covered
            if missing:
                actions.append(f"Add probes for: {', '.join(m.value for m in missing)}")
            if not actions:
                actions.append("Configuration is optimal")
            recommendations.append(
                {
                    "service": svc,
                    "total_probes": len(probes),
                    "active_probes": len(active),
                    "errored_probes": len(errored),
                    "actions": actions,
                }
            )
        return recommendations

    def compute_kernel_visibility_score(self) -> dict[str, Any]:
        """Compute overall kernel observability coverage score."""
        if not self._records:
            return {"score": 0.0, "coverage": {}, "total_probes": 0}
        metric_counts: dict[str, int] = {}
        active_count = 0
        for r in self._records:
            metric_counts[r.kernel_metric.value] = metric_counts.get(r.kernel_metric.value, 0) + 1
            if r.probe_status == ProbeStatus.ACTIVE:
                active_count += 1
        total_metrics = len(KernelMetric)
        covered_metrics = len(metric_counts)
        coverage_ratio = covered_metrics / total_metrics
        active_ratio = active_count / len(self._records) if self._records else 0.0
        avg_score = sum(r.score for r in self._records) / len(self._records)
        visibility_score = round(
            (coverage_ratio * 40 + active_ratio * 30 + (avg_score / 100) * 30), 2
        )
        return {
            "score": visibility_score,
            "coverage": metric_counts,
            "metrics_covered": covered_metrics,
            "metrics_total": total_metrics,
            "active_probes": active_count,
            "total_probes": len(self._records),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> EbpfTelemetryReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.ebpf_probe_type.value] = by_e1.get(r.ebpf_probe_type.value, 0) + 1
            by_e2[r.kernel_metric.value] = by_e2.get(r.kernel_metric.value, 0) + 1
            by_e3[r.probe_status.value] = by_e3.get(r.probe_status.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("eBPF Telemetry Engine is healthy")
        return EbpfTelemetryReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_ebpf_probe_type=by_e1,
            by_kernel_metric=by_e2,
            by_probe_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ebpf_telemetry_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.ebpf_probe_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "ebpf_probe_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
