"""PortScanTracker — Track network port scan results."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScanProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    ICMP = "icmp"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open_filtered"
    UNFILTERED = "unfiltered"


class ServiceRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Models ---


class PortScanRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    host: str = ""
    port: int = 0
    protocol: ScanProtocol = ScanProtocol.TCP
    state: PortState = PortState.CLOSED
    risk: ServiceRisk = ServiceRisk.LOW
    service_name: str = ""
    version: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PortScanAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    host: str = ""
    protocol: ScanProtocol = ScanProtocol.TCP
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PortScanReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_protocol: dict[str, int] = Field(default_factory=dict)
    by_state: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class PortScanTracker:
    """Track port scan results and correlate risks."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PortScanRecord] = []
        self._analyses: list[PortScanAnalysis] = []
        logger.info(
            "port_scan_tracker.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        host: str,
        port: int = 0,
        protocol: ScanProtocol = ScanProtocol.TCP,
        state: PortState = PortState.CLOSED,
        risk: ServiceRisk = ServiceRisk.LOW,
        service_name: str = "",
        version: str = "",
        cve_ids: list[str] | None = None,
        service: str = "",
        team: str = "",
    ) -> PortScanRecord:
        record = PortScanRecord(
            host=host,
            port=port,
            protocol=protocol,
            state=state,
            risk=risk,
            service_name=service_name,
            version=version,
            cve_ids=cve_ids or [],
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "port_scan_tracker.record_added",
            record_id=record.id,
            host=host,
            port=port,
            protocol=protocol.value,
        )
        return record

    def get_record(self, record_id: str) -> PortScanRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        protocol: ScanProtocol | None = None,
        state: PortState | None = None,
        limit: int = 50,
    ) -> list[PortScanRecord]:
        results = list(self._records)
        if protocol is not None:
            results = [r for r in results if r.protocol == protocol]
        if state is not None:
            results = [r for r in results if r.state == state]
        return results[-limit:]

    # -- domain operations --------------------------------

    def track_scan(self, host: str, ports: list[int] | None = None) -> dict[str, Any]:
        """Track scan for a host across ports."""
        matched = [r for r in self._records if r.host == host]
        if ports:
            matched = [r for r in matched if r.port in ports]
        open_ports = [r for r in matched if r.state == PortState.OPEN]
        return {
            "host": host,
            "total_ports_scanned": len(matched),
            "open_ports": len(open_ports),
            "high_risk": sum(
                1
                for r in open_ports
                if r.risk
                in (
                    ServiceRisk.CRITICAL,
                    ServiceRisk.HIGH,
                )
            ),
        }

    def identify_high_risk_ports(
        self,
    ) -> list[dict[str, Any]]:
        """Identify open ports with high/critical risk."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.state == PortState.OPEN and r.risk in (
                ServiceRisk.CRITICAL,
                ServiceRisk.HIGH,
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "host": r.host,
                        "port": r.port,
                        "protocol": r.protocol.value,
                        "risk": r.risk.value,
                        "service_name": r.service_name,
                        "cve_count": len(r.cve_ids),
                    }
                )
        return sorted(
            results,
            key=lambda x: 0 if x["risk"] == "critical" else 1,
        )

    def correlate_with_cves(
        self,
    ) -> list[dict[str, Any]]:
        """Correlate open ports with known CVEs."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.cve_ids and r.state == PortState.OPEN:
                results.append(
                    {
                        "host": r.host,
                        "port": r.port,
                        "service_name": r.service_name,
                        "version": r.version,
                        "cve_ids": r.cve_ids,
                        "cve_count": len(r.cve_ids),
                        "risk": r.risk.value,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["cve_count"],
            reverse=True,
        )

    # -- standard methods ---------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.host == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        open_ct = sum(1 for r in matched if r.state == PortState.OPEN)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "open_ports": open_ct,
        }

    def generate_report(self) -> PortScanReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_e1[r.protocol.value] = by_e1.get(r.protocol.value, 0) + 1
            by_e2[r.state.value] = by_e2.get(r.state.value, 0) + 1
            by_e3[r.risk.value] = by_e3.get(r.risk.value, 0) + 1
            scores.append(100.0 if r.state == PortState.CLOSED else 30.0)
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_ct = sum(1 for s in scores if s < self._threshold)
        recs: list[str] = []
        if gap_ct > 0:
            recs.append(f"{gap_ct} open port(s) need review")
        if not recs:
            recs.append("Port scan tracker healthy")
        return PortScanReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_ct,
            avg_score=avg,
            by_protocol=by_e1,
            by_state=by_e2,
            by_risk=by_e3,
            top_gaps=[],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        proto_dist: dict[str, int] = {}
        for r in self._records:
            k = r.protocol.value
            proto_dist[k] = proto_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "protocol_distribution": proto_dist,
            "unique_hosts": len({r.host for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("port_scan_tracker.cleared")
        return {"status": "cleared"}
