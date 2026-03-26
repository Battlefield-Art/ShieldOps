"""DNS Query Analytics Engine —
analyze DNS query patterns, detect anomalies,
track response code distributions and query volumes."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class QueryCategory(StrEnum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INTERNAL = "internal"
    EXTERNAL = "external"


class ResponseCode(StrEnum):
    NOERROR = "noerror"
    NXDOMAIN = "nxdomain"
    SERVFAIL = "servfail"
    REFUSED = "refused"
    TIMEOUT = "timeout"


class QueryVolume(StrEnum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    SPIKE = "spike"
    FLOOD = "flood"
    MINIMAL = "minimal"


# --- Models ---


class DNSQueryAnalyticsRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_domain: str = ""
    source_ip: str = ""
    query_category: QueryCategory = QueryCategory.NORMAL
    response_code: ResponseCode = ResponseCode.NOERROR
    query_volume: QueryVolume = QueryVolume.NORMAL
    queries_per_second: float = 0.0
    response_time_ms: float = 0.0
    record_type: str = "A"
    is_recursive: bool = True
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DNSQueryAnalyticsAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_domain: str = ""
    query_category: QueryCategory = QueryCategory.NORMAL
    avg_qps: float = 0.0
    nxdomain_rate: float = 0.0
    anomaly_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DNSQueryAnalyticsReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_qps: float = 0.0
    by_query_category: dict[str, int] = Field(default_factory=dict)
    by_response_code: dict[str, int] = Field(default_factory=dict)
    by_query_volume: dict[str, int] = Field(default_factory=dict)
    anomalous_domains: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class DNSQueryAnalyticsEngine:
    """Analyze DNS query patterns, detect anomalies,
    track response code distributions and query volumes."""

    def __init__(self, max_records: int = 200000, anomaly_threshold: float = 100.0) -> None:
        self._max_records = max_records
        self._anomaly_threshold = anomaly_threshold
        self._records: list[DNSQueryAnalyticsRecord] = []
        self._analyses: dict[str, DNSQueryAnalyticsAnalysis] = {}
        logger.info(
            "dns_query_analytics_engine.init",
            max_records=max_records,
            anomaly_threshold=anomaly_threshold,
        )

    def add_record(
        self,
        query_domain: str = "",
        source_ip: str = "",
        query_category: QueryCategory = QueryCategory.NORMAL,
        response_code: ResponseCode = ResponseCode.NOERROR,
        query_volume: QueryVolume = QueryVolume.NORMAL,
        queries_per_second: float = 0.0,
        response_time_ms: float = 0.0,
        record_type: str = "A",
        is_recursive: bool = True,
        description: str = "",
    ) -> DNSQueryAnalyticsRecord:
        record = DNSQueryAnalyticsRecord(
            query_domain=query_domain,
            source_ip=source_ip,
            query_category=query_category,
            response_code=response_code,
            query_volume=query_volume,
            queries_per_second=queries_per_second,
            response_time_ms=response_time_ms,
            record_type=record_type,
            is_recursive=is_recursive,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "dns_query_analytics.record_added",
            record_id=record.id,
            query_domain=query_domain,
        )
        return record

    def process(self, key: str) -> DNSQueryAnalyticsAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.query_domain == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        avg_qps = round(sum(r.queries_per_second for r in recs) / len(recs), 2)
        nxdomain = sum(1 for r in recs if r.response_code == ResponseCode.NXDOMAIN)
        nxdomain_rate = round(nxdomain / len(recs) * 100, 2)
        anomaly_score = round((avg_qps / self._anomaly_threshold * 50) + (nxdomain_rate * 0.5), 2)
        cat = recs[0].query_category
        if anomaly_score > 75:
            cat = QueryCategory.MALICIOUS
        elif anomaly_score > 50:
            cat = QueryCategory.SUSPICIOUS
        analysis = DNSQueryAnalyticsAnalysis(
            query_domain=recs[0].query_domain,
            query_category=cat,
            avg_qps=avg_qps,
            nxdomain_rate=nxdomain_rate,
            anomaly_score=anomaly_score,
            description=(
                f"{recs[0].query_domain} avg_qps={avg_qps} "
                f"nxdomain_rate={nxdomain_rate}% anomaly={anomaly_score}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> DNSQueryAnalyticsReport:
        by_cat: dict[str, int] = {}
        by_rcode: dict[str, int] = {}
        by_vol: dict[str, int] = {}
        qps_list: list[float] = []
        for r in self._records:
            c = r.query_category.value
            by_cat[c] = by_cat.get(c, 0) + 1
            rc = r.response_code.value
            by_rcode[rc] = by_rcode.get(rc, 0) + 1
            v = r.query_volume.value
            by_vol[v] = by_vol.get(v, 0) + 1
            qps_list.append(r.queries_per_second)
        avg_qps = round(sum(qps_list) / len(qps_list), 2) if qps_list else 0.0
        anomalous = list(
            {
                r.query_domain
                for r in self._records
                if r.queries_per_second > self._anomaly_threshold
                or r.query_category in (QueryCategory.SUSPICIOUS, QueryCategory.MALICIOUS)
            }
        )[:10]
        recs: list[str] = []
        if anomalous:
            recs.append(f"{len(anomalous)} domains with anomalous query patterns")
        nxdomain_count = by_rcode.get("nxdomain", 0)
        if nxdomain_count > len(self._records) * 0.1:
            recs.append("High NXDOMAIN rate — possible DGA or misconfiguration")
        if not recs:
            recs.append("DNS query patterns within normal bounds")
        return DNSQueryAnalyticsReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_qps=avg_qps,
            by_query_category=by_cat,
            by_response_code=by_rcode,
            by_query_volume=by_vol,
            anomalous_domains=anomalous,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        cat_dist: dict[str, int] = {}
        for r in self._records:
            k = r.query_category.value
            cat_dist[k] = cat_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "category_distribution": cat_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("dns_query_analytics_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def analyze_response_code_distribution(self) -> list[dict[str, Any]]:
        """Analyze response code distribution per domain."""
        domain_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            d = r.query_domain
            domain_data.setdefault(d, {})
            rc = r.response_code.value
            domain_data[d][rc] = domain_data[d].get(rc, 0) + 1
        results: list[dict[str, Any]] = []
        for domain, rcodes in domain_data.items():
            total = sum(rcodes.values())
            nxd_pct = round(rcodes.get("nxdomain", 0) / total * 100, 2) if total else 0.0
            results.append(
                {
                    "query_domain": domain,
                    "total_queries": total,
                    "response_codes": rcodes,
                    "nxdomain_pct": nxd_pct,
                }
            )
        results.sort(key=lambda x: x["nxdomain_pct"], reverse=True)
        return results

    def detect_query_volume_spikes(self) -> list[dict[str, Any]]:
        """Detect domains with query volume spikes above threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.queries_per_second > self._anomaly_threshold:
                results.append(
                    {
                        "query_domain": r.query_domain,
                        "source_ip": r.source_ip,
                        "queries_per_second": r.queries_per_second,
                        "query_volume": r.query_volume.value,
                        "response_code": r.response_code.value,
                    }
                )
        results.sort(key=lambda x: x["queries_per_second"], reverse=True)
        return results

    def top_queried_domains(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return top queried domains by total query count."""
        domain_counts: dict[str, dict[str, Any]] = {}
        for r in self._records:
            d = r.query_domain
            domain_counts.setdefault(d, {"count": 0, "total_qps": 0.0})
            domain_counts[d]["count"] += 1
            domain_counts[d]["total_qps"] += r.queries_per_second
        results: list[dict[str, Any]] = []
        for domain, data in domain_counts.items():
            results.append(
                {
                    "query_domain": domain,
                    "query_count": data["count"],
                    "avg_qps": round(data["total_qps"] / data["count"], 2),
                }
            )
        results.sort(key=lambda x: x["query_count"], reverse=True)
        return results[:limit]
