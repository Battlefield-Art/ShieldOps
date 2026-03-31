"""Security Data Pipeline Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    DataSourceType,
    EnrichmentResult,
    IngestedRecord,
    LoadResult,
    QualityCheck,
    QualityLevel,
    TransformedRecord,
)

logger = structlog.get_logger()

_SAMPLE_SOURCES: list[dict[str, Any]] = [
    {
        "source": "siem",
        "event_type": "authentication",
        "schema_version": "v2.1",
        "raw_size_bytes": 2048,
        "fields": {"user": "admin", "action": "login", "result": "success"},
    },
    {
        "source": "edr",
        "event_type": "process_creation",
        "schema_version": "v3.0",
        "raw_size_bytes": 4096,
        "fields": {"process": "powershell.exe", "parent": "cmd.exe", "hash": "abc123"},
    },
    {
        "source": "firewall",
        "event_type": "connection",
        "schema_version": "v1.5",
        "raw_size_bytes": 1024,
        "fields": {"src_ip": "10.0.1.5", "dst_ip": "198.51.100.1", "port": 443},
    },
    {
        "source": "cloud_trail",
        "event_type": "api_call",
        "schema_version": "v2.0",
        "raw_size_bytes": 3072,
        "fields": {"service": "iam", "action": "CreateUser", "principal": "root"},
    },
    {
        "source": "identity",
        "event_type": "privilege_escalation",
        "schema_version": "v1.0",
        "raw_size_bytes": 1536,
        "fields": {"user": "svc-deploy", "role": "admin", "method": "assume_role"},
    },
    {
        "source": "vulnerability",
        "event_type": "scan_result",
        "schema_version": "v2.2",
        "raw_size_bytes": 2560,
        "fields": {"cve": "CVE-2026-1234", "severity": "critical", "host": "web-01"},
    },
]

_IOC_FEEDS = ["alienvault", "abuse_ch", "misp", "virustotal"]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class SecurityDataPipelineToolkit:
    """Tools for security data ETL and enrichment."""

    def __init__(
        self,
        data_sources: Any | None = None,
        enrichment_api: Any | None = None,
    ) -> None:
        self._data_sources = data_sources
        self._enrichment_api = enrichment_api

    async def ingest_sources(
        self,
        tenant_id: str,
    ) -> list[IngestedRecord]:
        """Ingest security data from multiple sources."""
        logger.info(
            "sdp.ingest_sources",
            tenant_id=tenant_id,
        )

        if self._data_sources is not None:
            try:
                raw = await self._data_sources.fetch(
                    tenant_id=tenant_id,
                )
                return [IngestedRecord(**r) for r in raw]
            except Exception:
                logger.exception("sdp.ingest_sources.error")

        records: list[IngestedRecord] = []
        for i, s in enumerate(_SAMPLE_SOURCES):
            noise = random.randint(-100, 100)  # noqa: S311
            records.append(
                IngestedRecord(
                    id=_gen_id("IR", tenant_id, i),
                    source=DataSourceType(s["source"]),
                    timestamp=f"2026-03-30T10:{i:02d}:00Z",
                    raw_size_bytes=s["raw_size_bytes"] + noise,
                    schema_version=s["schema_version"],
                    event_type=s["event_type"],
                    fields=s["fields"],
                )
            )
        return records

    async def transform_data(
        self,
        records: list[IngestedRecord],
    ) -> list[TransformedRecord]:
        """Normalize and transform ingested records to OCSF."""
        logger.info(
            "sdp.transform_data",
            count=len(records),
        )

        transformed: list[TransformedRecord] = []
        for i, r in enumerate(records):
            sev = "info"
            if r.event_type in ("privilege_escalation", "scan_result"):
                sev = "high"
            elif r.event_type == "process_creation":
                sev = "medium"
            transformed.append(
                TransformedRecord(
                    id=_gen_id("TR", r.id, i),
                    source=r.source,
                    normalized_schema="OCSF",
                    event_type=r.event_type,
                    severity=sev,
                    timestamp=r.timestamp,
                    enrichments_applied=0,
                    fields=r.fields,
                )
            )
        return transformed

    async def enrich_records(
        self,
        records: list[TransformedRecord],
    ) -> list[EnrichmentResult]:
        """Enrich records with IOC and threat intelligence."""
        logger.info(
            "sdp.enrich_records",
            count=len(records),
        )

        enrichments: list[EnrichmentResult] = []
        for idx, r in enumerate(records):
            score = random.uniform(0.0, 1.0)  # noqa: S311
            matched = score > 0.6
            feed = random.choice(_IOC_FEEDS)  # noqa: S311
            ioc_val = r.fields.get(
                "src_ip",
                r.fields.get("hash", r.fields.get("cve", "")),
            )
            enrichments.append(
                EnrichmentResult(
                    id=_gen_id("ER", r.id, idx),
                    record_id=r.id,
                    enrichment_type="ioc_lookup",
                    matched=matched,
                    ioc_value=str(ioc_val),
                    threat_score=round(score, 2),
                    source_feed=feed,
                )
            )
        return enrichments

    async def validate_quality(
        self,
        records: list[TransformedRecord],
    ) -> list[QualityCheck]:
        """Validate data quality of transformed records."""
        logger.info(
            "sdp.validate_quality",
            count=len(records),
        )

        checks: list[QualityCheck] = []
        check_names = [
            "schema_completeness",
            "timestamp_validity",
            "field_type_check",
            "duplicate_detection",
        ]
        for i, name in enumerate(check_names):
            failed = random.randint(0, max(1, len(records) // 5))  # noqa: S311
            passed = failed == 0
            level = QualityLevel.HIGH if passed else QualityLevel.MEDIUM
            checks.append(
                QualityCheck(
                    id=_gen_id("QC", name, i),
                    check_name=name,
                    passed=passed,
                    records_checked=len(records),
                    records_failed=failed,
                    quality_level=level,
                    detail=f"{name}: {len(records) - failed}/{len(records)} passed",
                )
            )
        return checks

    async def load_destination(
        self,
        records: list[TransformedRecord],
    ) -> list[LoadResult]:
        """Load transformed records to destinations."""
        logger.info(
            "sdp.load_destination",
            count=len(records),
        )

        destinations = ["security_lake", "siem_index", "data_warehouse"]
        results: list[LoadResult] = []
        for i, dest in enumerate(destinations):
            dur = random.randint(50, 500)  # noqa: S311
            total_bytes = sum(256 for _ in records)
            results.append(
                LoadResult(
                    id=_gen_id("LR", dest, i),
                    destination=dest,
                    records_loaded=len(records),
                    bytes_written=total_bytes,
                    duration_ms=dur,
                    success=True,
                    error="",
                )
            )
        return results

    async def record_metric(
        self,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record a pipeline metric."""
        logger.info(
            "sdp.record_metric",
            metric=metric_name,
            value=value,
        )
        return {"metric": metric_name, "value": value, "recorded": True}
