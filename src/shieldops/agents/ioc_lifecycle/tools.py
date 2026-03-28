"""Tool functions for the IOC Lifecycle Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ioc_lifecycle.models import (
    IOCClassification,
    IOCEnrichment,
    IOCRecord,
    IOCStatus,
    IOCType,
)

logger = structlog.get_logger()

# Default IOC sources and sample data by source type
SOURCE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "threat_feed": [
        {
            "type": "ip",
            "value": "198.51.100.23",
            "confidence": 0.85,
            "tags": ["c2", "botnet"],
        },
        {
            "type": "domain",
            "value": "malware-c2.example.com",
            "confidence": 0.90,
            "tags": ["c2", "phishing"],
        },
        {
            "type": "hash_sha256",
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "confidence": 0.95,
            "tags": ["malware", "trojan"],
        },
    ],
    "siem_alert": [
        {
            "type": "ip",
            "value": "203.0.113.42",
            "confidence": 0.70,
            "tags": ["scanner", "recon"],
        },
        {
            "type": "url",
            "value": "https://evil.example.com/payload.exe",
            "confidence": 0.80,
            "tags": ["dropper"],
        },
    ],
    "default": [
        {
            "type": "ip",
            "value": "192.0.2.1",
            "confidence": 0.50,
            "tags": ["unknown"],
        },
    ],
}


class IOCLifecycleToolkit:
    """Toolkit for IOC lifecycle management."""

    def __init__(
        self,
        threat_intel_client: Any | None = None,
        enrichment_client: Any | None = None,
    ) -> None:
        self._threat_intel_client = threat_intel_client
        self._enrichment_client = enrichment_client

    async def collect_iocs(
        self,
        sources: list[str],
    ) -> list[IOCRecord]:
        """Collect IOCs from specified sources."""
        now = time.time()
        iocs: list[IOCRecord] = []

        for source in sources:
            templates = SOURCE_TEMPLATES.get(
                source,
                SOURCE_TEMPLATES["default"],
            )
            for tmpl in templates:
                ioc_type = IOCType(tmpl["type"])
                iocs.append(
                    IOCRecord(
                        id=f"ioc-{uuid4().hex[:12]}",
                        ioc_type=ioc_type,
                        value=tmpl["value"],
                        source=source,
                        status=IOCStatus.ACTIVE,
                        confidence=tmpl["confidence"],
                        first_seen=now,
                        last_seen=now,
                        tags=tmpl["tags"],
                    )
                )

        if self._threat_intel_client is not None:
            try:
                result = await self._threat_intel_client.fetch(
                    sources=sources,
                )
                for item in result.get("iocs", []):
                    iocs.append(
                        IOCRecord(
                            id=f"ioc-{uuid4().hex[:12]}",
                            ioc_type=IOCType(
                                item.get("type", "ip"),
                            ),
                            value=item.get("value", ""),
                            source=item.get("source", "api"),
                            confidence=item.get("confidence", 0.5),
                            first_seen=now,
                            last_seen=now,
                        )
                    )
            except Exception:
                logger.debug(
                    "threat_intel_client_failed",
                    sources=sources,
                )

        logger.info(
            "ioc.collected",
            count=len(iocs),
            sources=len(sources),
        )

        return iocs

    async def validate_iocs(
        self,
        iocs: list[IOCRecord],
    ) -> list[IOCRecord]:
        """Validate IOCs for format and deduplication."""
        seen: set[str] = set()
        validated: list[IOCRecord] = []

        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key in seen:
                continue
            if not ioc.value:
                continue
            seen.add(key)
            validated.append(ioc)

        logger.info(
            "ioc.validated",
            original=len(iocs),
            validated=len(validated),
            duplicates=len(iocs) - len(validated),
        )

        return validated

    async def enrich_ioc(
        self,
        ioc: IOCRecord,
    ) -> IOCEnrichment:
        """Enrich a single IOC with threat intelligence."""
        now = time.time()

        # Simulated enrichment based on IOC type
        geo = "US" if ioc.ioc_type == IOCType.IP else ""
        asn = "AS13335" if ioc.ioc_type == IOCType.IP else ""
        threat_score = min(ioc.confidence + 0.1, 1.0)
        families: list[str] = []
        if "malware" in ioc.tags or "trojan" in ioc.tags:
            families = ["emotet", "trickbot"]
        campaigns: list[str] = []
        if "c2" in ioc.tags:
            campaigns = ["APT29-Spring2026"]

        if self._enrichment_client is not None:
            try:
                result = await self._enrichment_client.enrich(
                    ioc_type=ioc.ioc_type.value,
                    value=ioc.value,
                )
                threat_score = result.get("threat_score", threat_score)
                geo = result.get("geo", geo)
                asn = result.get("asn", asn)
                families = result.get("families", families)
                campaigns = result.get("campaigns", campaigns)
            except Exception:
                logger.debug(
                    "enrichment_client_failed",
                    ioc_id=ioc.id,
                )

        enrichment = IOCEnrichment(
            ioc_id=ioc.id,
            threat_score=threat_score,
            malware_families=families,
            geo_location=geo,
            asn=asn,
            whois_info="",
            related_campaigns=campaigns,
            enrichment_source="shieldops_enrichment",
            enriched_at=now,
        )

        logger.info(
            "ioc.enriched",
            ioc_id=ioc.id,
            threat_score=threat_score,
        )

        return enrichment

    async def classify_ioc(
        self,
        ioc: IOCRecord,
        enrichment: IOCEnrichment,
    ) -> IOCClassification:
        """Classify an IOC based on enrichment data."""
        now = time.time()

        # Severity from threat score
        if enrichment.threat_score >= 0.9:
            severity = "critical"
        elif enrichment.threat_score >= 0.7:
            severity = "high"
        elif enrichment.threat_score >= 0.4:
            severity = "medium"
        else:
            severity = "low"

        # Kill chain phase heuristic
        phase = "delivery"
        if "c2" in ioc.tags:
            phase = "command_and_control"
        elif "recon" in ioc.tags or "scanner" in ioc.tags:
            phase = "reconnaissance"
        elif "dropper" in ioc.tags:
            phase = "installation"

        # False positive detection
        is_fp = enrichment.threat_score < 0.2
        fp_reason = ""
        if is_fp:
            fp_reason = "Threat score below threshold"

        tactics: list[str] = []
        if phase == "reconnaissance":
            tactics = ["TA0043"]
        elif phase == "command_and_control":
            tactics = ["TA0011"]
        elif phase == "installation":
            tactics = ["TA0002"]
        else:
            tactics = ["TA0001"]

        classification = IOCClassification(
            ioc_id=ioc.id,
            severity=severity,
            category=ioc.ioc_type.value,
            kill_chain_phase=phase,
            mitre_tactics=tactics,
            is_false_positive=is_fp,
            fp_reason=fp_reason,
            classified_at=now,
        )

        logger.info(
            "ioc.classified",
            ioc_id=ioc.id,
            severity=severity,
            is_fp=is_fp,
        )

        return classification

    async def check_age(
        self,
        iocs: list[IOCRecord],
    ) -> list[IOCRecord]:
        """Check IOC age and update status accordingly."""
        now = time.time()
        age_threshold_days = 90
        expiry_threshold_days = 180

        updated: list[IOCRecord] = []
        for ioc in iocs:
            age_days = (now - ioc.first_seen) / 86400
            new_status = ioc.status

            if age_days > expiry_threshold_days:
                new_status = IOCStatus.EXPIRED
            elif age_days > age_threshold_days:
                new_status = IOCStatus.AGED

            updated_ioc = ioc.model_copy(
                update={
                    "status": new_status,
                    "last_seen": now,
                },
            )
            updated.append(updated_ioc)

        aged = sum(1 for i in updated if i.status == IOCStatus.AGED)
        expired = sum(1 for i in updated if i.status == IOCStatus.EXPIRED)

        logger.info(
            "ioc.age_checked",
            total=len(updated),
            aged=aged,
            expired=expired,
        )

        return updated
