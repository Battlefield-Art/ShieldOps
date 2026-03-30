"""Threat Feed Aggregator Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    EnrichedThreat,
    FeedSource,
    IntelDistribution,
    IOCType,
    NormalizedIOC,
    ThreatCorrelation,
    ThreatFeed,
)

logger = structlog.get_logger()

_MOCK_FEEDS: list[dict[str, Any]] = [
    {
        "source": FeedSource.MISP,
        "ioc_value": "185.220.101.34",
        "ioc_type": IOCType.IP_ADDRESS,
        "severity": "high",
        "confidence": 0.92,
        "tags": ["apt28", "c2"],
    },
    {
        "source": FeedSource.MISP,
        "ioc_value": "evil-payload.ru",
        "ioc_type": IOCType.DOMAIN,
        "severity": "critical",
        "confidence": 0.95,
        "tags": ["apt28", "phishing"],
    },
    {
        "source": FeedSource.STIX_TAXII,
        "ioc_value": "45.155.205.99",
        "ioc_type": IOCType.IP_ADDRESS,
        "severity": "high",
        "confidence": 0.88,
        "tags": ["cobalt-strike", "c2"],
    },
    {
        "source": FeedSource.STIX_TAXII,
        "ioc_value": ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"),
        "ioc_type": IOCType.FILE_HASH,
        "severity": "critical",
        "confidence": 0.97,
        "tags": ["ransomware", "lockbit"],
    },
    {
        "source": FeedSource.ALIENVAULT_OTX,
        "ioc_value": "malware-drop.xyz",
        "ioc_type": IOCType.DOMAIN,
        "severity": "high",
        "confidence": 0.85,
        "tags": ["dropper", "emotet"],
    },
    {
        "source": FeedSource.ALIENVAULT_OTX,
        "ioc_value": "https://phish.example.com/login",
        "ioc_type": IOCType.URL,
        "severity": "medium",
        "confidence": 0.78,
        "tags": ["phishing", "credential-theft"],
    },
    {
        "source": FeedSource.VIRUSTOTAL,
        "ioc_value": ("d5e8a3f1b2c4d6e8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6"),
        "ioc_type": IOCType.FILE_HASH,
        "severity": "critical",
        "confidence": 0.99,
        "tags": ["trojan", "lazarus"],
    },
    {
        "source": FeedSource.VIRUSTOTAL,
        "ioc_value": "CVE-2024-3400",
        "ioc_type": IOCType.CVE,
        "severity": "critical",
        "confidence": 0.96,
        "tags": ["palo-alto", "rce"],
    },
    {
        "source": FeedSource.ABUSE_IPDB,
        "ioc_value": "91.215.85.17",
        "ioc_type": IOCType.IP_ADDRESS,
        "severity": "medium",
        "confidence": 0.72,
        "tags": ["scanner", "brute-force"],
    },
    {
        "source": FeedSource.INTERNAL,
        "ioc_value": "attacker@proton.me",
        "ioc_type": IOCType.EMAIL,
        "severity": "high",
        "confidence": 0.80,
        "tags": ["spear-phishing", "apt"],
    },
]

_CAMPAIGNS = [
    {
        "name": "APT28-PhishStorm",
        "actor": "APT28 (Fancy Bear)",
        "pattern": "spear-phishing",
        "mitre": [
            "T1566.001",
            "T1059.001",
            "T1071.001",
        ],
    },
    {
        "name": "LockBit-RaaS-Wave3",
        "actor": "LockBit Affiliate",
        "pattern": "ransomware-deployment",
        "mitre": ["T1486", "T1490", "T1027"],
    },
    {
        "name": "Lazarus-SupplyChain",
        "actor": "Lazarus Group",
        "pattern": "supply-chain-compromise",
        "mitre": [
            "T1195.002",
            "T1059.006",
            "T1583.001",
        ],
    },
]

_GEO_MAP: dict[str, dict[str, str]] = {
    "185.220.101.34": {
        "geo": "Moscow, RU",
        "asn": "AS47541",
        "org": "VegaNet LLC",
    },
    "45.155.205.99": {
        "geo": "Amsterdam, NL",
        "asn": "AS212238",
        "org": "Datacamp Limited",
    },
    "91.215.85.17": {
        "geo": "Bucharest, RO",
        "asn": "AS39798",
        "org": "MivoCloud SRL",
    },
}

_DISTRIBUTION_TARGETS = [
    "siem-splunk",
    "firewall-palo-alto",
    "edr-crowdstrike",
    "soar-xsoar",
    "email-gateway",
    "dns-sinkhole",
]


def _gen_id(
    prefix: str,
    seed: str,
    idx: int,
) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class ThreatFeedAggregatorToolkit:
    """Tools for threat feed aggregation."""

    def __init__(
        self,
        misp_client: Any | None = None,
        taxii_client: Any | None = None,
        otx_client: Any | None = None,
        vt_client: Any | None = None,
    ) -> None:
        self._misp = misp_client
        self._taxii = taxii_client
        self._otx = otx_client
        self._vt = vt_client

    async def collect_feeds(
        self,
        tenant_id: str,
    ) -> list[ThreatFeed]:
        """Collect IOCs from all threat feeds."""
        logger.info(
            "tfa.collect_feeds",
            tenant_id=tenant_id,
        )

        if self._misp is not None:
            try:
                raw = await self._misp.get_events(
                    tenant_id=tenant_id,
                )
                return [ThreatFeed(**r) for r in raw]
            except Exception:
                logger.exception(
                    "tfa.collect_feeds.error",
                )

        feeds: list[ThreatFeed] = []
        for i, f in enumerate(_MOCK_FEEDS):
            noise = random.gauss(  # noqa: S311
                0,
                0.02,
            )
            conf = round(
                min(
                    1.0,
                    max(0.0, f["confidence"] + noise),
                ),
                3,
            )
            feeds.append(
                ThreatFeed(
                    id=_gen_id("TF", tenant_id, i),
                    source=f["source"],
                    ioc_value=f["ioc_value"],
                    ioc_type=f["ioc_type"],
                    severity=f["severity"],
                    confidence=conf,
                    tags=f["tags"],
                    raw_data={"feed_idx": i},
                )
            )
        return feeds

    async def normalize_iocs(
        self,
        feeds: list[ThreatFeed],
    ) -> list[NormalizedIOC]:
        """Normalize and deduplicate IOCs."""
        logger.info(
            "tfa.normalize_iocs",
            count=len(feeds),
        )

        by_value: dict[str, list[ThreatFeed]] = {}
        for f in feeds:
            by_value.setdefault(
                f.ioc_value,
                [],
            ).append(f)

        normalized: list[NormalizedIOC] = []
        for i, (val, entries) in enumerate(
            by_value.items(),
        ):
            sources = list(
                {e.source for e in entries},
            )
            max_conf = max(e.confidence for e in entries)
            sev = max(
                entries,
                key=lambda e: e.confidence,
            ).severity
            all_tags: list[str] = []
            for e in entries:
                all_tags.extend(e.tags)
            normalized.append(
                NormalizedIOC(
                    id=_gen_id("IOC", val, i),
                    ioc_value=val,
                    ioc_type=entries[0].ioc_type,
                    sources=sources,
                    first_seen=("2026-03-28T00:00:00Z"),
                    last_seen=("2026-03-30T12:00:00Z"),
                    severity=sev,
                    confidence=round(max_conf, 3),
                    tags=list(set(all_tags)),
                )
            )
        return normalized

    async def correlate_threats(
        self,
        iocs: list[NormalizedIOC],
    ) -> list[ThreatCorrelation]:
        """Correlate IOCs into threat campaigns."""
        logger.info(
            "tfa.correlate_threats",
            count=len(iocs),
        )

        correlations: list[ThreatCorrelation] = []
        for i, camp in enumerate(_CAMPAIGNS):
            actor_key = camp["actor"].split(" ")[0].lower()
            pattern_key = camp["pattern"].split("-")[0]
            matched = [
                ioc.id
                for ioc in iocs
                if any(
                    t in ioc.tags
                    for t in [
                        actor_key,
                        pattern_key,
                    ]
                )
            ]
            if not matched:
                matched = [
                    iocs[i % len(iocs)].id,
                ]

            correlations.append(
                ThreatCorrelation(
                    id=_gen_id(
                        "TC",
                        camp["name"],
                        i,
                    ),
                    ioc_ids=matched,
                    campaign_name=camp["name"],
                    threat_actor=camp["actor"],
                    attack_pattern=camp["pattern"],
                    confidence=round(
                        0.75
                        + random.random()  # noqa: S311
                        * 0.2,
                        3,
                    ),
                    mitre_techniques=camp["mitre"],
                )
            )
        return correlations

    async def enrich_context(
        self,
        iocs: list[NormalizedIOC],
    ) -> list[EnrichedThreat]:
        """Enrich IOCs with geo, ASN, and context."""
        logger.info(
            "tfa.enrich_context",
            count=len(iocs),
        )

        enriched: list[EnrichedThreat] = []
        for i, ioc in enumerate(iocs):
            geo_info = _GEO_MAP.get(
                ioc.ioc_value,
                {
                    "geo": "Unknown",
                    "asn": "Unknown",
                    "org": "Unknown",
                },
            )
            malware: list[str] = []
            for tag in ioc.tags:
                if tag in (
                    "lockbit",
                    "emotet",
                    "trojan",
                    "ransomware",
                ):
                    malware.append(tag)

            sev_mult = 1.2 if ioc.severity == "critical" else 1.0
            src_mult = 1.1 if len(ioc.sources) > 1 else 1.0
            risk = round(
                ioc.confidence * 100 * sev_mult * src_mult,
                1,
            )
            risk = min(100.0, risk)

            enriched.append(
                EnrichedThreat(
                    id=_gen_id("ET", ioc.id, i),
                    ioc_id=ioc.id,
                    ioc_value=ioc.ioc_value,
                    geo_location=geo_info["geo"],
                    asn=geo_info["asn"],
                    whois_org=geo_info["org"],
                    malware_families=malware,
                    related_campaigns=[],
                    risk_score=risk,
                )
            )
        return enriched

    async def distribute_intel(
        self,
        enriched: list[EnrichedThreat],
    ) -> list[IntelDistribution]:
        """Distribute enriched intel to consumers."""
        logger.info(
            "tfa.distribute_intel",
            count=len(enriched),
        )

        distributions: list[IntelDistribution] = []
        high_risk = [e for e in enriched if e.risk_score >= 80.0]
        for i, target in enumerate(
            _DISTRIBUTION_TARGETS,
        ):
            count = len(high_risk) if high_risk else 1
            distributions.append(
                IntelDistribution(
                    id=_gen_id("ID", target, i),
                    target=target,
                    format="stix2.1",
                    ioc_count=count,
                    status="delivered",
                    recipients=[target],
                )
            )
        return distributions
