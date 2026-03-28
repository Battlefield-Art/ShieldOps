"""Tool functions for the Threat Feed Manager Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_feed_manager.models import (
    FeedHealth,
    FeedScore,
    FeedType,
    NormalizedIOC,
    ThreatFeed,
)

logger = structlog.get_logger()

# Simulated feed registry
FEED_REGISTRY: list[dict[str, Any]] = [
    {
        "name": "AlienVault OTX",
        "feed_type": FeedType.OSINT,
        "url": "https://otx.alienvault.com/api/v1/pulses",
    },
    {
        "name": "MISP Community",
        "feed_type": FeedType.MISP,
        "url": "https://misp.community/feed",
    },
    {
        "name": "TAXII Server",
        "feed_type": FeedType.STIX_TAXII,
        "url": "https://taxii.example.com/collections",
    },
    {
        "name": "FS-ISAC Feed",
        "feed_type": FeedType.ISAC,
        "url": "https://isac.example.com/indicators",
    },
    {
        "name": "Recorded Future",
        "feed_type": FeedType.COMMERCIAL,
        "url": "https://api.recordedfuture.com/v2",
    },
]

# IOC type patterns for classification
IOC_PATTERNS: dict[str, list[str]] = {
    "ip": ["ip", "address", "source_ip", "dest_ip", "ipv4", "ipv6"],
    "domain": ["domain", "hostname", "fqdn", "dns"],
    "hash": ["hash", "md5", "sha1", "sha256", "file_hash"],
    "url": ["url", "uri", "link", "endpoint"],
    "email": ["email", "sender", "from_address"],
    "cve": ["cve", "vulnerability", "vuln"],
}


class ThreatFeedManagerToolkit:
    """Toolkit for threat feed management operations."""

    def __init__(
        self,
        feed_client: Any | None = None,
        enrichment_client: Any | None = None,
    ) -> None:
        self._feed_client = feed_client
        self._enrichment_client = enrichment_client

    async def ingest_feeds(self) -> list[ThreatFeed]:
        """Poll all configured feeds and return raw data."""
        feeds: list[ThreatFeed] = []

        for entry in FEED_REGISTRY:
            feed_id = f"feed-{uuid4().hex[:12]}"
            health = FeedHealth.HEALTHY
            raw_data: list[dict[str, Any]] = []
            error = ""
            ioc_count = 0

            if self._feed_client is not None:
                try:
                    result = await self._feed_client.poll(entry["url"])
                    raw_data = result.get("indicators", [])
                    ioc_count = len(raw_data)
                except Exception as exc:
                    health = FeedHealth.ERROR
                    error = str(exc)
            else:
                # Simulated data
                raw_data = [
                    {
                        "type": "ip",
                        "value": f"10.0.{i}.{i + 1}",
                        "confidence": 0.8,
                        "tags": ["c2", "botnet"],
                    }
                    for i in range(3)
                ]
                ioc_count = len(raw_data)

            feeds.append(
                ThreatFeed(
                    id=feed_id,
                    name=entry["name"],
                    feed_type=entry["feed_type"],
                    url=entry["url"],
                    health=health,
                    ioc_count=ioc_count,
                    last_poll_ts=time.time(),
                    error=error,
                    raw_data=raw_data,
                )
            )

        logger.info(
            "threat_feed.ingested",
            total_feeds=len(feeds),
            healthy=sum(1 for f in feeds if f.health == FeedHealth.HEALTHY),
        )
        return feeds

    async def normalize_iocs(
        self,
        feeds: list[ThreatFeed],
    ) -> list[NormalizedIOC]:
        """Normalize raw IOC data from all feeds into a standard format."""
        iocs: list[NormalizedIOC] = []
        now = time.time()

        for feed in feeds:
            for raw in feed.raw_data:
                raw_type = str(raw.get("type", "")).lower()
                ioc_type = "unknown"
                for canonical, patterns in IOC_PATTERNS.items():
                    if any(p in raw_type for p in patterns):
                        ioc_type = canonical
                        break

                iocs.append(
                    NormalizedIOC(
                        id=f"ioc-{uuid4().hex[:12]}",
                        ioc_type=ioc_type,
                        value=str(raw.get("value", "")),
                        source_feed=feed.name,
                        confidence=float(raw.get("confidence", 0.5)),
                        severity=str(raw.get("severity", "medium")),
                        tags=raw.get("tags", []),
                        first_seen=now,
                        last_seen=now,
                    )
                )

        logger.info(
            "threat_feed.normalized",
            total_iocs=len(iocs),
            feeds_processed=len(feeds),
        )
        return iocs

    async def deduplicate(
        self,
        iocs: list[NormalizedIOC],
    ) -> list[NormalizedIOC]:
        """Deduplicate IOCs by value, keeping highest confidence."""
        seen: dict[str, NormalizedIOC] = {}

        for ioc in iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc

        deduped = list(seen.values())
        removed = len(iocs) - len(deduped)

        logger.info(
            "threat_feed.deduplicated",
            input=len(iocs),
            output=len(deduped),
            removed=removed,
        )
        return deduped

    async def score_feeds(
        self,
        feeds: list[ThreatFeed],
        iocs: list[NormalizedIOC],
    ) -> list[FeedScore]:
        """Score each feed on reliability, freshness, and coverage."""
        scores: list[FeedScore] = []
        now = time.time()

        for feed in feeds:
            feed_iocs = [i for i in iocs if i.source_feed == feed.name]

            # Reliability: based on health + average confidence
            if feed.health == FeedHealth.HEALTHY:
                health_score = 1.0
            elif feed.health == FeedHealth.DEGRADED:
                health_score = 0.6
            else:
                health_score = 0.2
            avg_conf = sum(i.confidence for i in feed_iocs) / len(feed_iocs) if feed_iocs else 0.0
            reliability = (health_score + avg_conf) / 2.0

            # Freshness: based on time since last poll
            age_hours = (now - feed.last_poll_ts) / 3600 if feed.last_poll_ts else 24
            freshness = max(0.0, 1.0 - (age_hours / 24.0))

            # Coverage: based on IOC count relative to average
            avg_count = max(sum(f.ioc_count for f in feeds) / len(feeds), 1)
            coverage = min(feed.ioc_count / avg_count, 1.0)

            overall = (reliability + freshness + coverage) / 3.0

            if overall >= 0.7:
                rec = "keep"
            elif overall >= 0.4:
                rec = "deprioritize"
            else:
                rec = "remove"

            scores.append(
                FeedScore(
                    id=f"score-{uuid4().hex[:12]}",
                    feed_id=feed.id,
                    feed_name=feed.name,
                    reliability=round(reliability, 3),
                    freshness=round(freshness, 3),
                    coverage=round(coverage, 3),
                    overall_score=round(overall, 3),
                    recommendation=rec,
                )
            )

        logger.info(
            "threat_feed.scored",
            total_feeds=len(scores),
            keep=sum(1 for s in scores if s.recommendation == "keep"),
        )
        return scores

    async def enrich_iocs(
        self,
        iocs: list[NormalizedIOC],
    ) -> list[NormalizedIOC]:
        """Enrich IOCs with additional context."""
        for ioc in iocs:
            if self._enrichment_client is not None:
                try:
                    result = await self._enrichment_client.lookup(ioc.value)
                    ioc.enrichment = result
                except Exception:
                    logger.debug("enrichment_failed", ioc=ioc.value)
            else:
                ioc.enrichment = {
                    "geo": "unknown",
                    "asn": "unknown",
                    "reputation": "suspicious",
                    "related_campaigns": [],
                }

        logger.info("threat_feed.enriched", total_iocs=len(iocs))
        return iocs
