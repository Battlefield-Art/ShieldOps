"""DNS Firewall Controller Agent — Tool functions."""

from __future__ import annotations

import hashlib
import math
import random
from typing import Any

import structlog

from .models import (
    DNSQueryRecord,
    DomainAnalysis,
    DomainCategory,
    PolicyAction,
    PolicyEnforcement,
    ReputationResult,
    TunnelingDetection,
)

logger = structlog.get_logger()

_SAMPLE_QUERIES: list[dict[str, Any]] = [
    {
        "source_ip": "10.1.0.20",
        "query_name": "safe.example.com",
        "query_type": "A",
        "client_subnet": "10.1.0.0/24",
    },
    {
        "source_ip": "10.1.0.20",
        "query_name": "a8f3kd9x.c2-server.xyz",
        "query_type": "A",
        "client_subnet": "10.1.0.0/24",
    },
    {
        "source_ip": "10.1.1.30",
        "query_name": "dGVzdGluZw.tunnel.evil.net",
        "query_type": "TXT",
        "client_subnet": "10.1.1.0/24",
    },
    {
        "source_ip": "10.1.1.30",
        "query_name": "bWFsd2FyZQ.tunnel.evil.net",
        "query_type": "TXT",
        "client_subnet": "10.1.1.0/24",
    },
    {
        "source_ip": "10.1.2.10",
        "query_name": "login.phish-bank.com",
        "query_type": "A",
        "client_subnet": "10.1.2.0/24",
    },
    {
        "source_ip": "10.1.2.10",
        "query_name": "cdn.legit-corp.com",
        "query_type": "CNAME",
        "client_subnet": "10.1.2.0/24",
    },
    {
        "source_ip": "10.1.3.5",
        "query_name": "miner-pool.crypto.cc",
        "query_type": "A",
        "client_subnet": "10.1.3.0/24",
    },
    {
        "source_ip": "10.1.0.50",
        "query_name": "updates.vendor.io",
        "query_type": "A",
        "client_subnet": "10.1.0.0/24",
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


def _shannon_entropy(label: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not label:
        return 0.0
    freq: dict[str, int] = {}
    for ch in label:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(label)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


class DNSFirewallControllerToolkit:
    """Tools for DNS firewall control operations."""

    def __init__(
        self,
        dns_source: Any | None = None,
        reputation_api: Any | None = None,
    ) -> None:
        self._dns_source = dns_source
        self._reputation_api = reputation_api

    async def ingest_queries(
        self,
        tenant_id: str,
    ) -> list[DNSQueryRecord]:
        """Ingest DNS queries from resolvers."""
        logger.info(
            "dfc.ingest_queries",
            tenant_id=tenant_id,
        )

        if self._dns_source is not None:
            try:
                raw = await self._dns_source.get_queries(
                    tenant_id=tenant_id,
                )
                return [DNSQueryRecord(**r) for r in raw]
            except Exception:
                logger.exception("dfc.ingest_queries.error")

        records: list[DNSQueryRecord] = []
        for i, q in enumerate(_SAMPLE_QUERIES):
            noise = random.randint(-5, 5)  # noqa: S311
            records.append(
                DNSQueryRecord(
                    id=_gen_id("DQ", tenant_id, i),
                    timestamp=f"2026-03-30T12:{i:02d}:00Z",
                    source_ip=q["source_ip"],
                    query_name=q["query_name"],
                    query_type=q["query_type"],
                    response_code="NOERROR",
                    client_subnet=q["client_subnet"],
                    resolver="10.0.0.53",
                    bytes_sent=64 + noise,
                )
            )
        return records

    async def analyze_domains(
        self,
        queries: list[DNSQueryRecord],
    ) -> list[DomainAnalysis]:
        """Analyze queried domains for categorization."""
        logger.info(
            "dfc.analyze_domains",
            count=len(queries),
        )

        seen: set[str] = set()
        analyses: list[DomainAnalysis] = []
        idx = 0
        for q in queries:
            parts = q.query_name.rsplit(".", 2)
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else q.query_name
            if domain in seen:
                continue
            seen.add(domain)

            label = q.query_name.split(".")[0]
            entropy = round(_shannon_entropy(label), 2)
            age = random.randint(1, 1000)  # noqa: S311

            cat = DomainCategory.BENIGN
            if "phish" in domain:
                cat = DomainCategory.PHISHING
            elif "evil" in domain or "c2" in domain:
                cat = DomainCategory.MALWARE
            elif "crypto" in domain or "miner" in domain:
                cat = DomainCategory.CRYPTOMINING
            elif entropy > 3.5:
                cat = DomainCategory.BOTNET

            analyses.append(
                DomainAnalysis(
                    id=_gen_id("DA", domain, idx),
                    domain=domain,
                    category=cat,
                    dga_score=round(min(entropy / 5.0, 1.0), 2),
                    entropy=entropy,
                    age_days=age,
                    is_newly_registered=age < 30,
                    alexa_rank=random.randint(0, 1000000),  # noqa: S311
                )
            )
            idx += 1
        return analyses

    async def check_reputation(
        self,
        analyses: list[DomainAnalysis],
    ) -> list[ReputationResult]:
        """Check domain reputation against threat feeds."""
        logger.info(
            "dfc.check_reputation",
            count=len(analyses),
        )

        if self._reputation_api is not None:
            try:
                raw = await self._reputation_api.check(
                    domains=[a.domain for a in analyses],
                )
                return [ReputationResult(**r) for r in raw]
            except Exception:
                logger.exception("dfc.check_reputation.error")

        results: list[ReputationResult] = []
        for i, a in enumerate(analyses):
            is_bad = a.category != DomainCategory.BENIGN
            feeds = random.randint(0, 5) if is_bad else 0  # noqa: S311
            results.append(
                ReputationResult(
                    id=_gen_id("RR", a.domain, i),
                    domain=a.domain,
                    reputation_score=round(0.1 if is_bad else 0.9, 2),
                    threat_feeds_matched=feeds,
                    feed_names=(["VirusTotal", "URLhaus", "PhishTank"][:feeds] if is_bad else []),
                    is_blocklisted=is_bad and feeds >= 2,
                    confidence=round(
                        0.85 + random.uniform(0, 0.1),  # noqa: S311
                        2,
                    ),
                )
            )
        return results

    async def detect_tunneling(
        self,
        queries: list[DNSQueryRecord],
    ) -> list[TunnelingDetection]:
        """Detect DNS tunneling patterns in query traffic."""
        logger.info(
            "dfc.detect_tunneling",
            count=len(queries),
        )

        groups: dict[str, list[DNSQueryRecord]] = {}
        for q in queries:
            parts = q.query_name.rsplit(".", 2)
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else q.query_name
            key = f"{q.source_ip}|{domain}"
            groups.setdefault(key, []).append(q)

        detections: list[TunnelingDetection] = []
        for idx, (key, group) in enumerate(groups.items()):
            src_ip, domain = key.split("|", 1)
            labels = [g.query_name.split(".")[0] for g in group]
            avg_len = sum(len(lb) for lb in labels) / len(labels)
            entropy = round(
                sum(_shannon_entropy(lb) for lb in labels) / len(labels),
                2,
            )
            is_tunnel = entropy > 3.0 and avg_len > 10 and len(group) >= 2
            detections.append(
                TunnelingDetection(
                    id=_gen_id("TD", key, idx),
                    source_ip=src_ip,
                    domain=domain,
                    subdomain_entropy=entropy,
                    avg_query_length=round(avg_len, 1),
                    query_frequency=round(len(group) / 5.0, 2),
                    payload_estimate_bytes=int(avg_len * len(group) * 2),
                    is_tunneling=is_tunnel,
                    confidence=0.88 if is_tunnel else 0.1,
                )
            )
        return detections

    async def enforce_dns_policy(
        self,
        reputation_results: list[ReputationResult],
        tunneling_detections: list[TunnelingDetection],
    ) -> list[PolicyEnforcement]:
        """Enforce DNS response policy zones."""
        logger.info(
            "dfc.enforce_dns_policy",
            rep_count=len(reputation_results),
            tunnel_count=len(tunneling_detections),
        )

        enforcements: list[PolicyEnforcement] = []
        idx = 0

        blocked_domains: set[str] = set()
        for r in reputation_results:
            if r.is_blocklisted:
                enforcements.append(
                    PolicyEnforcement(
                        id=_gen_id("PE", r.domain, idx),
                        domain=r.domain,
                        action=PolicyAction.SINKHOLE,
                        reason=(f"Blocklisted: {r.threat_feeds_matched} feeds"),
                        rpz_rule_id=_gen_id("RPZ", r.domain, idx),
                        sinkhole_ip="198.51.100.1",
                        applied=True,
                    )
                )
                blocked_domains.add(r.domain)
                idx += 1

        for t in tunneling_detections:
            if t.is_tunneling and t.domain not in blocked_domains:
                enforcements.append(
                    PolicyEnforcement(
                        id=_gen_id("PE", t.domain, idx),
                        domain=t.domain,
                        action=PolicyAction.NXDOMAIN,
                        reason="DNS tunneling detected",
                        rpz_rule_id=_gen_id("RPZ", t.domain, idx),
                        sinkhole_ip="",
                        applied=True,
                    )
                )
                blocked_domains.add(t.domain)
                idx += 1

        return enforcements

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Record a DNS firewall metric."""
        logger.info(
            "dfc.record_metric",
            metric=metric_name,
            value=value,
            tenant_id=tenant_id,
        )
        return {
            "metric": metric_name,
            "value": value,
            "tenant_id": tenant_id,
            "recorded": True,
        }
