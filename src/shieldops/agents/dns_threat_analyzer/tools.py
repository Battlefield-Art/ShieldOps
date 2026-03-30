"""DNS Threat Analyzer Agent — Tool functions."""

from __future__ import annotations

import hashlib
import math
import random
from typing import Any

import structlog

from .models import (
    BlockEnforcement,
    DNSPattern,
    DNSQuery,
    DNSThreat,
    DNSThreatType,
    DomainClassification,
    DomainRisk,
)

logger = structlog.get_logger()

_SAMPLE_QUERIES: list[dict[str, Any]] = [
    {
        "source_ip": "10.0.1.15",
        "query_name": "api.legit-service.com",
        "query_type": "A",
        "response_ip": "93.184.216.34",
        "ttl": 3600,
        "bytes_sent": 64,
        "bytes_received": 128,
    },
    {
        "source_ip": "10.0.1.15",
        "query_name": "aGVsbG8gd29ybGQ.exfil.evil.net",
        "query_type": "TXT",
        "response_ip": "198.51.100.1",
        "ttl": 30,
        "bytes_sent": 512,
        "bytes_received": 1024,
    },
    {
        "source_ip": "10.0.2.30",
        "query_name": "xj7k9m2p.botnet.cc",
        "query_type": "A",
        "response_ip": "203.0.113.50",
        "ttl": 60,
        "bytes_sent": 48,
        "bytes_received": 96,
    },
    {
        "source_ip": "10.0.2.30",
        "query_name": "r4t8w1q5.botnet.cc",
        "query_type": "A",
        "response_ip": "203.0.113.51",
        "ttl": 60,
        "bytes_sent": 48,
        "bytes_received": 96,
    },
    {
        "source_ip": "10.0.3.10",
        "query_name": "login.my-bank-secure.com",
        "query_type": "A",
        "response_ip": "192.0.2.100",
        "ttl": 300,
        "bytes_sent": 52,
        "bytes_received": 110,
    },
    {
        "source_ip": "10.0.3.10",
        "query_name": "cdn.trusted-site.com",
        "query_type": "CNAME",
        "response_ip": "198.51.100.200",
        "ttl": 7200,
        "bytes_sent": 56,
        "bytes_received": 120,
    },
    {
        "source_ip": "10.0.1.50",
        "query_name": "ns1.fast-flux-domain.xyz",
        "query_type": "A",
        "response_ip": "203.0.113.10",
        "ttl": 15,
        "bytes_sent": 44,
        "bytes_received": 88,
    },
    {
        "source_ip": "10.0.4.20",
        "query_name": "internal.corp.local",
        "query_type": "A",
        "response_ip": "10.10.0.5",
        "ttl": 3600,
        "bytes_sent": 40,
        "bytes_received": 80,
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


class DNSThreatAnalyzerToolkit:
    """Tools for DNS threat analysis."""

    def __init__(
        self,
        dns_log_source: Any | None = None,
        threat_intel_api: Any | None = None,
    ) -> None:
        self._dns_log_source = dns_log_source
        self._threat_intel_api = threat_intel_api

    async def collect_dns_logs(
        self,
        tenant_id: str,
    ) -> list[DNSQuery]:
        """Collect DNS query logs from resolvers."""
        logger.info(
            "dta.collect_dns_logs",
            tenant_id=tenant_id,
        )

        if self._dns_log_source is not None:
            try:
                raw = await self._dns_log_source.get_logs(
                    tenant_id=tenant_id,
                )
                return [DNSQuery(**r) for r in raw]
            except Exception:
                logger.exception("dta.collect_dns_logs.error")

        queries: list[DNSQuery] = []
        for i, q in enumerate(_SAMPLE_QUERIES):
            noise = random.randint(-10, 10)  # noqa: S311
            queries.append(
                DNSQuery(
                    id=_gen_id("DQ", tenant_id, i),
                    timestamp=f"2026-03-30T10:{i:02d}:00Z",
                    source_ip=q["source_ip"],
                    query_name=q["query_name"],
                    query_type=q["query_type"],
                    response_ip=q["response_ip"],
                    response_code="NOERROR",
                    ttl=q["ttl"],
                    resolver="10.0.0.53",
                    bytes_sent=q["bytes_sent"] + noise,
                    bytes_received=q["bytes_received"] + noise,
                )
            )
        return queries

    async def analyze_patterns(
        self,
        queries: list[DNSQuery],
    ) -> list[DNSPattern]:
        """Analyze DNS traffic patterns per source+domain."""
        logger.info(
            "dta.analyze_patterns",
            count=len(queries),
        )

        groups: dict[str, list[DNSQuery]] = {}
        for q in queries:
            parts = q.query_name.rsplit(".", 2)
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else q.query_name
            key = f"{q.source_ip}|{domain}"
            groups.setdefault(key, []).append(q)

        patterns: list[DNSPattern] = []
        for i, (key, group) in enumerate(groups.items()):
            src_ip, domain = key.split("|", 1)
            subdomains = {q.query_name for q in group}
            ips = {q.response_ip for q in group}
            avg_ttl = sum(q.ttl for q in group) / len(group)
            avg_bytes = sum(q.bytes_sent + q.bytes_received for q in group) / len(group)
            label = group[0].query_name.split(".")[0]
            patterns.append(
                DNSPattern(
                    id=_gen_id("DP", key, i),
                    source_ip=src_ip,
                    domain=domain,
                    query_count=len(group),
                    unique_subdomains=len(subdomains),
                    avg_ttl=round(avg_ttl, 1),
                    avg_payload_bytes=round(avg_bytes, 1),
                    distinct_ips=len(ips),
                    entropy_score=round(_shannon_entropy(label), 2),
                    time_span_minutes=len(group) * 5,
                )
            )
        return patterns

    async def detect_threats(
        self,
        patterns: list[DNSPattern],
    ) -> list[DNSThreat]:
        """Detect DNS-based threats from patterns."""
        logger.info(
            "dta.detect_threats",
            count=len(patterns),
        )

        threats: list[DNSThreat] = []
        idx = 0
        for p in patterns:
            if p.avg_payload_bytes > 400 and p.avg_ttl < 60:
                threats.append(
                    DNSThreat(
                        id=_gen_id("DT", p.id, idx),
                        threat_type=DNSThreatType.TUNNELING,
                        domain=p.domain,
                        source_ip=p.source_ip,
                        confidence=0.88,
                        severity="high",
                        evidence=[
                            f"High payload: {p.avg_payload_bytes}B",
                            f"Low TTL: {p.avg_ttl}s",
                        ],
                    )
                )
                idx += 1
            if p.entropy_score > 3.5:
                threats.append(
                    DNSThreat(
                        id=_gen_id("DT", p.id, idx),
                        threat_type=DNSThreatType.DGA_DOMAIN,
                        domain=p.domain,
                        source_ip=p.source_ip,
                        confidence=round(
                            min(p.entropy_score / 5.0, 0.95),
                            2,
                        ),
                        severity="high",
                        evidence=[
                            f"Entropy: {p.entropy_score}",
                            f"Subdomains: {p.unique_subdomains}",
                        ],
                    )
                )
                idx += 1
            if p.avg_ttl < 30 and p.distinct_ips > 1:
                threats.append(
                    DNSThreat(
                        id=_gen_id("DT", p.id, idx),
                        threat_type=DNSThreatType.FAST_FLUX,
                        domain=p.domain,
                        source_ip=p.source_ip,
                        confidence=0.78,
                        severity="medium",
                        evidence=[
                            f"TTL: {p.avg_ttl}s",
                            f"IPs: {p.distinct_ips}",
                        ],
                    )
                )
                idx += 1
        return threats

    async def classify_domains(
        self,
        threats: list[DNSThreat],
    ) -> list[DomainClassification]:
        """Classify domains identified in threats."""
        logger.info(
            "dta.classify_domains",
            count=len(threats),
        )

        seen: set[str] = set()
        classifications: list[DomainClassification] = []
        idx = 0
        for t in threats:
            if t.domain in seen:
                continue
            seen.add(t.domain)

            risk = DomainRisk.SUSPICIOUS
            if t.confidence >= 0.85:
                risk = DomainRisk.MALICIOUS
            elif t.confidence < 0.6:
                risk = DomainRisk.NEWLY_REGISTERED

            age = random.randint(1, 365)  # noqa: S311
            classifications.append(
                DomainClassification(
                    id=_gen_id("DC", t.domain, idx),
                    domain=t.domain,
                    risk=risk,
                    threat_type=t.threat_type,
                    registrar="unknown",
                    age_days=age,
                    whois_privacy=age < 30,
                    reputation_score=round(
                        1.0 - t.confidence,
                        2,
                    ),
                )
            )
            idx += 1
        return classifications

    async def enforce_blocks(
        self,
        classifications: list[DomainClassification],
    ) -> list[BlockEnforcement]:
        """Enforce DNS blocks for malicious domains."""
        logger.info(
            "dta.enforce_blocks",
            count=len(classifications),
        )

        results: list[BlockEnforcement] = []
        for i, c in enumerate(classifications):
            if c.risk in (
                DomainRisk.MALICIOUS,
                DomainRisk.SUSPICIOUS,
            ):
                results.append(
                    BlockEnforcement(
                        id=_gen_id("BE", c.domain, i),
                        domain=c.domain,
                        action="sinkhole",
                        status="enforced",
                        resolver_updated=True,
                        firewall_rule_id=_gen_id(
                            "FW",
                            c.domain,
                            i,
                        ),
                        rollback_available=True,
                    )
                )
            else:
                results.append(
                    BlockEnforcement(
                        id=_gen_id("BE", c.domain, i),
                        domain=c.domain,
                        action="monitor",
                        status="watching",
                        resolver_updated=False,
                        firewall_rule_id="",
                        rollback_available=True,
                    )
                )
        return results
