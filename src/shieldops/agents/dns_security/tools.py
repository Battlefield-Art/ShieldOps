"""DNS Security Agent — Tool functions for DNS threat detection."""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import DNSQuery, DNSResponse, DNSSeverity, DNSThreat, DNSThreatType

logger = structlog.get_logger()


def _generate_threat_id(domain: str, threat_type: str, index: int) -> str:
    """Generate a deterministic threat ID."""
    raw = f"{domain}:{threat_type}:{index}"
    return f"DNS-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


def _calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy of a domain string."""
    if not domain:
        return 0.0
    freq: dict[str, int] = {}
    for ch in domain:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(domain)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(
                min(curr_row[j] + 1, prev_row[j + 1] + 1, prev_row[j] + cost)
            )
        prev_row = curr_row
    return prev_row[-1]


# Known brand domains for typosquatting detection
_BRAND_DOMAINS = [
    "google.com", "microsoft.com", "amazon.com", "apple.com",
    "facebook.com", "github.com", "cloudflare.com", "stripe.com",
]


class DNSSecurityToolkit:
    """Tools for DNS-based threat detection."""

    def __init__(
        self,
        dns_log_client: Any | None = None,
        threat_intel_client: Any | None = None,
        firewall_client: Any | None = None,
    ) -> None:
        self._dns_log_client = dns_log_client
        self._threat_intel_client = threat_intel_client
        self._firewall_client = firewall_client

    async def collect_dns_queries(
        self, tenant_id: str
    ) -> list[DNSQuery]:
        """Collect DNS query logs for analysis."""
        logger.info("dns_security.collect", tenant_id=tenant_id)

        if self._dns_log_client is not None:
            try:
                raw = await self._dns_log_client.query_dns_logs(
                    tenant_id=tenant_id,
                )
                return [DNSQuery(**q) for q in raw]
            except Exception:
                logger.exception("dns_security.collect.error")

        # Fallback: synthetic DNS data
        now = datetime.now(UTC)
        return [
            DNSQuery(
                id="dns-001",
                domain="api.example.com",
                query_type="A",
                source_ip="10.0.1.100",
                response_ip="93.184.216.34",
                ttl=300,
                timestamp=now,
            ),
            DNSQuery(
                id="dns-002",
                domain="aG9zdC1leGZpbC5ldmlsLmNvbQ.tunnel.evil.com",
                query_type="TXT",
                source_ip="10.0.1.50",
                response_ip="",
                ttl=60,
                timestamp=now,
                query_size=180,
            ),
            DNSQuery(
                id="dns-003",
                domain="xk3jf9al2m.malware-c2.net",
                query_type="A",
                source_ip="10.0.2.30",
                response_ip="192.168.1.1",
                ttl=30,
                timestamp=now,
                response_code="NXDOMAIN",
            ),
            DNSQuery(
                id="dns-004",
                domain="g00gle.com",
                query_type="A",
                source_ip="10.0.1.200",
                response_ip="104.21.0.1",
                ttl=3600,
                timestamp=now,
            ),
        ]

    async def detect_tunneling(
        self, queries: list[DNSQuery]
    ) -> list[DNSThreat]:
        """Detect DNS tunneling based on query characteristics."""
        logger.info(
            "dns_security.detect_tunneling", query_count=len(queries)
        )

        threats: list[DNSThreat] = []
        for i, query in enumerate(queries):
            # Tunneling indicators: long subdomains, high entropy, TXT queries
            subdomain = query.domain.split(".")[0]
            entropy = _calculate_entropy(subdomain)
            is_txt = query.query_type in ("TXT", "NULL")
            is_long = len(subdomain) > 30

            if (entropy > 3.5 and is_long) or (is_txt and query.query_size > 100):
                confidence = min(1.0, entropy / 5.0)
                severity = (
                    DNSSeverity.HIGH if confidence > 0.7 else DNSSeverity.MEDIUM
                )
                threats.append(
                    DNSThreat(
                        id=_generate_threat_id(
                            query.domain, "tunneling", i
                        ),
                        threat_type=DNSThreatType.TUNNELING,
                        domain=query.domain,
                        severity=severity,
                        confidence=round(confidence, 3),
                        mitre_technique="T1071.004",
                        source_ips=[query.source_ip],
                        indicators=[
                            f"entropy={entropy}",
                            f"subdomain_len={len(subdomain)}",
                            f"query_type={query.query_type}",
                        ],
                        description=(
                            f"Potential DNS tunneling: {query.domain} "
                            f"(entropy={entropy}, type={query.query_type})"
                        ),
                    )
                )

        return threats

    async def detect_dga(
        self, queries: list[DNSQuery]
    ) -> list[DNSThreat]:
        """Detect Domain Generation Algorithm domains."""
        logger.info("dns_security.detect_dga", query_count=len(queries))

        threats: list[DNSThreat] = []
        for i, query in enumerate(queries):
            domain_parts = query.domain.split(".")
            if len(domain_parts) < 2:
                continue

            sld = domain_parts[-2]
            entropy = _calculate_entropy(sld)
            has_nxdomain = query.response_code == "NXDOMAIN"

            # DGA indicators: high entropy SLD + NXDOMAIN
            if entropy > 3.0 and (has_nxdomain or len(sld) > 12):
                confidence = min(1.0, (entropy - 2.0) / 3.0)
                if has_nxdomain:
                    confidence = min(1.0, confidence + 0.2)

                threats.append(
                    DNSThreat(
                        id=_generate_threat_id(query.domain, "dga", i),
                        threat_type=DNSThreatType.DGA,
                        domain=query.domain,
                        severity=DNSSeverity.HIGH,
                        confidence=round(confidence, 3),
                        mitre_technique="T1568.002",
                        source_ips=[query.source_ip],
                        indicators=[
                            f"entropy={entropy}",
                            f"nxdomain={has_nxdomain}",
                            f"sld_length={len(sld)}",
                        ],
                        description=(
                            f"Potential DGA domain: {query.domain} "
                            f"(entropy={entropy}, nxdomain={has_nxdomain})"
                        ),
                    )
                )

        return threats

    async def detect_typosquatting(
        self, queries: list[DNSQuery]
    ) -> list[DNSThreat]:
        """Detect typosquatting domains targeting known brands."""
        logger.info(
            "dns_security.detect_typosquatting", query_count=len(queries)
        )

        threats: list[DNSThreat] = []
        for i, query in enumerate(queries):
            for brand in _BRAND_DOMAINS:
                if query.domain == brand:
                    continue

                distance = _levenshtein_distance(
                    query.domain.lower(), brand.lower()
                )
                if 1 <= distance <= 2:
                    confidence = 1.0 - (distance / 5.0)
                    threats.append(
                        DNSThreat(
                            id=_generate_threat_id(
                                query.domain, "typosquatting", i
                            ),
                            threat_type=DNSThreatType.TYPOSQUATTING,
                            domain=query.domain,
                            severity=DNSSeverity.MEDIUM,
                            confidence=round(confidence, 3),
                            mitre_technique="T1583.001",
                            source_ips=[query.source_ip],
                            indicators=[
                                f"target_brand={brand}",
                                f"edit_distance={distance}",
                            ],
                            description=(
                                f"Typosquatting: {query.domain} "
                                f"resembles {brand} (distance={distance})"
                            ),
                        )
                    )
                    break

        return threats

    async def respond_to_threat(
        self, threat: DNSThreat
    ) -> DNSResponse:
        """Take response action for a DNS threat."""
        logger.info(
            "dns_security.respond",
            threat_id=threat.id,
            threat_type=threat.threat_type,
        )

        action = "block_domain"
        if threat.threat_type == DNSThreatType.TYPOSQUATTING:
            action = "sinkhole"

        if self._firewall_client is not None:
            try:
                await self._firewall_client.block_domain(
                    domain=threat.domain
                )
                return DNSResponse(
                    threat_id=threat.id,
                    action=action,
                    target=threat.domain,
                    status="completed",
                    details=f"Blocked {threat.domain} via firewall",
                )
            except Exception:
                logger.exception("dns_security.respond.error")

        return DNSResponse(
            threat_id=threat.id,
            action=action,
            target=threat.domain,
            status="simulated",
            details=f"Would {action} {threat.domain}",
        )
