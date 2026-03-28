"""Tool functions for the Finding Correlator Agent."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.finding_correlator.models import (
    CorrelationGroup,
    CorrelationStrength,
    NormalizedFinding,
    PrioritizedFinding,
    RawFinding,
)

logger = structlog.get_logger()


class FindingCorrelatorToolkit:
    """Toolkit for deduplicating and correlating findings."""

    def __init__(
        self,
        finding_sources: Any | None = None,
        asset_inventory: Any | None = None,
        vuln_database: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._finding_sources = finding_sources
        self._asset_inventory = asset_inventory
        self._vuln_database = vuln_database
        self._repository = repository

    async def collect_findings(
        self,
        tenant_id: str,
    ) -> list[RawFinding]:
        """Collect raw findings from all agents."""
        logger.info(
            "finding_correlator.collect",
            tenant_id=tenant_id,
        )
        if self._finding_sources is not None:
            try:
                return await self._finding_sources.list(tenant_id)
            except Exception:
                logger.warning("finding_correlator.collect_fallback")
        return []

    async def normalize_findings(
        self,
        raw_findings: list[RawFinding],
    ) -> list[NormalizedFinding]:
        """Normalize findings to a common schema."""
        logger.info(
            "finding_correlator.normalize",
            count=len(raw_findings),
        )
        normalized: list[NormalizedFinding] = []
        for rf in raw_findings:
            fingerprint = (f"{rf.cve_id or rf.title}:{rf.asset}:{rf.severity}").lower().strip()
            normalized.append(
                NormalizedFinding(
                    id=rf.id or uuid4().hex[:12],
                    original_ids=[rf.id],
                    source_type=rf.source_type,
                    title=rf.title,
                    description=rf.description,
                    severity=rf.severity.lower().strip(),
                    asset=rf.asset.lower().strip(),
                    cvss_score=rf.cvss_score,
                    cve_id=rf.cve_id,
                    fingerprint=fingerprint,
                )
            )
        return normalized

    async def deduplicate_findings(
        self,
        findings: list[NormalizedFinding],
    ) -> tuple[list[NormalizedFinding], int]:
        """Deduplicate findings by fingerprint."""
        logger.info(
            "finding_correlator.dedup",
            count=len(findings),
        )
        seen: dict[str, NormalizedFinding] = {}
        dupes = 0
        for f in findings:
            if f.fingerprint in seen:
                existing = seen[f.fingerprint]
                existing.original_ids.extend(f.original_ids)
                if f.cvss_score > existing.cvss_score:
                    existing.cvss_score = f.cvss_score
                dupes += 1
            else:
                seen[f.fingerprint] = f
        return list(seen.values()), dupes

    async def correlate_findings(
        self,
        findings: list[NormalizedFinding],
    ) -> list[CorrelationGroup]:
        """Correlate related findings."""
        logger.info(
            "finding_correlator.correlate",
            count=len(findings),
        )
        groups: list[CorrelationGroup] = []

        # Group by asset
        asset_map: dict[str, list[NormalizedFinding]] = {}
        for f in findings:
            asset_map.setdefault(f.asset, []).append(f)
        for asset, flist in asset_map.items():
            if len(flist) >= 2:
                max_cvss = max(f.cvss_score for f in flist)
                groups.append(
                    CorrelationGroup(
                        id=f"cg-{uuid4().hex[:8]}",
                        finding_ids=[f.id for f in flist],
                        strength=(
                            CorrelationStrength.STRONG
                            if len(flist) >= 3
                            else CorrelationStrength.MODERATE
                        ),
                        correlation_reason=(f"Same asset: {asset}"),
                        shared_asset=asset,
                        combined_risk=min(max_cvss * 1.2, 10.0),
                    )
                )

        # Group by CVE
        cve_map: dict[str, list[NormalizedFinding]] = {}
        for f in findings:
            if f.cve_id:
                cve_map.setdefault(f.cve_id, []).append(f)
        for cve, flist in cve_map.items():
            if len(flist) >= 2:
                groups.append(
                    CorrelationGroup(
                        id=f"cg-{uuid4().hex[:8]}",
                        finding_ids=[f.id for f in flist],
                        strength=(CorrelationStrength.STRONG),
                        correlation_reason=(f"Same CVE: {cve}"),
                        shared_asset="",
                        combined_risk=max(f.cvss_score for f in flist),
                    )
                )

        return groups

    async def prioritize_findings(
        self,
        findings: list[NormalizedFinding],
        groups: list[CorrelationGroup],
    ) -> list[PrioritizedFinding]:
        """Prioritize findings by risk."""
        logger.info(
            "finding_correlator.prioritize",
            count=len(findings),
        )
        group_map: dict[str, str] = {}
        for g in groups:
            for fid in g.finding_ids:
                group_map[fid] = g.id

        scored: list[tuple[float, NormalizedFinding]] = []
        for f in findings:
            score = f.cvss_score
            if f.id in group_map:
                score *= 1.15
            scored.append((score, f))
        scored.sort(key=lambda x: x[0], reverse=True)

        prioritized: list[PrioritizedFinding] = []
        for rank, (score, f) in enumerate(scored, 1):
            prioritized.append(
                PrioritizedFinding(
                    finding_id=f.id,
                    title=f.title,
                    severity=f.severity,
                    priority_rank=rank,
                    risk_score=round(score, 2),
                    correlation_group_id=group_map.get(f.id, ""),
                    recommended_action=(
                        "Remediate immediately" if score >= 9.0 else "Schedule remediation"
                    ),
                )
            )
        return prioritized
