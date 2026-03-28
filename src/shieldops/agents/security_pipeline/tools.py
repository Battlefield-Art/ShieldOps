"""Tool functions for the Security Pipeline Agent."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_pipeline.models import (
    DiscoveryDispatch,
    FindingCollection,
    PentestDispatch,
    PipelinePlan,
    RemediationDispatch,
    VerificationResult,
)

logger = structlog.get_logger()


class SecurityPipelineToolkit:
    """Toolkit for orchestrating the full security pipeline."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        finding_store: Any | None = None,
        remediation_engine: Any | None = None,
        verification_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._agent_registry = agent_registry
        self._finding_store = finding_store
        self._remediation_engine = remediation_engine
        self._verification_engine = verification_engine
        self._policy_engine = policy_engine
        self._repository = repository

    async def plan_pipeline(
        self,
        tenant_id: str,
        target_assets: list[str] | None = None,
    ) -> PipelinePlan:
        """Plan which agents to dispatch."""
        logger.info(
            "security_pipeline.plan",
            tenant_id=tenant_id,
        )
        default_agents = [
            "cloud_posture",
            "container_security",
            "api_security",
            "secrets_scanner",
            "supply_chain_security",
        ]
        return PipelinePlan(
            id=f"plan-{uuid4().hex[:8]}",
            phases=[
                "discovery",
                "testing",
                "analysis",
                "remediation",
                "verification",
            ],
            agents_to_dispatch=default_agents,
            estimated_duration_minutes=30,
            target_assets=target_assets or [],
        )

    async def dispatch_discovery(
        self,
        tenant_id: str,
        agents: list[str],
    ) -> list[DiscoveryDispatch]:
        """Dispatch discovery agents."""
        logger.info(
            "security_pipeline.dispatch_discovery",
            tenant_id=tenant_id,
            agent_count=len(agents),
        )
        results: list[DiscoveryDispatch] = []
        for agent in agents:
            if self._agent_registry is not None:
                try:
                    r = await self._agent_registry.run(agent, tenant_id)
                    results.append(
                        DiscoveryDispatch(
                            agent_name=agent,
                            status="completed",
                            assets_discovered=r.get("assets", 0),
                            findings_count=r.get("findings", 0),
                        )
                    )
                    continue
                except Exception:
                    logger.warning(
                        "security_pipeline.discovery_err",
                        agent=agent,
                    )
            results.append(
                DiscoveryDispatch(
                    agent_name=agent,
                    status="simulated",
                    assets_discovered=0,
                    findings_count=0,
                )
            )
        return results

    async def dispatch_pentest(
        self,
        tenant_id: str,
        agents: list[str],
    ) -> list[PentestDispatch]:
        """Dispatch pentest/scanner agents."""
        logger.info(
            "security_pipeline.dispatch_pentest",
            tenant_id=tenant_id,
            agent_count=len(agents),
        )
        results: list[PentestDispatch] = []
        for agent in agents:
            if self._agent_registry is not None:
                try:
                    r = await self._agent_registry.run(agent, tenant_id)
                    results.append(
                        PentestDispatch(
                            agent_name=agent,
                            status="completed",
                            vulnerabilities_found=r.get("vulns", 0),
                            critical_count=r.get("critical", 0),
                            high_count=r.get("high", 0),
                        )
                    )
                    continue
                except Exception:
                    logger.warning(
                        "security_pipeline.pentest_err",
                        agent=agent,
                    )
            results.append(
                PentestDispatch(
                    agent_name=agent,
                    status="simulated",
                    vulnerabilities_found=0,
                )
            )
        return results

    async def collect_findings(
        self,
        discovery_results: list[DiscoveryDispatch],
        pentest_results: list[PentestDispatch],
    ) -> list[FindingCollection]:
        """Collect and aggregate findings."""
        logger.info(
            "security_pipeline.collect_findings",
            discovery_count=len(discovery_results),
            pentest_count=len(pentest_results),
        )
        findings: list[FindingCollection] = []
        if self._finding_store is not None:
            try:
                raw = await self._finding_store.list_all()
                for r in raw:
                    findings.append(
                        FindingCollection(
                            id=r.get(
                                "id",
                                uuid4().hex[:8],
                            ),
                            source_agent=r.get("source", ""),
                            severity=r.get("severity", "medium"),
                            title=r.get("title", ""),
                            description=r.get("description", ""),
                            asset=r.get("asset", ""),
                        )
                    )
                return findings
            except Exception:
                logger.warning("security_pipeline.collect_fallback")
        return findings

    async def dispatch_remediation(
        self,
        findings: list[FindingCollection],
    ) -> list[RemediationDispatch]:
        """Dispatch remediations for findings."""
        logger.info(
            "security_pipeline.dispatch_remediation",
            finding_count=len(findings),
        )
        results: list[RemediationDispatch] = []
        for finding in findings:
            if self._remediation_engine is not None:
                try:
                    r = await self._remediation_engine.fix(finding.id)
                    results.append(
                        RemediationDispatch(
                            finding_id=finding.id,
                            agent_name=r.get("agent", "auto"),
                            status="completed",
                            action_taken=r.get("action", ""),
                            rollback_available=True,
                        )
                    )
                    continue
                except Exception:
                    logger.warning(
                        "security_pipeline.remediate_err",
                        finding_id=finding.id,
                    )
            results.append(
                RemediationDispatch(
                    finding_id=finding.id,
                    agent_name="pending",
                    status="pending",
                    action_taken="",
                )
            )
        return results

    async def verify_results(
        self,
        remediations: list[RemediationDispatch],
    ) -> list[VerificationResult]:
        """Verify remediations were effective."""
        logger.info(
            "security_pipeline.verify",
            remediation_count=len(remediations),
        )
        results: list[VerificationResult] = []
        for rem in remediations:
            if self._verification_engine is not None and rem.status == "completed":
                try:
                    v = await self._verification_engine.verify(rem.finding_id)
                    results.append(
                        VerificationResult(
                            finding_id=rem.finding_id,
                            verified=True,
                            retest_passed=v.get("passed", False),
                            remaining_risk=v.get("risk", "none"),
                        )
                    )
                    continue
                except Exception:
                    logger.warning(
                        "security_pipeline.verify_err",
                        finding_id=rem.finding_id,
                    )
            results.append(
                VerificationResult(
                    finding_id=rem.finding_id,
                    verified=False,
                    retest_passed=False,
                    remaining_risk="unknown",
                )
            )
        return results
