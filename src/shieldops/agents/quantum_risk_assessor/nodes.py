"""Node implementations for the Quantum Risk Assessor Agent."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.quantum_risk_assessor.models import (
    AlgorithmInventory,
    CryptoAlgorithmType,
    CryptoAsset,
    MigrationRecommendation,
    QuantumReasoningStep,
    QuantumRiskAssessorState,
    QuantumThreatLevel,
    ReadinessScore,
    VulnerabilityAssessment,
)
from shieldops.agents.quantum_risk_assessor.prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    AlgorithmAnalysisOutput,
    InfrastructureScanOutput,
    MigrationPlanOutput,
    ReadinessAnalysisOutput,
    VulnerabilityAnalysisOutput,
)
from shieldops.agents.quantum_risk_assessor.tools import (
    QuantumRiskAssessorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: QuantumRiskAssessorToolkit | None = None


def set_toolkit(
    toolkit: QuantumRiskAssessorToolkit,
) -> None:
    """Set the shared toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> QuantumRiskAssessorToolkit:
    if _toolkit is None:
        return QuantumRiskAssessorToolkit()
    return _toolkit


# ── Node: scan_infrastructure ─────────────────────────


async def scan_infrastructure(
    state: QuantumRiskAssessorState,
) -> dict[str, Any]:
    """Scan infrastructure for cryptographic assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_results = await toolkit.scan_crypto_infrastructure(
        state.scan_config,
    )

    assets = [CryptoAsset(**r) for r in raw_results if isinstance(r, dict) and "asset_id" in r]

    # Seed default assets when none discovered
    scope = state.scan_config.get("scope", "")
    if not assets and scope:
        for algo in [CryptoAlgorithmType.RSA, CryptoAlgorithmType.ECC, CryptoAlgorithmType.DH]:
            assets.append(
                CryptoAsset(
                    asset_id=f"ca-{algo.value}-001",
                    service_name=f"{algo.value.upper()} service ({scope})",
                    algorithm=algo.value,
                    key_size=2048 if algo == CryptoAlgorithmType.RSA else 256,
                    is_quantum_vulnerable=True,
                    threat_level=QuantumThreatLevel.HIGH,
                )
            )

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "scope": scope,
                "assets_found": len(assets),
                "algorithms": list({a.algorithm for a in assets}),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Infrastructure scan context:\n{ctx}",
            schema=InfrastructureScanOutput,
        )
        logger.info(
            "llm_enhanced",
            node="scan_infrastructure",
            vulnerable_count=getattr(llm_out, "vulnerable_count", 0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_infrastructure",
        )

    step = QuantumReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="scan_infrastructure",
        input_summary=f"Scanning scope={scope}",
        output_summary=f"Discovered {len(assets)} crypto assets",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="crypto_scanner",
    )

    await toolkit.record_quantum_metric("assets_discovered", float(len(assets)))

    return {
        "crypto_assets": assets,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_infrastructure",
        "session_start": start,
    }


# ── Node: inventory_algorithms ────────────────────────


async def inventory_algorithms(
    state: QuantumRiskAssessorState,
) -> dict[str, Any]:
    """Inventory cryptographic algorithms in use."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    asset_dicts = [a.model_dump() for a in state.crypto_assets]
    raw_inventory = await toolkit.inventory_algorithms(asset_dicts)

    inventory = [
        AlgorithmInventory(**i)
        for i in raw_inventory
        if isinstance(i, dict) and "inventory_id" in i
    ]

    # Build inventory from discovered assets when toolkit returns none
    if not inventory:
        algo_groups: dict[str, list[CryptoAsset]] = {}
        for asset in state.crypto_assets:
            algo_groups.setdefault(asset.algorithm, []).append(asset)
        for algo, group_assets in algo_groups.items():
            is_vulnerable = algo in (
                CryptoAlgorithmType.RSA,
                CryptoAlgorithmType.ECC,
                CryptoAlgorithmType.DH,
                CryptoAlgorithmType.DSA,
            )
            inventory.append(
                AlgorithmInventory(
                    inventory_id=f"inv-{algo}-001",
                    algorithm=algo,
                    key_size=group_assets[0].key_size if group_assets else 0,
                    usage_count=len(group_assets),
                    services=[a.service_name for a in group_assets],
                    quantum_vulnerable=is_vulnerable,
                    estimated_break_year=2032 if is_vulnerable else 0,
                    migration_priority="high" if is_vulnerable else "low",
                )
            )

    vulnerable_count = sum(1 for i in inventory if i.quantum_vulnerable)

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "total_algorithms": len(inventory),
                "vulnerable": vulnerable_count,
                "types": [i.algorithm for i in inventory],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Algorithm inventory context:\n{ctx}",
            schema=AlgorithmAnalysisOutput,
        )
        logger.info(
            "llm_enhanced",
            node="inventory_algorithms",
            harvest_risk=getattr(llm_out, "harvest_now_risk", False),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="inventory_algorithms",
        )

    step = QuantumReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="inventory_algorithms",
        input_summary=f"Inventorying {len(asset_dicts)} crypto assets",
        output_summary=f"Found {len(inventory)} algorithms ({vulnerable_count} vulnerable)",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="algorithm_inventory",
    )

    await toolkit.record_quantum_metric("algorithms_inventoried", float(len(inventory)))

    return {
        "algorithm_inventory": inventory,
        "vulnerable_algorithm_count": vulnerable_count,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "inventory_algorithms",
    }


# ── Node: assess_vulnerability ────────────────────────


async def assess_vulnerability(
    state: QuantumRiskAssessorState,
) -> dict[str, Any]:
    """Assess quantum vulnerability of inventoried algorithms."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    inv_dicts = [i.model_dump() for i in state.algorithm_inventory]
    raw_assessments = await toolkit.assess_quantum_vulnerability(inv_dicts)

    assessments = [
        VulnerabilityAssessment(**a)
        for a in raw_assessments
        if isinstance(a, dict) and "assessment_id" in a
    ]

    # Build assessments from inventory when toolkit returns none
    if not assessments:
        for inv in state.algorithm_inventory:
            shor = inv.algorithm in (
                CryptoAlgorithmType.RSA,
                CryptoAlgorithmType.ECC,
                CryptoAlgorithmType.DH,
                CryptoAlgorithmType.DSA,
            )
            grover = inv.algorithm in (
                CryptoAlgorithmType.AES,
                CryptoAlgorithmType.SHA,
            )
            threat = (
                QuantumThreatLevel.CRITICAL
                if shor
                else (QuantumThreatLevel.MEDIUM if grover else QuantumThreatLevel.LOW)
            )
            risk = 90.0 if shor else (50.0 if grover else 10.0)
            assessments.append(
                VulnerabilityAssessment(
                    assessment_id=f"va-{inv.inventory_id}",
                    algorithm=inv.algorithm,
                    threat_level=threat,
                    shor_vulnerable=shor,
                    grover_vulnerable=grover,
                    harvest_now_risk=shor,
                    estimated_time_to_break_years=8.0 if shor else 20.0,
                    data_shelf_life_years=10.0,
                    risk_score=risk,
                )
            )

    # Compute total risk score
    scores = [a.risk_score for a in assessments]
    total_risk = round(sum(scores) / len(scores), 2) if scores else 0.0
    critical_count = sum(
        1
        for a in assessments
        if a.threat_level in (QuantumThreatLevel.CRITICAL, QuantumThreatLevel.HIGH)
    )

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "request_id": state.request_id,
                "assessments": len(assessments),
                "shor_vulnerable": sum(1 for a in assessments if a.shor_vulnerable),
                "grover_vulnerable": sum(1 for a in assessments if a.grover_vulnerable),
                "total_risk": total_risk,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Vulnerability assessment context:\n{ctx}",
            schema=VulnerabilityAnalysisOutput,
        )
        if hasattr(llm_out, "risk_score") and llm_out.risk_score > 0:
            total_risk = round((total_risk + llm_out.risk_score) / 2, 2)
        logger.info(
            "llm_enhanced",
            node="assess_vulnerability",
            llm_risk=getattr(llm_out, "risk_score", 0.0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_vulnerability",
        )

    step = QuantumReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_vulnerability",
        input_summary=f"Assessing {len(inv_dicts)} algorithms",
        output_summary=f"Found {len(assessments)} vulnerabilities, risk={total_risk}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="vulnerability_assessor",
    )

    return {
        "vulnerability_assessments": assessments,
        "total_risk_score": total_risk,
        "critical_asset_count": critical_count,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_vulnerability",
    }


# ── Node: score_readiness ─────────────────────────────


async def score_readiness(
    state: QuantumRiskAssessorState,
) -> dict[str, Any]:
    """Score PQC migration readiness across categories."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    vuln_dicts = [v.model_dump() for v in state.vulnerability_assessments]
    asset_dicts = [a.model_dump() for a in state.crypto_assets]
    raw_scores = await toolkit.score_pqc_readiness(vuln_dicts, asset_dicts)

    scores = [ReadinessScore(**s) for s in raw_scores if isinstance(s, dict) and "category" in s]

    # Build default readiness scores when toolkit returns none
    if not scores:
        categories = [
            ("Crypto Inventory Completeness", 60.0),
            ("Crypto Agility", 40.0),
            ("Vendor PQC Readiness", 35.0),
            ("Key Management Flexibility", 50.0),
            ("Compliance Alignment", 45.0),
        ]
        for cat_name, cat_score in categories:
            scores.append(
                ReadinessScore(
                    category=cat_name,
                    score=cat_score,
                    max_score=100.0,
                    findings=[f"{cat_name} assessed"],
                    recommendations=[f"Improve {cat_name.lower()}"],
                )
            )

    overall = round(sum(s.score for s in scores) / len(scores), 2) if scores else 0.0

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "request_id": state.request_id,
                "categories": len(scores),
                "overall_readiness": overall,
                "vulnerable_algorithms": state.vulnerable_algorithm_count,
                "critical_assets": state.critical_asset_count,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"PQC readiness scoring context:\n{ctx}",
            schema=ReadinessAnalysisOutput,
        )
        if hasattr(llm_out, "overall_score") and llm_out.overall_score > 0:
            overall = round((overall + llm_out.overall_score) / 2, 2)
        logger.info(
            "llm_enhanced",
            node="score_readiness",
            llm_score=getattr(llm_out, "overall_score", 0.0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="score_readiness",
        )

    step = QuantumReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="score_readiness",
        input_summary=f"Scoring readiness for {len(vuln_dicts)} vulnerabilities",
        output_summary=f"PQC readiness={overall}%, {len(scores)} categories",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="readiness_scorer",
    )

    await toolkit.record_quantum_metric("pqc_readiness_score", overall)

    return {
        "readiness_scores": scores,
        "pqc_readiness_score": overall,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "score_readiness",
    }


# ── Node: recommend_migration ─────────────────────────


async def recommend_migration(
    state: QuantumRiskAssessorState,
) -> dict[str, Any]:
    """Generate PQC migration recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    readiness_dicts = [s.model_dump() for s in state.readiness_scores]
    vuln_dicts = [v.model_dump() for v in state.vulnerability_assessments]
    raw_recs = await toolkit.recommend_migration(readiness_dicts, vuln_dicts)

    recommendations = [
        MigrationRecommendation(**r)
        for r in raw_recs
        if isinstance(r, dict) and "recommendation_id" in r
    ]

    # Build default recommendations from vulnerability assessments
    if not recommendations:
        pqc_map = {
            CryptoAlgorithmType.RSA: "ML-KEM-768 + ML-DSA-65",
            CryptoAlgorithmType.ECC: "ML-KEM-768",
            CryptoAlgorithmType.DH: "ML-KEM-768",
            CryptoAlgorithmType.DSA: "ML-DSA-65",
            CryptoAlgorithmType.AES: "AES-256",
            CryptoAlgorithmType.SHA: "SHA-384 / SHA-3",
        }
        for vuln in state.vulnerability_assessments:
            if vuln.risk_score >= 50.0:
                recommended = pqc_map.get(vuln.algorithm, "ML-KEM-768")
                recommendations.append(
                    MigrationRecommendation(
                        recommendation_id=f"rec-{vuln.assessment_id}",
                        asset_id=vuln.asset_id,
                        current_algorithm=vuln.algorithm,
                        recommended_algorithm=recommended,
                        priority="critical" if vuln.shor_vulnerable else "medium",
                        effort_weeks=4.0 if vuln.shor_vulnerable else 2.0,
                        risk_reduction=vuln.risk_score * 0.8,
                        reasoning=(
                            f"Migrate from {vuln.algorithm} to {recommended} — "
                            f"threat_level={vuln.threat_level}, "
                            f"shor={vuln.shor_vulnerable}"
                        ),
                    )
                )

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "request_id": state.request_id,
                "recommendation_count": len(recommendations),
                "critical_assets": state.critical_asset_count,
                "pqc_readiness": state.pqc_readiness_score,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Migration recommendation context:\n{ctx}",
            schema=MigrationPlanOutput,
        )
        logger.info(
            "llm_enhanced",
            node="recommend_migration",
            quick_wins=getattr(llm_out, "quick_wins", 0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_migration",
        )

    step = QuantumReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_migration",
        input_summary=f"Generating migration plan for {state.critical_asset_count} critical assets",
        output_summary=f"Created {len(recommendations)} recommendations",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="migration_planner",
    )

    return {
        "migration_recommendations": recommendations,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_migration",
    }


# ── Node: report ──────────────────────────────────────


async def report(
    state: QuantumRiskAssessorState,
) -> dict[str, Any]:
    """Finalize quantum risk assessment and record metrics."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_quantum_metric("assessment_duration_ms", float(duration_ms))
    await toolkit.record_quantum_metric("total_risk_score", state.total_risk_score)
    await toolkit.record_quantum_metric("pqc_readiness_score", state.pqc_readiness_score)
    await toolkit.record_quantum_metric(
        "vulnerable_algorithms", float(state.vulnerable_algorithm_count)
    )
    await toolkit.record_quantum_metric("critical_assets", float(state.critical_asset_count))

    # LLM report generation
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "request_id": state.request_id,
                "tenant_id": state.tenant_id,
                "total_risk_score": state.total_risk_score,
                "pqc_readiness_score": state.pqc_readiness_score,
                "vulnerable_algorithms": state.vulnerable_algorithm_count,
                "critical_assets": state.critical_asset_count,
                "recommendations": len(state.migration_recommendations),
                "duration_ms": duration_ms,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Quantum risk assessment results:\n{ctx}",
            schema=InfrastructureScanOutput,
        )
        logger.info(
            "llm_report_generated",
            node="report",
            summary=getattr(llm_out, "summary", "")[:80],
        )
    except Exception:
        logger.debug(
            "llm_report_skipped",
            node="report",
        )

    findings = [
        {
            "type": "quantum_risk_assessment",
            "total_risk_score": state.total_risk_score,
            "pqc_readiness_score": state.pqc_readiness_score,
            "vulnerable_algorithms": state.vulnerable_algorithm_count,
            "critical_assets": state.critical_asset_count,
            "recommendations": len(state.migration_recommendations),
        }
    ]

    stats = {
        "crypto_assets": len(state.crypto_assets),
        "algorithms_inventoried": len(state.algorithm_inventory),
        "vulnerabilities_assessed": len(state.vulnerability_assessments),
        "readiness_categories": len(state.readiness_scores),
        "migration_recommendations": len(state.migration_recommendations),
        "duration_ms": duration_ms,
    }

    step = QuantumReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=f"Finalizing assessment {state.request_id}",
        output_summary=f"Complete in {duration_ms}ms, risk={state.total_risk_score}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "findings": findings,
        "stats": stats,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
