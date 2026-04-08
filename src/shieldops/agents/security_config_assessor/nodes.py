"""Security Config Assessor Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BenchmarkResult,
    ConfigScan,
    SCAStage,
    SystemInventory,
)
from .tools import SecurityConfigAssessorToolkit

logger = structlog.get_logger()

# Module-level toolkit reference
_toolkit: SecurityConfigAssessorToolkit | None = None


def _get_toolkit() -> SecurityConfigAssessorToolkit:
    """Get the module-level toolkit, creating default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = SecurityConfigAssessorToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: inventory_systems
# ------------------------------------------------------------------
async def inventory_systems(
    state: dict[str, Any],
    toolkit: SecurityConfigAssessorToolkit,
) -> dict[str, Any]:
    """Enumerate target systems for assessment."""
    logger.info("sca.node.inventory_systems")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    benchmarks = state.get("benchmarks", ["cis_aws"])

    systems = await toolkit.inventory_systems(
        tenant_id,
        benchmarks,
    )
    systems_data = [s.model_dump() for s in systems]

    reasoning = f"Inventoried {len(systems)} systems across {', '.join(benchmarks)}"

    try:
        from .prompts import (
            SYSTEM_INVENTORY_ANALYSIS,
            InventoryAnalysisOutput,
        )

        ctx = json.dumps(
            {
                "total_systems": len(systems),
                "benchmarks": benchmarks,
                "platforms": list({s.platform for s in systems}),
                "reachable": sum(1 for s in systems if s.reachable),
            },
            default=str,
        )
        llm_result = cast(
            InventoryAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_INVENTORY_ANALYSIS,
                user_prompt=(f"Inventory context:\n{ctx}"),
                schema=InventoryAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sca",
            node="inventory_systems",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sca",
            node="inventory_systems",
        )

    return {
        "stage": SCAStage.SCAN_CONFIGS.value,
        "systems": systems_data,
        "current_step": "inventory_systems",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ------------------------------------------------------------------
# Node 2: scan_configs
# ------------------------------------------------------------------
async def scan_configs(
    state: dict[str, Any],
    toolkit: SecurityConfigAssessorToolkit,
) -> dict[str, Any]:
    """Collect configuration items from target systems."""
    logger.info("sca.node.scan_configs")
    state = _to_dict(state)

    raw_systems = state.get("systems", [])
    systems = [SystemInventory(**s) for s in raw_systems]

    scans = await toolkit.scan_configs(systems)
    scans_data = [s.model_dump() for s in scans]

    compliant = sum(1 for s in scans if s.compliant)
    non_compliant = len(scans) - compliant

    return {
        "stage": SCAStage.BENCHMARK_CHECK.value,
        "config_scans": scans_data,
        "current_step": "scan_configs",
        "reasoning_chain": (
            state.get("reasoning_chain", [])
            + [
                f"Scanned {len(scans)} configs:"
                f" {compliant} compliant,"
                f" {non_compliant} non-compliant"
            ]
        ),
    }


# ------------------------------------------------------------------
# Node 3: benchmark_check
# ------------------------------------------------------------------
async def benchmark_check(
    state: dict[str, Any],
    toolkit: SecurityConfigAssessorToolkit,
) -> dict[str, Any]:
    """Evaluate CIS controls against collected configs."""
    logger.info("sca.node.benchmark_check")
    state = _to_dict(state)

    raw_systems = state.get("systems", [])
    systems = [SystemInventory(**s) for s in raw_systems]
    raw_scans = state.get("config_scans", [])
    scans = [ConfigScan(**s) for s in raw_scans]
    level = state.get("compliance_level", "level_1")

    results = await toolkit.benchmark_check(
        systems,
        scans,
        level,
    )
    results_data = [r.model_dump() for r in results]

    pass_ct = sum(1 for r in results if r.status == "pass")
    fail_ct = sum(1 for r in results if r.status == "fail")
    warn_ct = sum(1 for r in results if r.status == "warn")

    reasoning = f"Checked {len(results)} controls: {pass_ct} pass, {fail_ct} fail, {warn_ct} warn"

    try:
        from .prompts import (
            SYSTEM_BENCHMARK_ANALYSIS,
            BenchmarkAnalysisOutput,
        )

        ctx = json.dumps(
            {
                "total": len(results),
                "pass": pass_ct,
                "fail": fail_ct,
                "warn": warn_ct,
                "level": level,
                "failing": [
                    {
                        "id": r.control_id,
                        "name": r.control_name,
                        "severity": r.severity,
                    }
                    for r in results
                    if r.status == "fail"
                ][:20],
            },
            default=str,
        )
        llm_result = cast(
            BenchmarkAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_BENCHMARK_ANALYSIS,
                user_prompt=(f"Benchmark context:\n{ctx}"),
                schema=BenchmarkAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sca",
            node="benchmark_check",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sca",
            node="benchmark_check",
        )

    return {
        "stage": SCAStage.DETECT_DRIFT.value,
        "benchmark_results": results_data,
        "current_step": "benchmark_check",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ------------------------------------------------------------------
# Node 4: detect_drift
# ------------------------------------------------------------------
async def detect_drift(
    state: dict[str, Any],
    toolkit: SecurityConfigAssessorToolkit,
) -> dict[str, Any]:
    """Detect configuration drift from hardening baseline."""
    logger.info("sca.node.detect_drift")
    state = _to_dict(state)

    raw_scans = state.get("config_scans", [])
    scans = [ConfigScan(**s) for s in raw_scans]
    raw_results = state.get("benchmark_results", [])
    results = [BenchmarkResult(**r) for r in raw_results]

    drifts = await toolkit.detect_drift(scans, results)
    drifts_data = [d.model_dump() for d in drifts]

    critical = sum(1 for d in drifts if d.drift_severity == "critical")
    high = sum(1 for d in drifts if d.drift_severity == "high")

    reasoning = f"Detected {len(drifts)} drifts: {critical} critical, {high} high"

    try:
        from .prompts import (
            SYSTEM_DRIFT_ANALYSIS,
            DriftAnalysisOutput,
        )

        ctx = json.dumps(
            {
                "total_drifts": len(drifts),
                "critical": critical,
                "high": high,
                "top_drifts": [
                    {
                        "control": d.control_id,
                        "path": d.config_path,
                        "severity": d.drift_severity,
                    }
                    for d in drifts[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DriftAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_DRIFT_ANALYSIS,
                user_prompt=f"Drift context:\n{ctx}",
                schema=DriftAnalysisOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sca",
            node="detect_drift",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sca",
            node="detect_drift",
        )

    return {
        "stage": SCAStage.GENERATE_FIXES.value,
        "drifts": drifts_data,
        "current_step": "detect_drift",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ------------------------------------------------------------------
# Node 5: generate_fixes
# ------------------------------------------------------------------
async def generate_fixes(
    state: dict[str, Any],
    toolkit: SecurityConfigAssessorToolkit,
) -> dict[str, Any]:
    """Generate remediation scripts for failing controls."""
    logger.info("sca.node.generate_fixes")
    state = _to_dict(state)

    raw_results = state.get("benchmark_results", [])
    results = [BenchmarkResult(**r) for r in raw_results]
    raw_drifts = state.get("drifts", [])
    from .models import ConfigDrift

    drifts = [ConfigDrift(**d) for d in raw_drifts]

    scripts = await toolkit.generate_fixes(results, drifts)
    scripts_data = [s.model_dump() for s in scripts]

    reversible = sum(1 for s in scripts if s.reversible)

    reasoning = f"Generated {len(scripts)} remediation scripts, {reversible} reversible"

    try:
        from .prompts import (
            SYSTEM_REMEDIATION_PLANNING,
            RemediationPlanOutput,
        )

        ctx = json.dumps(
            {
                "total_scripts": len(scripts),
                "reversible": reversible,
                "manual": len(scripts) - reversible,
                "by_risk": {
                    "critical": sum(1 for s in scripts if s.risk_level == "critical"),
                    "high": sum(1 for s in scripts if s.risk_level == "high"),
                    "medium": sum(1 for s in scripts if s.risk_level == "medium"),
                },
            },
            default=str,
        )
        llm_result = cast(
            RemediationPlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_REMEDIATION_PLANNING,
                user_prompt=(f"Remediation context:\n{ctx}"),
                schema=RemediationPlanOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sca",
            node="generate_fixes",
        )
        reasoning = f"{llm_result.summary} {reasoning}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sca",
            node="generate_fixes",
        )

    return {
        "stage": SCAStage.REPORT.value,
        "remediation_scripts": scripts_data,
        "current_step": "generate_fixes",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ------------------------------------------------------------------
# Node 6: generate_report
# ------------------------------------------------------------------
async def generate_report(
    state: dict[str, Any],
    toolkit: SecurityConfigAssessorToolkit,
) -> dict[str, Any]:
    """Produce the final assessment report with stats."""
    logger.info("sca.node.generate_report")
    state = _to_dict(state)

    raw_results = state.get("benchmark_results", [])
    raw_drifts = state.get("drifts", [])
    raw_scripts = state.get("remediation_scripts", [])
    raw_systems = state.get("systems", [])

    total = len(raw_results) if raw_results else 1
    passing = sum(1 for r in raw_results if r.get("status") == "pass")
    failing = sum(1 for r in raw_results if r.get("status") == "fail")
    compliance_score = round(
        (passing / total) * 100.0,
        1,
    )

    severity_dist: dict[str, int] = {}
    for d in raw_drifts:
        sev = d.get("drift_severity", "medium")
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "systems_assessed": len(raw_systems),
        "controls_evaluated": total,
        "controls_passing": passing,
        "controls_failing": failing,
        "compliance_score": compliance_score,
        "drifts_detected": len(raw_drifts),
        "severity_distribution": severity_dist,
        "scripts_generated": len(raw_scripts),
        "benchmarks": state.get("benchmarks", []),
    }

    report_summary = (
        f"Compliance score: {compliance_score}/100."
        f" {len(raw_systems)} systems,"
        f" {total} controls,"
        f" {len(raw_drifts)} drifts,"
        f" {len(raw_scripts)} scripts generated."
    )

    return {
        "stage": SCAStage.REPORT.value,
        "stats": stats,
        "compliance_score": compliance_score,
        "session_duration_ms": elapsed,
        "current_step": "generate_report",
        "reasoning_chain": (state.get("reasoning_chain", []) + [report_summary]),
    }
