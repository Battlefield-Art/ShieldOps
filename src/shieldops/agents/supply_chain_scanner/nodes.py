"""Supply Chain Scanner Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import AIAsset, AssetType, ScanStage
from .tools import SupplyChainScannerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def inventory_ai_assets(
    state: dict[str, Any],
    toolkit: SupplyChainScannerToolkit,
) -> dict[str, Any]:
    """Discover all AI components in the tenant."""
    logger.info("supply_chain_scanner.node.inventory")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    session_start = time.time()

    assets = await toolkit.inventory_ai_assets(tenant_id=tenant_id)
    asset_dicts = [a.model_dump() for a in assets]

    type_counts: dict[str, int] = {}
    for a in assets:
        t = a.asset_type.value
        type_counts[t] = type_counts.get(t, 0) + 1

    summary_parts = [f"{c} {t}" for t, c in type_counts.items()]
    summary = ", ".join(summary_parts)

    return {
        "ai_assets": asset_dicts,
        "stage": ScanStage.SCAN_MODEL_REGISTRIES.value,
        "session_start": session_start,
        "current_step": "inventory_ai_assets",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Inventoried {len(assets)} AI assets: {summary}"],
    }


async def scan_model_registries(
    state: dict[str, Any],
    toolkit: SupplyChainScannerToolkit,
) -> dict[str, Any]:
    """Scan model registries for tampering."""
    logger.info("supply_chain_scanner.node.scan_registries")
    state = _to_dict(state)

    raw_assets = state.get("ai_assets", [])
    models = [AIAsset(**a) for a in raw_assets if a.get("asset_type") == AssetType.MODEL_WEIGHT]

    findings = await toolkit.scan_model_registry(models)
    finding_dicts = [f.model_dump() for f in findings]

    threats = sum(1 for f in findings if f.threat_type is not None)
    note = f"Scanned {len(models)} models: {threats} threats found"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_REGISTRY_ANALYSIS,
            RegistryAnalysisResult,
        )

        ctx = json.dumps(
            {
                "model_count": len(models),
                "threat_count": threats,
                "findings": finding_dicts[:10],
            },
            default=str,
        )
        llm_result = cast(
            RegistryAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_REGISTRY_ANALYSIS,
                user_prompt=(f"Registry scan results:\n{ctx}"),
                schema=RegistryAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="supply_chain_scanner",
            node="scan_model_registries",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="supply_chain_scanner",
            node="scan_model_registries",
        )

    return {
        "registry_findings": finding_dicts,
        "stage": ScanStage.SCAN_RAG_SOURCES.value,
        "current_step": "scan_model_registries",
        "reasoning_chain": state.get("reasoning_chain", []) + [note],
    }


async def scan_rag_sources(
    state: dict[str, Any],
    toolkit: SupplyChainScannerToolkit,
) -> dict[str, Any]:
    """Scan RAG data sources for poisoning."""
    logger.info("supply_chain_scanner.node.scan_rag")
    state = _to_dict(state)

    raw_assets = state.get("ai_assets", [])
    sources = [AIAsset(**a) for a in raw_assets if a.get("asset_type") == AssetType.RAG_DOCUMENT]

    findings = await toolkit.scan_rag_sources(sources)
    finding_dicts = [f.model_dump() for f in findings]

    poisoned = sum(f.poisoned_count for f in findings)
    adversarial = sum(f.adversarial_embeddings for f in findings)
    note = (
        f"Scanned {len(sources)} RAG sources: "
        f"{poisoned} poisoned docs, "
        f"{adversarial} adversarial embeddings"
    )

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_RAG_POISONING,
            RAGPoisoningResult,
        )

        ctx = json.dumps(
            {
                "source_count": len(sources),
                "poisoned_total": poisoned,
                "adversarial_total": adversarial,
                "findings": finding_dicts[:10],
            },
            default=str,
        )
        llm_result = cast(
            RAGPoisoningResult,
            await llm_structured(
                system_prompt=SYSTEM_RAG_POISONING,
                user_prompt=(f"RAG scan results:\n{ctx}"),
                schema=RAGPoisoningResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="supply_chain_scanner",
            node="scan_rag_sources",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="supply_chain_scanner",
            node="scan_rag_sources",
        )

    return {
        "rag_findings": finding_dicts,
        "stage": ScanStage.SCAN_PROMPT_TEMPLATES.value,
        "current_step": "scan_rag_sources",
        "reasoning_chain": state.get("reasoning_chain", []) + [note],
    }


async def scan_prompt_templates(
    state: dict[str, Any],
    toolkit: SupplyChainScannerToolkit,
) -> dict[str, Any]:
    """Audit prompt templates for injection vulns."""
    logger.info("supply_chain_scanner.node.scan_templates")
    state = _to_dict(state)

    raw_assets = state.get("ai_assets", [])
    templates = [
        AIAsset(**a) for a in raw_assets if a.get("asset_type") == AssetType.PROMPT_TEMPLATE
    ]

    findings = await toolkit.audit_prompt_templates(templates)
    finding_dicts = [f.model_dump() for f in findings]

    vulnerable = sum(1 for f in findings if f.injection_vulnerable)
    note = f"Audited {len(templates)} templates: {vulnerable} injection-vulnerable"

    return {
        "template_findings": finding_dicts,
        "stage": ScanStage.SCAN_TOOL_DEFINITIONS.value,
        "current_step": "scan_prompt_templates",
        "reasoning_chain": state.get("reasoning_chain", []) + [note],
    }


async def scan_tool_definitions(
    state: dict[str, Any],
    toolkit: SupplyChainScannerToolkit,
) -> dict[str, Any]:
    """Audit tool definitions for hijacking."""
    logger.info("supply_chain_scanner.node.scan_tools")
    state = _to_dict(state)

    raw_assets = state.get("ai_assets", [])
    tools = [AIAsset(**a) for a in raw_assets if a.get("asset_type") == AssetType.TOOL_DEFINITION]

    findings = await toolkit.audit_tool_definitions(tools)
    finding_dicts = [f.model_dump() for f in findings]

    hijacked = sum(1 for f in findings if f.hijack_risk)
    exfil = sum(1 for f in findings if f.exfiltration_capable)
    note = f"Audited {len(tools)} tools: {hijacked} hijack risks, {exfil} exfiltration-capable"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_TOOL_HIJACK,
            ToolHijackResult,
        )

        ctx = json.dumps(
            {
                "tool_count": len(tools),
                "hijacked": hijacked,
                "exfiltration": exfil,
                "findings": finding_dicts[:10],
            },
            default=str,
        )
        llm_result = cast(
            ToolHijackResult,
            await llm_structured(
                system_prompt=SYSTEM_TOOL_HIJACK,
                user_prompt=(f"Tool audit results:\n{ctx}"),
                schema=ToolHijackResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="supply_chain_scanner",
            node="scan_tool_definitions",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="supply_chain_scanner",
            node="scan_tool_definitions",
        )

    return {
        "tool_findings": finding_dicts,
        "stage": ScanStage.REPORT.value,
        "current_step": "scan_tool_definitions",
        "reasoning_chain": state.get("reasoning_chain", []) + [note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: SupplyChainScannerToolkit,
) -> dict[str, Any]:
    """Generate final supply chain scan report."""
    logger.info("supply_chain_scanner.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    reg = state.get("registry_findings", [])
    rag = state.get("rag_findings", [])
    tmpl = state.get("template_findings", [])
    tool = state.get("tool_findings", [])
    assets = state.get("ai_assets", [])

    # Count threats across all scan types
    reg_threats = sum(1 for r in reg if r.get("threat_type") is not None)
    rag_threats = sum(1 for r in rag if r.get("threat_type") is not None)
    tmpl_threats = sum(1 for t in tmpl if t.get("threat_type") is not None)
    tool_threats = sum(1 for t in tool if t.get("threat_type") is not None)
    total_threats = reg_threats + rag_threats + tmpl_threats + tool_threats

    # Severity weights
    sev_w = {
        "critical": 1.0,
        "high": 0.7,
        "medium": 0.4,
        "low": 0.1,
    }

    # Compute per-category scores
    def _score(items: list[dict[str, Any]]) -> float:
        if not items:
            return 0.0
        total = sum(
            sev_w.get(i.get("severity", "low"), 0.1)
            for i in items
            if i.get("threat_type") is not None
        )
        return min(total / max(len(items), 1), 1.0)

    reg_score = _score(reg)
    rag_score = _score(rag)
    tmpl_score = _score(tmpl)
    tool_score = _score(tool)

    # Weighted composite: registry 30%, RAG 30%,
    # templates 20%, tools 20%
    supply_chain_score = round(
        1.0 - (reg_score * 0.30 + rag_score * 0.30 + tmpl_score * 0.20 + tool_score * 0.20),
        4,
    )

    stats = {
        "total_assets": len(assets),
        "total_threats": total_threats,
        "registry_threats": reg_threats,
        "rag_threats": rag_threats,
        "template_threats": tmpl_threats,
        "tool_threats": tool_threats,
        "registry_subscore": round(reg_score, 4),
        "rag_subscore": round(rag_score, 4),
        "template_subscore": round(tmpl_score, 4),
        "tool_subscore": round(tool_score, 4),
    }

    note = f"Report: {len(assets)} assets, {total_threats} threats, score={supply_chain_score}"

    # LLM enhancement
    try:
        from .prompts import (
            SYSTEM_SCAN_ASSESSMENT,
            SupplyChainScanResult,
        )

        ctx = json.dumps(
            {
                "stats": stats,
                "registry_findings": reg[:5],
                "rag_findings": rag[:5],
                "template_findings": tmpl[:5],
                "tool_findings": tool[:5],
            },
            default=str,
        )
        llm_result = cast(
            SupplyChainScanResult,
            await llm_structured(
                system_prompt=SYSTEM_SCAN_ASSESSMENT,
                user_prompt=(f"Supply chain scan data:\n{ctx}"),
                schema=SupplyChainScanResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="supply_chain_scanner",
            node="generate_report",
        )
        note = f"{llm_result.summary} {note}"
        if llm_result.risk_score > 0:
            supply_chain_score = round(
                (supply_chain_score + (1.0 - llm_result.risk_score)) / 2,
                4,
            )
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="supply_chain_scanner",
            node="generate_report",
        )

    return {
        "total_threats": total_threats,
        "supply_chain_score": supply_chain_score,
        "stats": stats,
        "current_step": "report",
        "stage": ScanStage.REPORT.value,
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + [note],
    }
