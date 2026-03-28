"""Asset Inventory Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    ClassifiedAsset,
    Criticality,
    DiscoveredAsset,
    InventoryStage,
)
from .prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_OWNERSHIP,
    SYSTEM_REPORT,
    ClassificationResult,
    InventoryReportResult,
    OwnershipResult,
)
from .tools import AssetInventoryToolkit

logger = structlog.get_logger()


async def discover(
    state: dict[str, Any],
    toolkit: AssetInventoryToolkit,
) -> dict[str, Any]:
    """Discover assets across infrastructure."""
    logger.info("asset_inventory.node.discover")

    tenant_id = state.get("tenant_id", "")
    assets = await toolkit.discover_assets(tenant_id)
    assets_data = [a.model_dump(mode="json") for a in assets]

    unmanaged = sum(1 for a in assets if not a.is_managed)
    return {
        "stage": InventoryStage.CLASSIFY.value,
        "discovered_assets": assets_data,
        "total_assets": len(assets),
        "unmanaged_count": unmanaged,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(assets)} assets ({unmanaged} unmanaged)"],
    }


async def classify(
    state: dict[str, Any],
    toolkit: AssetInventoryToolkit,
) -> dict[str, Any]:
    """Classify discovered assets."""
    logger.info("asset_inventory.node.classify")

    raw_assets = state.get("discovered_assets", [])
    assets = [DiscoveredAsset(**a) for a in raw_assets]

    classifications_data: list[dict[str, Any]] = []
    critical = 0
    for asset in assets:
        c = await toolkit.classify_asset(asset)
        classifications_data.append(c.model_dump())
        if c.criticality == Criticality.CRITICAL:
            critical += 1

    reasoning_note = f"Classified {len(classifications_data)} assets, {critical} critical"

    if classifications_data:
        try:
            context = json.dumps(
                {
                    "total": len(classifications_data),
                    "classifications": [
                        {
                            "id": c["asset_id"],
                            "type": c["asset_type"],
                            "criticality": c["criticality"],
                        }
                        for c in classifications_data[:15]
                    ],
                },
                default=str,
            )
            result = cast(
                ClassificationResult,
                await llm_structured(
                    system_prompt=SYSTEM_CLASSIFY,
                    user_prompt=(f"Classification context:\n{context}"),
                    schema=ClassificationResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug(
                "llm_fallback",
                agent="asset_inventory",
                node="classify",
            )

    return {
        "stage": InventoryStage.ASSIGN_OWNERS.value,
        "classifications": classifications_data,
        "critical_count": critical,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assign_owners(
    state: dict[str, Any],
    toolkit: AssetInventoryToolkit,
) -> dict[str, Any]:
    """Assign owners to discovered assets."""
    logger.info("asset_inventory.node.assign_owners")

    raw_assets = state.get("discovered_assets", [])
    assets = [DiscoveredAsset(**a) for a in raw_assets]

    assignments_data: list[dict[str, Any]] = []
    for asset in assets:
        assignment = await toolkit.assign_owner(asset)
        assignments_data.append(assignment.model_dump())

    reasoning_note = f"Assigned owners to {len(assignments_data)} assets"

    if assignments_data:
        try:
            context = json.dumps(
                {
                    "total": len(assignments_data),
                    "assignments": [
                        {
                            "id": a["asset_id"],
                            "team": a["owner_team"],
                            "confidence": a["confidence"],
                        }
                        for a in assignments_data[:15]
                    ],
                },
                default=str,
            )
            result = cast(
                OwnershipResult,
                await llm_structured(
                    system_prompt=SYSTEM_OWNERSHIP,
                    user_prompt=(f"Ownership context:\n{context}"),
                    schema=OwnershipResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug(
                "llm_fallback",
                agent="asset_inventory",
                node="assign_owners",
            )

    return {
        "stage": InventoryStage.ASSESS_RISK.value,
        "owner_assignments": assignments_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: AssetInventoryToolkit,
) -> dict[str, Any]:
    """Assess risk for classified assets."""
    logger.info("asset_inventory.node.assess_risk")

    raw_assets = state.get("discovered_assets", [])
    raw_classifications = state.get("classifications", [])
    assets = [DiscoveredAsset(**a) for a in raw_assets]
    classifications = [ClassifiedAsset(**c) for c in raw_classifications]

    class_map = {c.asset_id: c for c in classifications}
    assessments_data: list[dict[str, Any]] = []

    for asset in assets:
        classification = class_map.get(asset.id)
        if classification:
            assessment = await toolkit.assess_risk(asset, classification)
            assessments_data.append(assessment.model_dump())

    return {
        "stage": InventoryStage.RECONCILE.value,
        "risk_assessments": assessments_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Assessed risk for {len(assessments_data)} assets"],
    }


async def reconcile(
    state: dict[str, Any],
    toolkit: AssetInventoryToolkit,
) -> dict[str, Any]:
    """Reconcile discovered assets against known inventory."""
    logger.info("asset_inventory.node.reconcile")

    raw_assets = state.get("discovered_assets", [])
    assets = [DiscoveredAsset(**a) for a in raw_assets]

    result = await toolkit.reconcile_inventory(assets)

    return {
        "stage": InventoryStage.REPORT.value,
        "reconciliation": result.model_dump(),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Reconciled: {result.new_assets} new, "
            f"{result.unmanaged_assets} unmanaged, "
            f"{result.changed_assets} changed"
        ],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: AssetInventoryToolkit,
) -> dict[str, Any]:
    """Generate asset inventory report."""
    logger.info("asset_inventory.node.report")

    total = state.get("total_assets", 0)
    unmanaged = state.get("unmanaged_count", 0)
    critical = state.get("critical_count", 0)
    summary = f"Inventoried {total} assets: {critical} critical, {unmanaged} unmanaged"

    try:
        context = json.dumps(
            {
                "total_assets": total,
                "unmanaged_count": unmanaged,
                "critical_count": critical,
                "reconciliation": state.get("reconciliation", {}),
                "risk_assessments": state.get("risk_assessments", [])[:10],
            },
            default=str,
        )
        result = cast(
            InventoryReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Asset inventory context:\n{context}"),
                schema=InventoryReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="asset_inventory",
            node="report",
        )

    return {
        "stage": InventoryStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
