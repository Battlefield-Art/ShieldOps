"""Asset Exposure Scorer Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AESStage,
    DiscoveredAsset,
    ExposureScore,
    ReasoningStep,
    VulnerabilityCheck,
)
from .tools import AssetExposureScorerToolkit

logger = structlog.get_logger()

_toolkit: AssetExposureScorerToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: AssetExposureScorerToolkit) -> None:  # noqa: PLW0603
    """Set the module-level toolkit."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> AssetExposureScorerToolkit:
    if _toolkit is None:
        msg = "Toolkit not initialised — call set_toolkit first"
        raise RuntimeError(msg)
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Assets
# ------------------------------------------------------------------


async def discover_assets(
    state: dict[str, Any],
    toolkit: AssetExposureScorerToolkit,
) -> dict[str, Any]:
    """Discover internet-facing assets."""
    logger.info("aes.node.discover_assets")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    assets = await toolkit.discover_assets(tenant_id)
    data = [a.model_dump() for a in assets]

    note = f"Discovered {len(assets)} internet-facing assets"

    return {
        "stage": AESStage.FINGERPRINT_SERVICES.value,
        "assets": data,
        "assets_discovered": len(assets),
        "current_step": "discover_assets",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_assets",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Fingerprint Services
# ------------------------------------------------------------------


async def fingerprint_services(
    state: dict[str, Any],
    toolkit: AssetExposureScorerToolkit,
) -> dict[str, Any]:
    """Fingerprint services on discovered assets."""
    logger.info("aes.node.fingerprint_services")
    state = _to_dict(state)

    assets = [DiscoveredAsset(**a) for a in state.get("assets", [])]
    fingerprints = await toolkit.fingerprint_services(assets)
    data = [f.model_dump() for f in fingerprints]

    note = f"Fingerprinted {len(fingerprints)} services"

    try:
        from .prompts import SYSTEM_ANALYZE, FingerprintInsight

        ctx = json.dumps(
            {
                "fingerprints": [
                    {
                        "service": f.service_name,
                        "version": f.version,
                        "tls": f.tls_version,
                    }
                    for f in fingerprints[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            FingerprintInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Service fingerprints:\n{ctx}",
                schema=FingerprintInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="aes",
            node="fingerprint_services",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="aes",
            node="fingerprint_services",
        )

    return {
        "stage": AESStage.CHECK_VULNS.value,
        "fingerprints": data,
        "current_step": "fingerprint_services",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="fingerprint_services",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Check Vulnerabilities
# ------------------------------------------------------------------


async def check_vulns(
    state: dict[str, Any],
    toolkit: AssetExposureScorerToolkit,
) -> dict[str, Any]:
    """Check for known vulnerabilities on assets."""
    logger.info("aes.node.check_vulns")
    state = _to_dict(state)

    assets = [DiscoveredAsset(**a) for a in state.get("assets", [])]
    vulns = await toolkit.check_vulns(assets)
    data = [v.model_dump() for v in vulns]

    critical = sum(1 for v in vulns if v.severity == "critical")
    note = f"Found {len(vulns)} vulnerabilities, {critical} critical"

    return {
        "stage": AESStage.SCORE_EXPOSURE.value,
        "vulnerabilities": data,
        "current_step": "check_vulns",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="check_vulns",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Score Exposure
# ------------------------------------------------------------------


async def score_exposure(
    state: dict[str, Any],
    toolkit: AssetExposureScorerToolkit,
) -> dict[str, Any]:
    """Compute exposure scores for each asset."""
    logger.info("aes.node.score_exposure")
    state = _to_dict(state)

    assets = [DiscoveredAsset(**a) for a in state.get("assets", [])]
    vulns = [VulnerabilityCheck(**v) for v in state.get("vulnerabilities", [])]
    scores = await toolkit.score_exposure(assets, vulns)
    data = [s.model_dump() for s in scores]

    critical_count = sum(1 for s in scores if s.exposure_level.value == "critical")
    note = f"Scored {len(scores)} assets, {critical_count} critical"

    return {
        "stage": AESStage.TRACK_CHANGES.value,
        "scores": data,
        "critical_exposures": critical_count,
        "current_step": "score_exposure",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="score_exposure",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Track Changes
# ------------------------------------------------------------------


async def track_changes(
    state: dict[str, Any],
    toolkit: AssetExposureScorerToolkit,
) -> dict[str, Any]:
    """Track exposure score changes over time."""
    logger.info("aes.node.track_changes")
    state = _to_dict(state)

    scores = [ExposureScore(**s) for s in state.get("scores", [])]
    changes = await toolkit.track_changes(scores)
    data = [c.model_dump() for c in changes]

    increased = sum(1 for c in changes if c.change_type == "increased")
    note = f"Tracked {len(changes)} changes, {increased} increased"

    return {
        "stage": AESStage.REPORT.value,
        "changes": data,
        "current_step": "track_changes",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="track_changes",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: AssetExposureScorerToolkit,
) -> dict[str, Any]:
    """Compile the final exposure assessment report."""
    logger.info("aes.node.report")
    state = _to_dict(state)

    asset_count = state.get("assets_discovered", 0)
    vuln_count = len(state.get("vulnerabilities", []))
    critical = state.get("critical_exposures", 0)
    change_count = len(state.get("changes", []))

    lines = [
        "# Asset Exposure Assessment Report",
        "",
        f"**Assets discovered:** {asset_count}",
        f"**Vulnerabilities found:** {vuln_count}",
        f"**Critical exposures:** {critical}",
        f"**Score changes tracked:** {change_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "assets": asset_count,
                "vulnerabilities": vuln_count,
                "critical": critical,
                "changes": change_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Exposure assessment:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="aes",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="aes",
            node="report",
        )

    return {
        "stage": AESStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
