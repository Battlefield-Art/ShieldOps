"""Node implementations for the Web App Scanner Agent."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.web_app_scanner.models import (
    ScannerStage,
    VulnCategory,
)
from shieldops.agents.web_app_scanner.prompts import (
    SYSTEM_INJECTION_ANALYSIS,
    SYSTEM_WEB_REPORT,
    InjectionAnalysisOutput,
    WebScanReportOutput,
)
from shieldops.agents.web_app_scanner.tools import (
    WebAppScannerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()


async def discover_endpoints(
    state: dict[str, Any],
    toolkit: WebAppScannerToolkit,
) -> dict[str, Any]:
    """Discover web endpoints on the target."""
    target_url = state.get("target_url", "")
    auth_config = state.get("auth_config", {})

    endpoints = await toolkit.discover_endpoints(target_url, auth_config)
    logger.info(
        "web_scanner.endpoints_discovered",
        count=len(endpoints),
    )
    return {
        "endpoints_discovered": endpoints,
        "stage": ScannerStage.crawl_application,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Discovered {len(endpoints)} endpoints on {target_url}",
        ],
    }


async def crawl_application(
    state: dict[str, Any],
    toolkit: WebAppScannerToolkit,
) -> dict[str, Any]:
    """Crawl the application for pages and forms."""
    endpoints = state.get("endpoints_discovered", [])
    depth = state.get("scan_depth", 3)

    pages = await toolkit.crawl_application(endpoints, depth)
    logger.info(
        "web_scanner.pages_crawled",
        count=len(pages),
    )
    return {
        "pages_crawled": pages,
        "stage": ScannerStage.test_injection,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Crawled {len(pages)} pages at depth {depth}",
        ],
    }


async def test_injection(
    state: dict[str, Any],
    toolkit: WebAppScannerToolkit,
) -> dict[str, Any]:
    """Test for injection vulnerabilities."""
    endpoints = state.get("endpoints_discovered", [])
    findings = await toolkit.test_injection(endpoints)

    # LLM-enhanced injection analysis
    for finding in findings:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_INJECTION_ANALYSIS,
                user_prompt=(
                    f"Endpoint: {finding.get('endpoint')}, "
                    f"Param: {finding.get('parameter')}, "
                    f"Payload: {finding.get('payload')}, "
                    f"Evidence: {finding.get('evidence')}"
                ),
                schema=InjectionAnalysisOutput,
            )
            if hasattr(result, "remediation"):
                finding["remediation"] = getattr(result, "remediation", "")
            logger.info(
                "llm_enhanced",
                node="test_injection",
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="test_injection",
            )

    logger.info(
        "web_scanner.injection_tested",
        findings=len(findings),
    )
    return {
        "injection_findings": findings,
        "stage": ScannerStage.test_authentication,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Found {len(findings)} injection findings",
        ],
    }


async def test_authentication(
    state: dict[str, Any],
    toolkit: WebAppScannerToolkit,
) -> dict[str, Any]:
    """Test authentication mechanisms."""
    endpoints = state.get("endpoints_discovered", [])
    auth_config = state.get("auth_config", {})

    findings = await toolkit.test_authentication(endpoints, auth_config)
    logger.info(
        "web_scanner.auth_tested",
        findings=len(findings),
    )
    return {
        "auth_findings": findings,
        "stage": ScannerStage.test_access_control,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Found {len(findings)} auth findings",
        ],
    }


async def test_access_control(
    state: dict[str, Any],
    toolkit: WebAppScannerToolkit,
) -> dict[str, Any]:
    """Test access control and authorization."""
    endpoints = state.get("endpoints_discovered", [])
    findings = await toolkit.test_access_control(endpoints)
    logger.info(
        "web_scanner.access_control_tested",
        findings=len(findings),
    )
    return {
        "access_control_findings": findings,
        "stage": ScannerStage.report,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Found {len(findings)} access control findings",
        ],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: WebAppScannerToolkit,
) -> dict[str, Any]:
    """Generate the final web app scan report."""
    inj = state.get("injection_findings", [])
    auth = state.get("auth_findings", [])
    acl = state.get("access_control_findings", [])

    # OWASP coverage mapping
    categories_tested = set()
    for finding in inj:
        categories_tested.add(finding.get("category", ""))
    for _finding in acl:
        categories_tested.add("idor")
    for _f in auth:
        categories_tested.add("auth_bypass")

    coverage: dict[str, str] = {}
    for cat in VulnCategory:
        if cat.value in categories_tested:
            coverage[cat.value] = "tested"
        else:
            coverage[cat.value] = "not_tested"

    vuln_count = len(
        [
            finding
            for finding in [*inj, *auth, *acl]
            if finding.get("result") in ("vulnerable", "potentially_vulnerable")
        ]
    )
    total = len(inj) + len(auth) + len(acl)
    score = max(0.0, 100.0 - vuln_count * 15) if total > 0 else 100.0

    report: dict[str, Any] = {
        "total_tests": total,
        "vulnerabilities_found": vuln_count,
        "owasp_coverage": coverage,
        "security_score": score,
    }

    # LLM-enhanced report
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "injection": inj[:10],
                "auth": auth[:10],
                "access_control": acl[:10],
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_WEB_REPORT,
            user_prompt=f"Web scan results:\n{ctx}",
            schema=WebScanReportOutput,
        )
        report["executive_summary"] = getattr(result, "executive_summary", "")
        report["recommendations"] = getattr(result, "recommendations", [])
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    return {
        "report_summary": report,
        "owasp_coverage": coverage,
        "security_score": score,
        "stage": ScannerStage.report,
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            f"Report: score={score:.1f}, {vuln_count} vulns found",
        ],
    }
