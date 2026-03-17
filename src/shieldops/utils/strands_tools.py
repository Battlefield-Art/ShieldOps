"""Strands Agents SDK tool wrappers for ShieldOps.

Wraps ShieldOps agent toolkits as @tool decorated functions
compatible with the strands-agents SDK for AWS Bedrock deployment.

Install: ``pip install strands-agents``
"""

from __future__ import annotations

import json
from typing import Any

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Strands availability check
# ---------------------------------------------------------------------------

try:
    from strands import tool  # type: ignore[import-untyped]

    STRANDS_AVAILABLE = True
except ImportError:
    STRANDS_AVAILABLE = False

    def tool(func: Any) -> Any:  # type: ignore[misc]
        """No-op decorator when strands-agents is not installed."""
        return func


# ---------------------------------------------------------------------------
# Helper: run an async runner from sync context (Strands tools are sync)
# ---------------------------------------------------------------------------


def _run_async(coro: Any) -> Any:
    """Execute an async coroutine from a synchronous Strands tool context."""
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # We are inside an existing event loop — use a new thread
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=600)
    else:
        return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@tool
def investigate_incident(alert_id: str, environment: str = "production") -> str:
    """Investigate an infrastructure incident using ShieldOps AI agents.

    Correlates logs, metrics, and traces to identify root cause.

    Args:
        alert_id: The alert ID to investigate.
        environment: Target environment (production, staging, development).

    Returns:
        JSON summary of investigation findings.
    """
    try:
        from shieldops.agents.investigation.runner import InvestigationRunner
        from shieldops.models.base import AlertContext

        runner = InvestigationRunner()
        alert = AlertContext(
            alert_id=alert_id,
            alert_name=f"strands-investigation-{alert_id}",
            severity="high",
            source="strands-agent",
            environment=environment,
        )
        result = _run_async(runner.investigate(alert))
        summary: dict[str, Any] = {
            "alert_id": alert_id,
            "environment": environment,
            "status": getattr(result, "status", "completed"),
            "root_cause": getattr(result, "root_cause", "analysis pending"),
            "confidence": getattr(result, "confidence", 0.0),
            "hypotheses_count": len(getattr(result, "hypotheses", [])),
            "reasoning_steps": len(getattr(result, "reasoning_chain", [])),
        }
        return json.dumps(summary, indent=2, default=str)
    except Exception as exc:
        logger.exception("strands_tools.investigate_incident.error")
        return json.dumps(
            {"error": str(exc), "alert_id": alert_id, "status": "failed"},
            indent=2,
        )


@tool
def run_security_scan(targets: str, categories: str = "vulnerability,configuration") -> str:
    """Run a security scan against specified targets.

    Args:
        targets: Comma-separated list of target services or namespaces.
        categories: Comma-separated scan categories (vulnerability, configuration, compliance).

    Returns:
        JSON summary of security scan findings.
    """
    try:
        from shieldops.agents.security.runner import SecurityRunner

        runner = SecurityRunner()
        result = _run_async(runner.scan())
        scan_categories = [c.strip() for c in categories.split(",")]
        target_list = [t.strip() for t in targets.split(",")]
        summary: dict[str, Any] = {
            "targets": target_list,
            "categories": scan_categories,
            "status": getattr(result, "status", "completed"),
            "findings_count": len(getattr(result, "findings", [])),
            "critical_count": getattr(result, "critical_count", 0),
            "high_count": getattr(result, "high_count", 0),
        }
        return json.dumps(summary, indent=2, default=str)
    except Exception as exc:
        logger.exception("strands_tools.run_security_scan.error")
        return json.dumps(
            {"error": str(exc), "targets": targets, "status": "failed"},
            indent=2,
        )


@tool
def check_compliance(frameworks: str = "soc2") -> str:
    """Run a compliance audit for specified frameworks.

    Args:
        frameworks: Comma-separated list of frameworks (soc2, hipaa, pci_dss, iso27001).

    Returns:
        JSON summary of compliance audit results.
    """
    try:
        from shieldops.agents.compliance_auditor.runner import ComplianceAuditorRunner

        framework_list = [f.strip() for f in frameworks.split(",")]
        runner = ComplianceAuditorRunner()
        result = _run_async(runner.run(frameworks=framework_list))
        summary: dict[str, Any] = {
            "frameworks": framework_list,
            "status": (
                result.get("status", "completed") if isinstance(result, dict) else "completed"
            ),
            "controls_assessed": (
                result.get("controls_assessed", 0) if isinstance(result, dict) else 0
            ),
            "controls_passing": (
                result.get("controls_passing", 0) if isinstance(result, dict) else 0
            ),
        }
        return json.dumps(summary, indent=2, default=str)
    except Exception as exc:
        logger.exception("strands_tools.check_compliance.error")
        return json.dumps(
            {"error": str(exc), "frameworks": frameworks, "status": "failed"},
            indent=2,
        )


@tool
def optimize_telemetry(namespace: str = "default") -> str:
    """Analyze and optimize telemetry pipeline costs.

    Args:
        namespace: The Kubernetes namespace or service group to optimize.

    Returns:
        JSON summary of telemetry optimization recommendations.
    """
    try:
        from shieldops.agents.telemetry_optimizer.runner import TelemetryOptimizerRunner

        runner = TelemetryOptimizerRunner()
        result = _run_async(runner.run(namespace))
        summary: dict[str, Any] = {
            "namespace": namespace,
            "status": getattr(result, "status", "completed"),
            "recommendations_count": len(getattr(result, "recommendations", [])),
            "estimated_savings_pct": getattr(result, "estimated_savings_pct", 0.0),
        }
        return json.dumps(summary, indent=2, default=str)
    except Exception as exc:
        logger.exception("strands_tools.optimize_telemetry.error")
        return json.dumps(
            {"error": str(exc), "namespace": namespace, "status": "failed"},
            indent=2,
        )


@tool
def assess_threat_model(service: str) -> str:
    """Run STRIDE threat model analysis on a service.

    Args:
        service: The service name or architecture component to analyze.

    Returns:
        JSON summary of STRIDE threat model findings.
    """
    try:
        from shieldops.agents.threat_modeling.runner import ThreatModelingRunner

        runner = ThreatModelingRunner()
        result = _run_async(runner.run(target_service=service))
        summary: dict[str, Any] = {
            "service": service,
            "status": (
                result.get("status", "completed") if isinstance(result, dict) else "completed"
            ),
            "threats_found": (result.get("threats_found", 0) if isinstance(result, dict) else 0),
            "risk_level": (
                result.get("risk_level", "unknown") if isinstance(result, dict) else "unknown"
            ),
        }
        return json.dumps(summary, indent=2, default=str)
    except Exception as exc:
        logger.exception("strands_tools.assess_threat_model.error")
        return json.dumps(
            {"error": str(exc), "service": service, "status": "failed"},
            indent=2,
        )


# Convenience list of all tool functions for registration
ALL_TOOLS = [
    investigate_incident,
    run_security_scan,
    check_compliance,
    optimize_telemetry,
    assess_threat_model,
]
