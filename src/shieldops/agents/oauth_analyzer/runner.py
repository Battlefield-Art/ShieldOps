"""OAuth Grant Analyzer Agent runner — entry point for OAuth grant analysis."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.oauth_analyzer.graph import create_oauth_analyzer_graph
from shieldops.agents.oauth_analyzer.models import OAuthAnalyzerState
from shieldops.agents.oauth_analyzer.nodes import set_toolkit
from shieldops.agents.oauth_analyzer.tools import OAuthAnalyzerToolkit
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class OAuthAnalyzerRunner:
    """Runs OAuth grant analysis workflows.

    Usage:
        runner = OAuthAnalyzerRunner()
        result = await runner.analyze("tenant-acme", scan_scope=["github", "slack"])
    """

    def __init__(
        self,
        identity_provider: Any | None = None,
        saas_registry: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._toolkit = OAuthAnalyzerToolkit(
            identity_provider=identity_provider,
            saas_registry=saas_registry,
            threat_intel=threat_intel,
        )
        set_toolkit(self._toolkit)

        graph = create_oauth_analyzer_graph(
            identity_provider=identity_provider,
            saas_registry=saas_registry,
            threat_intel=threat_intel,
        )
        self._app = graph.compile()

        self._analyses: dict[str, OAuthAnalyzerState] = {}

    async def analyze(
        self,
        tenant_id: str,
        scan_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run a full OAuth grant analysis for a tenant.

        Args:
            tenant_id: The tenant or organization to scan.
            scan_scope: Optional list of providers to scan
                (e.g. ["google_workspace", "github"]).

        Returns:
            A dict with grants, anomalies, recommendations, stats,
            and reasoning chain.
        """
        request_id = f"oauth-{uuid4().hex[:12]}"
        scan_scope = scan_scope or []

        logger.info(
            "oauth_analyzer_started",
            request_id=request_id,
            tenant_id=tenant_id,
            scan_scope=scan_scope,
        )

        initial_state = OAuthAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_scope=scan_scope,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("oauth_analyzer.analyze") as span:
                span.set_attribute("oauth_analyzer.request_id", request_id)
                span.set_attribute("oauth_analyzer.tenant_id", tenant_id)

                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "request_id": request_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final_state = OAuthAnalyzerState.model_validate(final_state_dict)

                span.set_attribute(
                    "oauth_analyzer.grants_found",
                    len(final_state.discovered_grants),
                )
                span.set_attribute(
                    "oauth_analyzer.anomalies_found",
                    len(final_state.anomalies),
                )

            logger.info(
                "oauth_analyzer_completed",
                request_id=request_id,
                tenant_id=tenant_id,
                grants=len(final_state.discovered_grants),
                anomalies=len(final_state.anomalies),
                recommendations=len(final_state.recommendations),
                duration_ms=final_state.session_duration_ms,
            )

            self._analyses[request_id] = final_state

            return {
                "request_id": request_id,
                "tenant_id": tenant_id,
                "grants": [g.model_dump() for g in final_state.discovered_grants],
                "anomalies": [a.model_dump() for a in final_state.anomalies],
                "recommendations": [r.model_dump() for r in final_state.recommendations],
                "stats": final_state.stats,
                "reasoning_chain": final_state.reasoning_chain,
                "duration_ms": final_state.session_duration_ms,
                "error": final_state.error,
            }

        except Exception as exc:
            logger.error(
                "oauth_analyzer_failed",
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(exc),
            )
            error_state = OAuthAnalyzerState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(exc),
                current_step="failed",
            )
            self._analyses[request_id] = error_state
            return {
                "request_id": request_id,
                "tenant_id": tenant_id,
                "grants": [],
                "anomalies": [],
                "recommendations": [],
                "stats": {},
                "reasoning_chain": [],
                "duration_ms": 0,
                "error": str(exc),
            }

    def get_analysis(self, request_id: str) -> OAuthAnalyzerState | None:
        """Retrieve a completed analysis by request ID."""
        return self._analyses.get(request_id)

    def list_analyses(self) -> list[dict[str, Any]]:
        """List all analyses with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "status": state.current_step,
                "grants": len(state.discovered_grants),
                "anomalies": len(state.anomalies),
                "recommendations": len(state.recommendations),
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for rid, state in self._analyses.items()
        ]
