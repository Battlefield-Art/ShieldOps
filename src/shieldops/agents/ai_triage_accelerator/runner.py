"""AI Triage Accelerator runner — entry point for executing triage workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ai_triage_accelerator.graph import (
    create_ai_triage_accelerator_graph,
)
from shieldops.agents.ai_triage_accelerator.models import (
    AITriageAcceleratorState,
    AlertBatch,
)
from shieldops.agents.ai_triage_accelerator.nodes import (
    set_toolkit,
)
from shieldops.agents.ai_triage_accelerator.tools import (
    AITriageAcceleratorToolkit,
)

logger = structlog.get_logger()


class AITriageAcceleratorRunner:
    """Runner for the AI Triage Accelerator Agent."""

    def __init__(
        self,
        siem_client: Any | None = None,
        threat_intel_client: Any | None = None,
        identity_graph_client: Any | None = None,
        asset_inventory: Any | None = None,
    ) -> None:
        self._toolkit = AITriageAcceleratorToolkit(
            siem_client=siem_client,
            threat_intel_client=threat_intel_client,
            identity_graph_client=identity_graph_client,
            asset_inventory=asset_inventory,
        )
        set_toolkit(self._toolkit)
        graph = create_ai_triage_accelerator_graph()
        self._app = graph.compile()
        self._results: dict[str, AITriageAcceleratorState] = {}
        logger.info(
            "ai_triage_accelerator_runner.initialized",
        )

    async def triage(
        self,
        tenant_id: str,
        alerts: list[dict[str, Any]] | None = None,
        source: str = "api",
    ) -> AITriageAcceleratorState:
        """Run the AI triage accelerator workflow.

        Args:
            tenant_id: Tenant identifier for isolation.
            alerts: List of raw alert dicts to triage.
                Each should have: id, title, description,
                source, severity, src_ip, dst_ip, domain,
                hash, host, user.
            source: Alert source identifier.

        Returns:
            Final AITriageAcceleratorState with
            classifications, enrichments, confidence
            scores, routing actions, and metrics.
        """
        request_id = f"ai-triage-{uuid4().hex[:12]}"
        raw_alerts = alerts or []

        batch = AlertBatch(
            id=f"batch-{uuid4().hex[:12]}",
            tenant_id=tenant_id,
            alerts=raw_alerts,
            source=source,
            batch_size=len(raw_alerts),
        )

        initial_state = AITriageAcceleratorState(
            request_id=request_id,
            tenant_id=tenant_id,
            alert_batch=batch,
        )

        logger.info(
            "ai_triage_accelerator_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            alert_count=len(raw_alerts),
            source=source,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "ai_triage_accelerator",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = AITriageAcceleratorState.model_validate(
                final_dict,
            )
            self._results[request_id] = final_state

            logger.info(
                "ai_triage_accelerator_runner.completed",
                request_id=request_id,
                alert_count=len(
                    final_state.alert_batch.alerts,
                ),
                classifications=len(
                    final_state.classifications,
                ),
                routing_actions=len(
                    final_state.routing_actions,
                ),
                speedup=f"{final_state.speedup_factor:.1f}x",
                accuracy=f"{final_state.accuracy_score:.2f}",
                fp_rate=f"{final_state.false_positive_rate:.2f}",
                duration_ms=(final_state.session_duration_ms),
            )
            return final_state

        except Exception as e:
            logger.error(
                "ai_triage_accelerator_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = AITriageAcceleratorState(
                request_id=request_id,
                tenant_id=tenant_id,
                alert_batch=batch,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> AITriageAcceleratorState | None:
        """Retrieve a previous triage result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all triage results with summary."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "alert_count": len(
                    state.alert_batch.alerts,
                ),
                "classifications": len(
                    state.classifications,
                ),
                "routing_actions": len(
                    state.routing_actions,
                ),
                "speedup_factor": state.speedup_factor,
                "accuracy_score": state.accuracy_score,
                "false_positive_rate": (state.false_positive_rate),
                "current_step": state.current_step,
                "duration_ms": (state.session_duration_ms),
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]
