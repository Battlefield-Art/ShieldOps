"""Cross-Vendor Correlator Agent runner."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cross_vendor_correlator.graph import (
    create_cross_vendor_correlator_graph,
)
from shieldops.agents.cross_vendor_correlator.models import (
    CrossVendorCorrelatorState,
)
from shieldops.agents.cross_vendor_correlator.nodes import (
    set_toolkit,
)
from shieldops.agents.cross_vendor_correlator.tools import (
    CrossVendorCorrelatorToolkit,
)

logger = structlog.get_logger()


class CrossVendorCorrelatorRunner:
    """Runner for the Cross-Vendor Correlator Agent."""

    def __init__(
        self,
        vendor_connectors: Any | None = None,
        ocsf_normalizer: Any | None = None,
        correlation_engine: Any | None = None,
        kill_chain_mapper: Any | None = None,
        situation_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CrossVendorCorrelatorToolkit(
            vendor_connectors=vendor_connectors,
            ocsf_normalizer=ocsf_normalizer,
            correlation_engine=correlation_engine,
            kill_chain_mapper=kill_chain_mapper,
            situation_store=situation_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cross_vendor_correlator_graph()
        self._app = graph.compile()
        self._results: dict[str, CrossVendorCorrelatorState] = {}
        logger.info("cross_vendor_correlator_runner.initialized")

    async def correlate(
        self,
        tenant_id: str,
        vendors: list[str] | None = None,
        time_window_minutes: int = 60,
    ) -> CrossVendorCorrelatorState:
        """Run cross-vendor correlation."""
        session_id = f"cvc-{uuid4().hex[:12]}"
        initial = CrossVendorCorrelatorState(
            tenant_id=tenant_id,
            vendors=vendors or [],
            time_window_minutes=time_window_minutes,
        )

        logger.info(
            "cross_vendor_correlator.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            vendors=vendors,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": ("cross_vendor_correlator"),
                    }
                },
            )
            final = CrossVendorCorrelatorState.model_validate(result)
            self._results[session_id] = final

            logger.info(
                "cross_vendor_correlator.completed",
                session_id=session_id,
                alerts=final.total_alerts_ingested,
                situations=(final.total_situations_created),
                vendors=final.vendors_correlated,
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "cross_vendor_correlator.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = CrossVendorCorrelatorState(
                tenant_id=tenant_id,
                vendors=vendors or [],
                error=str(e),
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> CrossVendorCorrelatorState | None:
        """Retrieve a stored result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all correlation run summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "alerts": s.total_alerts_ingested,
                "situations": (s.total_situations_created),
                "vendors": s.vendors_correlated,
                "stage": s.current_stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
