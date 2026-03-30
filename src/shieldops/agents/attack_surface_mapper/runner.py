"""Attack Surface Mapper runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.attack_surface_mapper.graph import (
    create_attack_surface_mapper_graph,
)
from shieldops.agents.attack_surface_mapper.models import (
    AttackSurfaceMapperState,
)
from shieldops.agents.attack_surface_mapper.nodes import (
    set_toolkit,
)
from shieldops.agents.attack_surface_mapper.tools import (
    AttackSurfaceMapperToolkit,
)

logger = structlog.get_logger()


class AttackSurfaceMapperRunner:
    """Runner for the Attack Surface Mapper Agent."""

    def __init__(
        self,
        dns_scanner: Any | None = None,
        cert_monitor: Any | None = None,
        cloud_enumerator: Any | None = None,
        vuln_scanner: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AttackSurfaceMapperToolkit(
            dns_scanner=dns_scanner,
            cert_monitor=cert_monitor,
            cloud_enumerator=cloud_enumerator,
            vuln_scanner=vuln_scanner,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_attack_surface_mapper_graph()
        self._app = graph.compile()
        self._results: dict[str, AttackSurfaceMapperState] = {}
        logger.info("asm_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        scan_config: dict[str, Any] | None = None,
    ) -> AttackSurfaceMapperState:
        """Run attack surface mapping workflow."""
        sid = f"asm-{uuid4().hex[:12]}"
        initial = AttackSurfaceMapperState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_config=scan_config or {},
        )

        logger.info(
            "asm_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "attack_surface_mapper",
                    },
                },
            )
            final = AttackSurfaceMapperState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "asm_runner.completed",
                session_id=sid,
                assets=len(final.discovered_assets),
                risk=final.max_risk_score,
                paths=len(final.attack_paths),
                recs=len(final.recommendations),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "asm_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = AttackSurfaceMapperState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_config=scan_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> AttackSurfaceMapperState | None:
        """Retrieve a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_assets": len(s.discovered_assets),
                "shadow_it": s.shadow_it_count,
                "internet_facing": (s.internet_facing_count),
                "max_risk": s.max_risk_score,
                "attack_paths": len(s.attack_paths),
                "recommendations": len(s.recommendations),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
