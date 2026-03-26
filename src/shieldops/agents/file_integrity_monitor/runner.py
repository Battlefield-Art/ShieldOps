"""File Integrity Monitor Agent runner.

Takes a tenant ID and optional monitored paths, constructs
the LangGraph, runs it end-to-end, and returns the
completed FIM state.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.file_integrity_monitor.graph import (
    create_file_integrity_monitor_graph,
)
from shieldops.agents.file_integrity_monitor.models import (
    FileIntegrityMonitorState,
)
from shieldops.agents.file_integrity_monitor.nodes import (
    set_toolkit,
)
from shieldops.agents.file_integrity_monitor.tools import (
    FileIntegrityMonitorToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class FileIntegrityMonitorRunner:
    """Runs file integrity monitor agent workflows.

    Usage:
        runner = FileIntegrityMonitorRunner()
        result = await runner.monitor(
            tenant_id="tenant-123"
        )
    """

    def __init__(self) -> None:
        self._toolkit = FileIntegrityMonitorToolkit()
        set_toolkit(self._toolkit)

        graph = create_file_integrity_monitor_graph()
        self._app = graph.compile()

        # In-memory store of completed scans
        self._scans: dict[str, FileIntegrityMonitorState] = {}

    async def monitor(
        self,
        tenant_id: str,
        monitored_paths: list[str] | None = None,
    ) -> FileIntegrityMonitorState:
        """Run a full FIM scan for a tenant.

        Args:
            tenant_id: The tenant to monitor.
            monitored_paths: Optional list of specific
                paths to monitor. If None, uses defaults.

        Returns:
            Completed FileIntegrityMonitorState with
            changes, classifications, and report.
        """
        run_id = f"fim-{uuid4().hex[:12]}"

        logger.info(
            "fim_scan_started",
            run_id=run_id,
            tenant_id=tenant_id,
        )

        initial_state = FileIntegrityMonitorState(
            tenant_id=tenant_id,
            run_id=run_id,
            monitored_paths=monitored_paths or [],
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("file_integrity_monitor.run") as span:
                span.set_attribute("fim.run_id", run_id)
                span.set_attribute("fim.tenant_id", tenant_id)

                final_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "run_id": run_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final_state = FileIntegrityMonitorState.model_validate(final_dict)

                span.set_attribute(
                    "fim.baselines_scanned",
                    final_state.baselines_scanned,
                )
                span.set_attribute(
                    "fim.changes_detected",
                    final_state.changes_detected,
                )
                span.set_attribute(
                    "fim.critical_changes",
                    final_state.critical_changes,
                )
                span.set_attribute(
                    "fim.duration_ms",
                    final_state.duration_ms,
                )

            logger.info(
                "fim_scan_completed",
                run_id=run_id,
                tenant_id=tenant_id,
                baselines=final_state.baselines_scanned,
                changes=final_state.changes_detected,
                critical=final_state.critical_changes,
                compliance_violations=(final_state.compliance_violations),
                responses=len(final_state.responses),
                duration_ms=final_state.duration_ms,
            )

            self._scans[run_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "fim_scan_failed",
                run_id=run_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            error_state = FileIntegrityMonitorState(
                tenant_id=tenant_id,
                run_id=run_id,
                error=str(e),
            )
            self._scans[run_id] = error_state
            return error_state

    def get_scan(self, run_id: str) -> FileIntegrityMonitorState | None:
        """Retrieve a completed scan by run ID."""
        return self._scans.get(run_id)

    def list_scans(self) -> list[dict[str, Any]]:
        """List all scans with summary info."""
        return [
            {
                "run_id": rid,
                "tenant_id": state.tenant_id,
                "stage": state.stage,
                "baselines_scanned": (state.baselines_scanned),
                "changes_detected": (state.changes_detected),
                "critical_changes": (state.critical_changes),
                "compliance_violations": (state.compliance_violations),
                "duration_ms": state.duration_ms,
                "error": state.error,
            }
            for rid, state in self._scans.items()
        ]
