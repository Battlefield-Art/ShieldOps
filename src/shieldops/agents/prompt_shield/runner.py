"""Prompt Shield Agent runner — entry point for executing prompt defense workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.prompt_shield.graph import build_graph
from shieldops.agents.prompt_shield.models import PromptSample, PromptShieldState
from shieldops.agents.prompt_shield.nodes import set_toolkit
from shieldops.agents.prompt_shield.tools import PromptShieldToolkit

logger = structlog.get_logger()


class PromptShieldRunner:
    """Runner for the Prompt Shield Agent."""

    def __init__(
        self,
        policy_engine: Any | None = None,
        threat_intel: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PromptShieldToolkit(
            policy_engine=policy_engine,
            threat_intel=threat_intel,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = build_graph(self._toolkit)
        self._app = graph.compile()
        self._results: dict[str, PromptShieldState] = {}
        logger.info("prompt_shield_runner.initialized")

    async def analyze(
        self,
        tenant_id: str,
        prompts: list[dict[str, Any]],
        *,
        scan_id: str | None = None,
    ) -> PromptShieldState:
        """Run prompt shield analysis on a batch of prompts.

        Args:
            tenant_id: Tenant identifier for policy lookup.
            prompts: List of prompt dicts with at minimum a ``content`` key.
            scan_id: Optional scan identifier; generated if omitted.

        Returns:
            Final ``PromptShieldState`` with detections, enforcement actions, and report.
        """
        scan_id = scan_id or f"scan-{uuid4().hex[:12]}"
        session_id = f"ps-{uuid4().hex[:12]}"

        samples = [
            PromptSample(
                sample_id=p.get("sample_id", f"ps-{idx:04d}"),
                content=p.get("content", ""),
                source=p.get("source", "api"),
                role=p.get("role", "user"),
                metadata=p.get("metadata", {}),
            )
            for idx, p in enumerate(prompts)
        ]

        initial_state = PromptShieldState(
            tenant_id=tenant_id,
            scan_id=scan_id,
            prompts=samples,
        )

        logger.info(
            "prompt_shield_runner.starting",
            session_id=session_id,
            scan_id=scan_id,
            tenant_id=tenant_id,
            prompt_count=len(samples),
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={"metadata": {"session_id": session_id, "agent": "prompt_shield"}},
            )
            final_state = PromptShieldState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "prompt_shield_runner.completed",
                session_id=session_id,
                scan_id=scan_id,
                total_scanned=final_state.total_scanned,
                total_blocked=final_state.total_blocked,
                total_malicious=final_state.total_malicious,
                risk_level=final_state.report.get("risk_level", "unknown"),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "prompt_shield_runner.failed",
                session_id=session_id,
                scan_id=scan_id,
                error=str(e),
            )
            error_state = PromptShieldState(
                tenant_id=tenant_id,
                scan_id=scan_id,
                prompts=samples,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> PromptShieldState | None:
        """Retrieve a previous scan result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results with summary information."""
        return [
            {
                "session_id": sid,
                "scan_id": state.scan_id,
                "tenant_id": state.tenant_id,
                "total_scanned": state.total_scanned,
                "total_blocked": state.total_blocked,
                "total_malicious": state.total_malicious,
                "risk_level": state.report.get("risk_level", "unknown"),
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
