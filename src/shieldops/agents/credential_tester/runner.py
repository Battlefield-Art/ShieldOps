"""Credential Tester Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.credential_tester.graph import (
    build_graph,
)
from shieldops.agents.credential_tester.models import (
    CredentialTesterState,
)
from shieldops.agents.credential_tester.tools import (
    CredentialTesterToolkit,
)

logger = structlog.get_logger()


class CredentialTesterRunner:
    """Runner for the Credential Tester Agent."""

    def __init__(
        self,
        identity_provider: Any | None = None,
        hibp_client: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CredentialTesterToolkit(
            identity_provider=identity_provider,
            hibp_client=hibp_client,
            policy_engine=policy_engine,
            repository=repository,
        )
        graph = build_graph(self._toolkit)
        self._app = graph.compile()
        self._results: dict[str, CredentialTesterState] = {}
        logger.info("credential_tester_runner.initialized")

    async def test(
        self,
        tenant_id: str,
        account_ids: list[str] | None = None,
        policy_names: list[str] | None = None,
    ) -> CredentialTesterState:
        """Run a credential hygiene test."""
        session_id = f"crt-{uuid4().hex[:12]}"

        initial = CredentialTesterState(
            request_id=session_id,
            tenant_id=tenant_id,
            account_ids=account_ids or [],
            policy_names=policy_names or ["default"],
        )

        logger.info(
            "credential_tester_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            accounts=len(initial.account_ids),
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "credential_tester",
                    }
                },
            )
            final = CredentialTesterState.model_validate(result)
            self._results[session_id] = final
            logger.info(
                "credential_tester_runner.completed",
                session_id=session_id,
                risk=final.overall_risk_score,
                at_risk=len(final.accounts_at_risk),
            )
            return final

        except Exception as e:
            logger.error(
                "credential_tester_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            err = CredentialTesterState(
                request_id=session_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            self._results[session_id] = err
            return err

    def get_result(self, session_id: str) -> CredentialTesterState | None:
        """Get a previous test result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all test results."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "risk": s.overall_risk_score,
                "at_risk": len(s.accounts_at_risk),
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
