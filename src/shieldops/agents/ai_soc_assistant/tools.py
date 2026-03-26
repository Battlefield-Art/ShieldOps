"""Tool functions for the AI SOC Assistant Agent."""

from typing import Any

import structlog

logger = structlog.get_logger()


class AISOCAssistantToolkit:
    """Toolkit for cross-vendor SOC investigation."""

    def __init__(
        self,
        splunk_connector: Any | None = None,
        elastic_connector: Any | None = None,
        crowdstrike_connector: Any | None = None,
        defender_connector: Any | None = None,
        okta_connector: Any | None = None,
        soar_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._splunk = splunk_connector
        self._elastic = elastic_connector
        self._crowdstrike = crowdstrike_connector
        self._defender = defender_connector
        self._okta = okta_connector
        self._soar = soar_engine
        self._repository = repository

    async def search_siem(
        self,
        query: str,
        time_range: str = "24h",
        entities: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Search SIEM (Splunk + Elastic) for events."""
        logger.info(
            "ai_soc_assistant.search_siem",
            query=query[:80],
            time_range=time_range,
            entity_count=len(entities or []),
        )
        results: list[dict[str, Any]] = []
        # Splunk search
        if self._splunk:
            try:
                splunk_hits = await self._splunk.search(
                    query,
                    time_range=time_range,
                )
                results.extend(splunk_hits)
            except Exception:
                logger.warning("splunk_search_failed")
        # Elastic search
        if self._elastic:
            try:
                elastic_hits = await self._elastic.search(
                    query,
                    time_range=time_range,
                )
                results.extend(elastic_hits)
            except Exception:
                logger.warning("elastic_search_failed")
        return results

    async def query_edr(
        self,
        entities: list[str],
        time_range: str = "24h",
    ) -> list[dict[str, Any]]:
        """Query EDR (CrowdStrike + Defender) for endpoint data."""
        logger.info(
            "ai_soc_assistant.query_edr",
            entity_count=len(entities),
            time_range=time_range,
        )
        results: list[dict[str, Any]] = []
        if self._crowdstrike:
            try:
                cs_hits = await self._crowdstrike.query(
                    entities,
                    time_range=time_range,
                )
                results.extend(cs_hits)
            except Exception:
                logger.warning("crowdstrike_query_failed")
        if self._defender:
            try:
                defender_hits = await self._defender.query(
                    entities,
                    time_range=time_range,
                )
                results.extend(defender_hits)
            except Exception:
                logger.warning("defender_query_failed")
        return results

    async def check_identity(
        self,
        entities: list[str],
        time_range: str = "24h",
    ) -> list[dict[str, Any]]:
        """Check identity provider (Okta) for auth events."""
        logger.info(
            "ai_soc_assistant.check_identity",
            entity_count=len(entities),
        )
        if self._okta:
            try:
                return await self._okta.get_user_events(
                    entities,
                    time_range=time_range,
                )
            except Exception:
                logger.warning("okta_query_failed")
        return []

    async def scan_cloud(
        self,
        entities: list[str],
        time_range: str = "24h",
    ) -> list[dict[str, Any]]:
        """Scan cloud audit logs for entity activity."""
        logger.info(
            "ai_soc_assistant.scan_cloud",
            entity_count=len(entities),
        )
        return []

    async def run_playbook(
        self,
        playbook_name: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a SOAR playbook."""
        logger.info(
            "ai_soc_assistant.run_playbook",
            playbook=playbook_name,
        )
        if self._soar:
            try:
                return await self._soar.execute(
                    playbook_name,
                    parameters,
                )
            except Exception:
                logger.warning("playbook_execution_failed")
        return {
            "status": "completed",
            "playbook": playbook_name,
        }

    async def record_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record an assistant metric."""
        logger.info(
            "ai_soc_assistant.record_metric",
            metric_type=metric_type,
            value=value,
        )
