"""Grafana Mimir Integration — Prometheus remote write and PromQL querying.

Push API: POST /api/v1/push (Prometheus remote write)
Query API: GET /prometheus/api/v1/query_range (PromQL)
OTLP: POST /otlp/v1/metrics

When no ``username`` is configured the client operates in **buffered/test mode**:
data is stored locally instead of being sent over HTTP.
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class MimirMetric(BaseModel):
    """A single metric sample for Mimir remote write."""

    name: str
    value: float
    labels: dict[str, str] = Field(default_factory=dict)
    timestamp_ms: int = Field(default_factory=lambda: int(time.time() * 1000))


class MimirClient:
    """Push metrics to Mimir and query with PromQL.

    Endpoints:
    - POST /api/v1/push — Prometheus remote write (JSON format)
    - GET  /prometheus/api/v1/query_range — PromQL range queries
    - POST /otlp/v1/metrics — OTLP metric ingestion

    When ``username`` is empty the client operates in **buffered/test mode**:
    data is stored locally instead of being sent over HTTP.
    """

    def __init__(
        self,
        url: str = "http://localhost:9009",
        tenant_id: str = "shieldops",
        username: str = "",
        password: str = "",
    ):
        self._url = url.rstrip("/")
        self._tenant_id = tenant_id
        self._username = username
        self._password = password
        self._buffer: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Scope-OrgID": self._tenant_id,
        }

    def _auth(self) -> tuple[str, str] | None:
        if self._username and self._password:
            return (self._username, self._password)
        return None

    async def _post(self, path: str, payload: Any) -> dict[str, Any]:
        """POST JSON to the Mimir API."""
        url = f"{self._url}{path}"

        if not self._username:
            self._buffer.append({"path": path, "payload": payload})
            count = len(payload) if isinstance(payload, list) else 1
            logger.debug("mimir_buffered", path=path, count=count)
            return {"status": "buffered", "count": count}

        try:
            import httpx  # noqa: WPS433

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers=self._headers(),
                    auth=self._auth(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                logger.info("mimir_push_ok", path=path, status=resp.status_code)
                return {"status": "ok", "http_status": resp.status_code}
        except Exception as exc:
            logger.error("mimir_push_error", path=path, error=str(exc))
            return {"status": "error", "error": str(exc)}

    async def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        """GET from the Mimir/Prometheus API."""
        url = f"{self._url}{path}"

        if not self._username:
            logger.debug("mimir_query_buffered", path=path, params=params)
            return {"status": "buffered", "data": {"result": []}}

        try:
            import httpx  # noqa: WPS433

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    url,
                    params=params,
                    headers=self._headers(),
                    auth=self._auth(),
                    timeout=30.0,
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.error("mimir_query_error", path=path, error=str(exc))
            return {"status": "error", "error": str(exc), "data": {"result": []}}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def push_metrics(self, metrics: list[MimirMetric]) -> dict[str, Any]:
        """Push metrics via Prometheus remote write JSON format.

        Sends a list of timeseries samples to POST /api/v1/push.
        Each metric becomes a timeseries with ``__name__`` plus any extra labels.
        """
        timeseries: list[dict[str, Any]] = []
        for m in metrics:
            ts_labels = {"__name__": m.name, **m.labels}
            timeseries.append(
                {
                    "labels": ts_labels,
                    "samples": [{"value": m.value, "timestamp": m.timestamp_ms}],
                }
            )

        return await self._post("/api/v1/push", timeseries)

    async def push_agent_metric(
        self,
        agent_type: str,
        metric_name: str,
        value: float,
        extra_labels: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Convenience: push a single agent metric.

        Automatically adds ``platform`` and ``agent_type`` labels, and
        prefixes the metric name with ``shieldops_agent_``.
        """
        labels: dict[str, str] = {
            "platform": "shieldops",
            "agent_type": agent_type,
        }
        if extra_labels:
            labels.update(extra_labels)

        metric = MimirMetric(
            name=f"shieldops_agent_{metric_name}",
            value=value,
            labels=labels,
        )
        return await self.push_metrics([metric])

    async def query(
        self,
        promql: str,
        start_s: float = 0,
        end_s: float = 0,
        step: str = "15s",
    ) -> list[dict[str, Any]]:
        """Query metrics using PromQL: GET /prometheus/api/v1/query_range.

        Returns a list of result entries.  When in buffered mode an empty
        list is returned.
        """
        now = time.time()
        if end_s == 0:
            end_s = now
        if start_s == 0:
            start_s = end_s - 3600  # 1 hour ago

        params: dict[str, Any] = {
            "query": promql,
            "start": str(start_s),
            "end": str(end_s),
            "step": step,
        }
        result = await self._get("/prometheus/api/v1/query_range", params)
        return result.get("data", {}).get("result", [])

    def get_buffered(self) -> list[dict[str, Any]]:
        """Get locally buffered metrics (when no Mimir credentials configured)."""
        return self._buffer

    def clear_buffer(self) -> None:
        """Clear all buffered data."""
        self._buffer = []
