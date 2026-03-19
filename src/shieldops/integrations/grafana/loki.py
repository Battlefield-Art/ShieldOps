"""Grafana Loki Integration — Log ingestion and LogQL querying.

Push API: POST /loki/api/v1/push
Query API: GET /loki/api/v1/query_range
Labels API: GET /loki/api/v1/labels

Loki receives log streams grouped by label sets.  Each stream contains
timestamp/line pairs.  When no ``url`` is configured (empty string) the
client operates in **buffered/test mode** — data is stored locally.
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class LokiStream(BaseModel):
    """A Loki log stream with labels and entries."""

    labels: dict[str, str]
    entries: list[tuple[str, str]] = Field(default_factory=list)  # (timestamp_ns, line)


class LokiPushRequest(BaseModel):
    """Loki push API request body."""

    streams: list[LokiStream] = Field(default_factory=list)


class LokiClient:
    """Push logs to Loki and query with LogQL.

    Endpoints:
    - POST /loki/api/v1/push — log ingestion
    - GET  /loki/api/v1/query_range — LogQL queries
    - GET  /loki/api/v1/labels — available label names

    When ``url`` is empty the client operates in **buffered/test mode**:
    data is stored locally instead of being sent over HTTP.
    """

    def __init__(
        self,
        url: str = "http://localhost:3100",
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

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST JSON to the Loki API.

        In production this uses ``httpx.AsyncClient``.  When no username is
        configured the data is buffered locally for inspection in tests.
        """
        url = f"{self._url}{path}"

        if not self._username:
            self._buffer.append({"path": path, "payload": payload})
            logger.debug(
                "loki_buffered",
                path=path,
                stream_count=len(payload.get("streams", [])),
            )
            return {"status": "buffered", "count": len(payload.get("streams", []))}

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
                logger.info("loki_push_ok", path=path, status=resp.status_code)
                return {"status": "ok", "http_status": resp.status_code}
        except Exception as exc:
            logger.error("loki_push_error", path=path, error=str(exc))
            return {"status": "error", "error": str(exc)}

    async def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        """GET from the Loki API."""
        url = f"{self._url}{path}"

        if not self._username:
            logger.debug("loki_query_buffered", path=path, params=params)
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
            logger.error("loki_query_error", path=path, error=str(exc))
            return {"status": "error", "error": str(exc), "data": {"result": []}}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def push_logs(self, streams: list[LokiStream]) -> dict[str, Any]:
        """Push log streams to POST /loki/api/v1/push.

        The Loki push format expects::

            {"streams": [{"stream": {labels}, "values": [["ts_ns", "line"], ...]}]}
        """
        loki_streams: list[dict[str, Any]] = []
        for s in streams:
            loki_streams.append(
                {
                    "stream": s.labels,
                    "values": [list(entry) for entry in s.entries],
                }
            )

        payload = {"streams": loki_streams}
        return await self._post("/loki/api/v1/push", payload)

    async def push_agent_log(
        self,
        agent_type: str,
        level: str,
        message: str,
        extra_labels: dict[str, str] | None = None,
        structured_metadata: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Convenience: push a single agent log entry with structured metadata.

        Automatically adds ``platform``, ``agent_type``, and ``level`` labels.
        Structured metadata is appended to the log line as key=value pairs.
        """
        labels: dict[str, str] = {
            "platform": "shieldops",
            "agent_type": agent_type,
            "level": level,
        }
        if extra_labels:
            labels.update(extra_labels)

        line = message
        if structured_metadata:
            meta_str = " ".join(f"{k}={v}" for k, v in structured_metadata.items())
            line = f"{message} | {meta_str}"

        ts_ns = str(int(time.time() * 1_000_000_000))
        stream = LokiStream(labels=labels, entries=[(ts_ns, line)])
        return await self.push_logs([stream])

    async def query(
        self,
        logql: str,
        start_ns: int = 0,
        end_ns: int = 0,
        limit: int = 100,
        direction: str = "backward",
    ) -> list[dict[str, Any]]:
        """Query logs using LogQL: GET /loki/api/v1/query_range.

        Returns a list of result entries.  When in buffered mode an empty
        list is returned.
        """
        now_ns = int(time.time() * 1_000_000_000)
        if end_ns == 0:
            end_ns = now_ns
        if start_ns == 0:
            start_ns = end_ns - 3_600_000_000_000  # 1 hour ago

        params: dict[str, Any] = {
            "query": logql,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": str(limit),
            "direction": direction,
        }
        result = await self._get("/loki/api/v1/query_range", params)
        return result.get("data", {}).get("result", [])

    async def get_labels(self) -> list[str]:
        """Get available label names from GET /loki/api/v1/labels."""
        result = await self._get("/loki/api/v1/labels", {})
        return result.get("data", []) if isinstance(result.get("data"), list) else []

    def get_buffered(self) -> list[dict[str, Any]]:
        """Get locally buffered logs (when no Loki credentials configured)."""
        return self._buffer

    def clear_buffer(self) -> None:
        """Clear all buffered data."""
        self._buffer = []
