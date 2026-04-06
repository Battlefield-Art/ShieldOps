"""OTLP/gRPC log receiver.

Implements the ``opentelemetry.proto.collector.logs.v1.LogsService/Export``
RPC and pushes each inbound ``LogRecord`` through the ShieldOps ingestion
pipeline with ``source_provider="otel"``.

The ``grpc`` and ``opentelemetry-proto`` packages are imported lazily so
``shieldops.ingestion.otlp`` stays importable in stripped-down environments.
The module exposes ``start_otlp_grpc_server()`` /
``stop_otlp_grpc_server()`` lifecycle hooks — these are not called on
import; callers (typically the FastAPI lifespan) must invoke them.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from shieldops.ingestion.otlp.parser import _iter_resource_logs_proto
from shieldops.ingestion.pipeline import BatchResult, process_batch

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------

_server: Any = None
_server_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Lazy imports
# ---------------------------------------------------------------------------


def _import_grpc() -> tuple[Any, Any, Any]:
    """Import grpc.aio + the OTLP logs service stubs.

    Returns ``(grpc_aio, logs_service_pb2, logs_service_pb2_grpc)``.
    Raises ``RuntimeError`` with a helpful message if any are missing.
    """
    try:
        from grpc import aio as grpc_aio  # type: ignore[import-not-found]
        from opentelemetry.proto.collector.logs.v1 import (  # type: ignore[import-not-found]
            logs_service_pb2,
            logs_service_pb2_grpc,
        )
    except Exception as exc:  # pragma: no cover - import guard
        raise RuntimeError("OTLP/gRPC support requires 'grpcio' and 'opentelemetry-proto'") from exc
    return grpc_aio, logs_service_pb2, logs_service_pb2_grpc


# ---------------------------------------------------------------------------
# Servicer
# ---------------------------------------------------------------------------


def _build_logs_service(logs_service_pb2: Any, logs_service_pb2_grpc: Any, org_id: str) -> Any:
    """Build the LogsService servicer class bound to the given org_id.

    Defined lazily inside a factory so we can subclass a type we only have
    after importing grpc at runtime.
    """

    class LogsService(logs_service_pb2_grpc.LogsServiceServicer):  # type: ignore[misc, name-defined]
        """OTLP LogsService — converts incoming ExportLogsServiceRequest
        messages into raw events and routes them through ``process_batch``."""

        def __init__(self) -> None:
            self.org_id = org_id

        async def Export(  # noqa: N802  (gRPC method naming)
            self,
            request: Any,
            context: Any,  # noqa: ARG002
        ) -> Any:
            try:
                events = _iter_resource_logs_proto(request)
            except Exception as exc:
                logger.exception("otlp.grpc_parse_failed", error=str(exc))
                return logs_service_pb2.ExportLogsServiceResponse()

            if not events:
                return logs_service_pb2.ExportLogsServiceResponse()

            try:
                batch: BatchResult = await process_batch(events, "otel", self.org_id)
                logger.info(
                    "otlp.grpc_logs_ingested",
                    org_id=self.org_id,
                    accepted=batch.accepted,
                    rejected=batch.rejected,
                )
            except Exception as exc:
                logger.exception("otlp.grpc_pipeline_failed", error=str(exc))

            # Empty response = full success per OTLP spec. Partial success
            # can be signalled via ExportLogsPartialSuccess — wire it when
            # per-record errors become meaningful.
            return logs_service_pb2.ExportLogsServiceResponse()

    return LogsService()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


async def start_otlp_grpc_server(
    host: str = "0.0.0.0",  # noqa: S104  # nosec B104 — receivers bind to all interfaces
    port: int = 4317,
    org_id: str = "default",
    max_concurrent_rpcs: int = 100,
) -> Any:
    """Start (or return) the process-wide OTLP/gRPC log server.

    Args:
        host: Bind address. Defaults to all interfaces.
        port: Bind port. OTLP/gRPC standard port is 4317.
        org_id: Tenant id applied to every ingested log record.
        max_concurrent_rpcs: Server-side concurrency cap.

    Returns:
        The running ``grpc.aio.Server`` instance.
    """
    global _server
    async with _server_lock:
        if _server is not None:
            return _server

        grpc_aio, logs_service_pb2, logs_service_pb2_grpc = _import_grpc()

        server = grpc_aio.server(maximum_concurrent_rpcs=max_concurrent_rpcs)
        servicer = _build_logs_service(logs_service_pb2, logs_service_pb2_grpc, org_id)
        logs_service_pb2_grpc.add_LogsServiceServicer_to_server(servicer, server)
        bind_addr = f"{host}:{port}"
        server.add_insecure_port(bind_addr)
        await server.start()
        _server = server
        logger.info("otlp.grpc_server_started", bind=bind_addr, org_id=org_id)
        return server


async def stop_otlp_grpc_server(grace: float = 1.0) -> None:
    """Gracefully stop the OTLP/gRPC log server, if running."""
    global _server
    async with _server_lock:
        if _server is None:
            return
        try:
            await _server.stop(grace)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("otlp.grpc_server_stop_failed", error=str(exc))
        _server = None
        logger.info("otlp.grpc_server_stopped")


def get_otlp_grpc_server() -> Any:
    """Return the currently running OTLP/gRPC server, if any."""
    return _server
