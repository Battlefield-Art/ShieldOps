"""OpenTelemetry pipeline processors for ShieldOps.

Implements the Processor stage of the Receiver->Processor->Exporter pipeline.
Includes batch, resource detection, memory limiter, and custom enrichment.
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class BatchConfig(BaseModel):
    """Configuration for batch processing."""

    timeout_seconds: float = 5.0
    send_batch_size: int = 512
    send_batch_max_size: int = 1024


class MemoryLimiterConfig(BaseModel):
    """Configuration for memory limiting."""

    check_interval_seconds: float = 1.0
    limit_mib: int = 200
    spike_limit_mib: int = 50


class ResourceDetectionConfig(BaseModel):
    """Configuration for resource detection."""

    detectors: list[str] = Field(default_factory=lambda: ["system", "env", "k8snode"])
    override: bool = False


class ProcessorChain:
    """Chain of processors that transform telemetry data."""

    def __init__(
        self,
        batch_config: BatchConfig | None = None,
        memory_config: MemoryLimiterConfig | None = None,
        resource_config: ResourceDetectionConfig | None = None,
        enrichment_attributes: dict[str, str] | None = None,
    ) -> None:
        self._batch_config = batch_config or BatchConfig()
        self._memory_config = memory_config or MemoryLimiterConfig()
        self._resource_config = resource_config or ResourceDetectionConfig()
        self._enrichment = enrichment_attributes or {}
        self._batch_buffer: list[dict[str, Any]] = []
        self._last_flush = time.time()
        self._stats = {
            "processed": 0,
            "batches_flushed": 0,
            "dropped_memory_limit": 0,
            "enriched": 0,
        }
        logger.info("processor_chain.init")

    async def process(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Process a batch of telemetry records through the chain."""
        # Step 1: Memory limiter check
        records = self._apply_memory_limit(records)

        # Step 2: Resource detection / enrichment
        records = self._enrich_resources(records)

        # Step 3: Custom attribute enrichment
        records = self._apply_enrichment(records)

        # Step 4: Batch accumulation
        self._batch_buffer.extend(records)
        self._stats["processed"] += len(records)

        # Step 5: Flush if batch is full or timeout reached
        if self._should_flush():
            return self._flush_batch()
        return []

    async def flush(self) -> list[dict[str, Any]]:
        """Force flush the batch buffer."""
        return self._flush_batch()

    def get_stats(self) -> dict[str, Any]:
        """Get processor statistics."""
        return {
            **self._stats,
            "buffer_size": len(self._batch_buffer),
        }

    def _apply_memory_limit(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Drop records if memory limit would be exceeded."""
        max_records = self._memory_config.limit_mib * 100  # Rough estimate
        if len(self._batch_buffer) + len(records) > max_records:
            excess = len(self._batch_buffer) + len(records) - max_records
            self._stats["dropped_memory_limit"] += excess
            logger.warning(
                "processor_chain.memory_limit",
                dropped=excess,
            )
            return records[: len(records) - excess] if excess < len(records) else []
        return records

    def _enrich_resources(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Add resource detection attributes."""
        import socket

        hostname = socket.gethostname()
        for record in records:
            resource = record.setdefault("resource", {})
            if "system" in self._resource_config.detectors:
                resource.setdefault("host.name", hostname)
            if "env" in self._resource_config.detectors:
                resource.setdefault("deployment.environment", "production")
        return records

    def _apply_enrichment(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply custom enrichment attributes."""
        if not self._enrichment:
            return records
        for record in records:
            attrs = record.setdefault("attributes", {})
            for k, v in self._enrichment.items():
                attrs.setdefault(k, v)
            self._stats["enriched"] += 1
        return records

    def _should_flush(self) -> bool:
        """Check if batch should be flushed."""
        if len(self._batch_buffer) >= self._batch_config.send_batch_size:
            return True
        elapsed = time.time() - self._last_flush
        if elapsed >= self._batch_config.timeout_seconds:
            return True
        return False

    def _flush_batch(self) -> list[dict[str, Any]]:
        """Flush the batch buffer."""
        batch = self._batch_buffer[: self._batch_config.send_batch_max_size]
        self._batch_buffer = self._batch_buffer[self._batch_config.send_batch_max_size :]
        self._last_flush = time.time()
        self._stats["batches_flushed"] += 1
        return batch
