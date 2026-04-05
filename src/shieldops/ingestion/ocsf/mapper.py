"""OCSF mapper framework — registry and normalization entry point.

Provides the Protocol for vendor mappers, a global registry for lookup,
and the ``normalize()`` function as the single entry point for transforming
raw vendor events into OCSF-normalized models.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import structlog

from shieldops.ingestion.ocsf.models import OCSFBaseEvent

logger = structlog.get_logger()


@runtime_checkable
class OCSFMapper(Protocol):
    """Protocol that all vendor-specific OCSF mappers must implement."""

    def map(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        """Transform a raw vendor event into an OCSF event model."""
        ...


class MapperRegistry:
    """Registry that maps source_provider names to their OCSFMapper instances.

    Usage::

        registry = MapperRegistry()
        registry.register("cloudtrail", CloudTrailMapper())
        event = registry.normalize("cloudtrail", raw)
    """

    def __init__(self) -> None:
        self._mappers: dict[str, OCSFMapper] = {}

    def register(self, source_provider: str, mapper: OCSFMapper) -> None:
        """Register a mapper for a given source provider."""
        self._mappers[source_provider] = mapper
        logger.info(
            "ocsf_mapper_registered",
            source_provider=source_provider,
            mapper=type(mapper).__name__,
        )

    def get(self, source_provider: str) -> OCSFMapper | None:
        """Look up the mapper for a source provider."""
        return self._mappers.get(source_provider)

    def providers(self) -> list[str]:
        """Return list of registered source provider names."""
        return list(self._mappers.keys())

    def normalize(self, source_provider: str, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        """Normalize a raw event using the registered mapper.

        If no mapper is registered for the source_provider, returns a base
        OCSFBaseEvent with the raw event stored and normalized left empty.
        """
        mapper = self.get(source_provider)
        if mapper is None:
            logger.warning(
                "ocsf_no_mapper_for_provider",
                source_provider=source_provider,
            )
            return OCSFBaseEvent(
                source_provider=source_provider,
                source_type="unknown",
                raw_event=raw_event,
                normalized={},
            )
        try:
            return mapper.map(raw_event)
        except Exception:
            logger.exception(
                "ocsf_mapper_error",
                source_provider=source_provider,
            )
            return OCSFBaseEvent(
                source_provider=source_provider,
                source_type="mapper_error",
                raw_event=raw_event,
                normalized={},
            )


# ---------------------------------------------------------------------------
# Default global registry — auto-populated with built-in mappers
# ---------------------------------------------------------------------------

_default_registry: MapperRegistry | None = None


def _get_default_registry() -> MapperRegistry:
    """Lazily build and return the default global registry."""
    global _default_registry  # noqa: PLW0603
    if _default_registry is not None:
        return _default_registry

    from shieldops.ingestion.ocsf.mappers.azure_activity import AzureActivityMapper
    from shieldops.ingestion.ocsf.mappers.cloudtrail import CloudTrailMapper
    from shieldops.ingestion.ocsf.mappers.crowdstrike import CrowdStrikeMapper
    from shieldops.ingestion.ocsf.mappers.guardduty import GuardDutyMapper
    from shieldops.ingestion.ocsf.mappers.syslog import SyslogMapper
    from shieldops.ingestion.ocsf.mappers.vpc_flow import VPCFlowMapper

    registry = MapperRegistry()
    registry.register("cloudtrail", CloudTrailMapper())
    registry.register("crowdstrike", CrowdStrikeMapper())
    registry.register("guardduty", GuardDutyMapper())
    registry.register("vpc_flow", VPCFlowMapper())
    registry.register("azure_activity", AzureActivityMapper())
    registry.register("syslog", SyslogMapper())

    _default_registry = registry
    return _default_registry


def normalize(source_provider: str, raw_event: dict[str, Any]) -> OCSFBaseEvent:
    """Normalize a raw vendor event to OCSF using the default registry.

    This is the main entry point for the OCSF normalization engine.

    Args:
        source_provider: Vendor identifier (e.g. "cloudtrail", "crowdstrike").
        raw_event: Raw event dict from the vendor.

    Returns:
        An OCSF-normalized event model.
    """
    registry = _get_default_registry()
    return registry.normalize(source_provider, raw_event)
