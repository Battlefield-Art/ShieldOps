"""Event validation for the ingestion pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any

VALID_SOURCES = frozenset({"cloudtrail", "crowdstrike_fdr", "syslog", "webhook", "custom"})


def validate_event(event: dict[str, Any]) -> list[str]:
    """Validate a single ingestion event and return a list of error strings.

    An empty list means the event is valid.
    """
    errors: list[str] = []

    # source is required and must be from the allowed set
    source = event.get("source", "")
    if not source:
        errors.append("missing required field: source")
    elif source not in VALID_SOURCES:
        errors.append(
            f"invalid source '{source}'; must be one of: {', '.join(sorted(VALID_SOURCES))}"
        )

    # raw_event must be a non-empty dict
    raw_event = event.get("raw_event")
    if not isinstance(raw_event, dict) or len(raw_event) == 0:
        errors.append("raw_event must be a non-empty dict")

    # timestamp (optional but must parse if provided)
    ts = event.get("timestamp", "")
    if ts:
        try:
            datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            errors.append(f"timestamp '{ts}' is not valid ISO 8601")

    return errors
