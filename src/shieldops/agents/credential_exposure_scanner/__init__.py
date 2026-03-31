"""Credential Exposure Scanner Agent — credential leak detection."""

from shieldops.agents.credential_exposure_scanner.graph import (
    create_credential_exposure_scanner_graph,
)

__all__ = ["create_credential_exposure_scanner_graph"]
