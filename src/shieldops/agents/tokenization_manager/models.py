"""Tokenization Manager Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TokenStage(StrEnum):
    DISCOVER_FIELDS = "discover_fields"
    GENERATE_TOKENS = "generate_tokens"
    MAP_VAULT = "map_vault"
    VALIDATE_INTEGRITY = "validate_integrity"
    ROTATE = "rotate"
    REPORT = "report"


class TokenType(StrEnum):
    FORMAT_PRESERVING = "format_preserving"
    RANDOM = "random"
    HASH_BASED = "hash_based"
    DETERMINISTIC = "deterministic"
    VAULT_BASED = "vault_based"
    REVERSIBLE = "reversible"


class VaultStatus(StrEnum):
    ACTIVE = "active"
    ROTATING = "rotating"
    DEGRADED = "degraded"
    SEALED = "sealed"
    MAINTENANCE = "maintenance"


class TokenizationManagerState(BaseModel):
    request_id: str = ""
    stage: TokenStage = TokenStage.DISCOVER_FIELDS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
