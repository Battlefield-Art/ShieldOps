"""License data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class LicenseTier(StrEnum):
    """License tier identifiers.

    Each tier maps to an ``agent_limit`` via :meth:`agent_limit`:

    - STARTER:      10 agents
    - PROFESSIONAL: 50 agents
    - ENTERPRISE:   100 agents
    - UNLIMITED:    unlimited (sentinel ``-1``)
    """

    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    UNLIMITED = "unlimited"

    @classmethod
    def agent_limit(cls, tier: LicenseTier | str) -> int:
        mapping: dict[str, int] = {
            cls.STARTER.value: 10,
            cls.PROFESSIONAL.value: 50,
            cls.ENTERPRISE.value: 100,
            cls.UNLIMITED.value: -1,
        }
        key = tier.value if isinstance(tier, cls) else str(tier).lower()
        if key not in mapping:
            raise ValueError(f"unknown license tier: {tier}")
        return mapping[key]


class LicenseStatus(StrEnum):
    """Runtime status of a license after validation."""

    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"  # <30 days until expiry
    GRACE = "grace"  # expired but within grace period
    EXPIRED = "expired"  # expired beyond grace period
    INVALID = "invalid"


class License(BaseModel):
    """A decoded ShieldOps license.

    Signature is carried for audit/debugging; validation is performed against
    the original JWT (see :class:`shieldops.licensing.LicenseValidator`).
    """

    org_id: str
    tier: str
    agent_limit: int
    issued_at: datetime
    expires_at: datetime
    signature: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}
