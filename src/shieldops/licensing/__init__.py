"""ShieldOps per-agent licensing system.

Provides signed JWT license issuance, offline validation, agent-count
enforcement, grace-period handling, and optional anonymous usage telemetry.
"""

from __future__ import annotations

from shieldops.licensing.manager import (
    LicenseExpiredError,
    LicenseLimitError,
    LicenseManager,
)
from shieldops.licensing.models import License, LicenseStatus, LicenseTier
from shieldops.licensing.validator import (
    GRACE_PERIOD_DAYS,
    LicenseError,
    LicenseSignatureError,
    LicenseValidator,
)

__all__ = [
    "GRACE_PERIOD_DAYS",
    "License",
    "LicenseError",
    "LicenseExpiredError",
    "LicenseLimitError",
    "LicenseManager",
    "LicenseSignatureError",
    "LicenseStatus",
    "LicenseTier",
    "LicenseValidator",
]
