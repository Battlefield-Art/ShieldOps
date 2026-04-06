"""License JWT signing utilities.

Production license issuance uses RS256 with an externally-managed private
key. Tests may use HS256 with a shared secret.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import jwt

from shieldops.licensing.models import LicenseTier

DEFAULT_ALGORITHM = "RS256"
HS_ALGORITHM = "HS256"


def sign_license(
    *,
    org_id: str,
    tier: str | LicenseTier,
    expires_at: datetime,
    issued_at: datetime | None = None,
    agent_limit: int | None = None,
    metadata: dict[str, Any] | None = None,
    private_key: str | None = None,
    hmac_secret: str | None = None,
    algorithm: str = DEFAULT_ALGORITHM,
) -> str:
    """Create a signed ShieldOps license JWT.

    Either ``private_key`` (RS256) or ``hmac_secret`` (HS256) must be given.
    """
    if private_key is None and hmac_secret is None:
        raise ValueError("private_key or hmac_secret required")

    tier_value = tier.value if isinstance(tier, LicenseTier) else str(tier).lower()
    limit = agent_limit if agent_limit is not None else LicenseTier.agent_limit(tier_value)
    now = issued_at or datetime.now(UTC)

    payload: dict[str, Any] = {
        "org_id": org_id,
        "tier": tier_value,
        "agent_limit": limit,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "issued_at": now.astimezone(UTC).isoformat(),
        "expires_at": expires_at.astimezone(UTC).isoformat(),
        "metadata": metadata or {},
        "iss": "shieldops-license-server",
    }

    key = private_key or hmac_secret
    alg = algorithm if private_key else HS_ALGORITHM
    token = jwt.encode(payload, key, algorithm=alg)
    if isinstance(token, bytes):  # pragma: no cover — PyJWT<2 compat
        token = token.decode("utf-8")
    return token
