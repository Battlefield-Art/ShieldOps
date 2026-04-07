"""Offline license JWT validation with grace-period support."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import structlog
from jwt.exceptions import InvalidSignatureError, InvalidTokenError

from shieldops.licensing.models import License, LicenseStatus, LicenseTier

logger = structlog.get_logger(__name__)

GRACE_PERIOD_DAYS = 30
DEFAULT_ALGORITHM = "RS256"
HS_ALGORITHM = "HS256"  # Test-only fallback

EXPIRING_SOON_DAYS = 30


class LicenseError(Exception):
    """Base licensing error.

    Single root for the licensing exception hierarchy — see RFC #244.
    ``LicenseSignatureError`` (JWT tamper) and
    ``LicenseLimitError`` / ``LicenseExpiredError`` (enforcement, in
    ``manager.py``) both subclass this single base.
    """


class LicenseSignatureError(LicenseError):
    """Raised when the JWT signature is invalid or tampered."""


class LicenseValidator:
    """Validate ShieldOps license JWTs offline.

    Parameters
    ----------
    public_key:
        RSA public key (PEM) used to verify RS256 signatures. For tests, a
        shared HMAC secret may be supplied via ``hmac_secret`` instead.
    algorithm:
        JWT algorithm (``RS256`` by default).
    hmac_secret:
        Optional HMAC secret for test-only HS256 validation. Production
        deployments should always use RS256 with an external private key.
    grace_period_days:
        Number of days beyond ``exp`` during which the license is treated as
        ``GRACE`` (warn but allow).
    """

    def __init__(
        self,
        public_key: str | None = None,
        *,
        algorithm: str = DEFAULT_ALGORITHM,
        hmac_secret: str | None = None,
        grace_period_days: int = GRACE_PERIOD_DAYS,
    ) -> None:
        if public_key is None and hmac_secret is None:
            raise ValueError("public_key or hmac_secret required")
        self._public_key = public_key
        self._hmac_secret = hmac_secret
        self._algorithm = algorithm if public_key else HS_ALGORITHM
        self._grace_period_days = grace_period_days

    # ------------------------------------------------------------------ #
    # Core validation
    # ------------------------------------------------------------------ #
    def validate_license(self, jwt_token: str) -> License:
        """Verify signature + decode payload.

        Does NOT raise on expiration — callers should use :meth:`status` to
        determine whether the license is within the grace period. Raises
        :class:`LicenseSignatureError` on tamper/invalid signature.
        """
        key = self._public_key or self._hmac_secret
        assert key is not None  # guarded in __init__
        try:
            payload: dict[str, Any] = jwt.decode(
                jwt_token,
                key,
                algorithms=[self._algorithm],
                options={"verify_exp": False},  # we handle grace period ourselves
            )
        except InvalidSignatureError as exc:
            raise LicenseSignatureError("license signature invalid") from exc
        except InvalidTokenError as exc:
            raise LicenseSignatureError(f"license token invalid: {exc}") from exc

        try:
            tier = payload["tier"]
            org_id = payload["org_id"]
            issued_at = _to_dt(payload.get("iat") or payload["issued_at"])
            expires_at = _to_dt(payload.get("exp") or payload["expires_at"])
        except KeyError as exc:
            raise LicenseError(f"license missing required field: {exc}") from exc

        agent_limit = int(payload.get("agent_limit", LicenseTier.agent_limit(tier)))

        return License(
            org_id=org_id,
            tier=tier,
            agent_limit=agent_limit,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=jwt_token.rsplit(".", 1)[-1],
            metadata=payload.get("metadata", {}),
        )

    # ------------------------------------------------------------------ #
    # Enforcement helpers
    # ------------------------------------------------------------------ #
    def status(self, license: License, *, now: datetime | None = None) -> LicenseStatus:
        """Return runtime status of a license."""
        now = now or datetime.now(UTC)
        expires_at = _ensure_utc(license.expires_at)
        if now <= expires_at:
            if expires_at - now <= timedelta(days=EXPIRING_SOON_DAYS):
                return LicenseStatus.EXPIRING_SOON
            return LicenseStatus.ACTIVE
        if now <= expires_at + timedelta(days=self._grace_period_days):
            return LicenseStatus.GRACE
        return LicenseStatus.EXPIRED

    def check_agent_count(
        self,
        license: License,
        current_agent_count: int,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Return True if execution is allowed for the current agent count.

        - Unlimited tier (agent_limit == -1) always allows when not expired.
        - Status EXPIRED (beyond grace) always denies.
        - Otherwise enforces ``current_agent_count <= agent_limit``.
        """
        stat = self.status(license, now=now)
        if stat is LicenseStatus.EXPIRED:
            logger.warning(
                "license_expired_beyond_grace",
                org_id=license.org_id,
                expires_at=license.expires_at.isoformat(),
            )
            return False
        if stat is LicenseStatus.GRACE:
            logger.warning(
                "license_in_grace_period",
                org_id=license.org_id,
                expires_at=license.expires_at.isoformat(),
            )
        if license.agent_limit < 0:
            return True
        allowed = current_agent_count <= license.agent_limit
        if not allowed:
            logger.warning(
                "license_agent_limit_exceeded",
                org_id=license.org_id,
                current=current_agent_count,
                limit=license.agent_limit,
            )
        return allowed

    def days_until_expiry(self, license: License, *, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        delta = _ensure_utc(license.expires_at) - now
        return delta.days


# ---------------------------------------------------------------------- #
# Internal helpers
# ---------------------------------------------------------------------- #
def _to_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _ensure_utc(value)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        return _ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    raise ValueError(f"cannot parse datetime from {value!r}")


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)
