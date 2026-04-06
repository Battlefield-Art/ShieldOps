"""Unit tests for the ShieldOps licensing system."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shieldops.licensing import (
    GRACE_PERIOD_DAYS,
    LicenseError,
    LicenseSignatureError,
    LicenseStatus,
    LicenseTier,
    LicenseValidator,
)
from shieldops.licensing.signer import sign_license

TEST_SECRET = "test-hmac-secret-please-do-not-use-in-prod"  # noqa: S105


def _make_validator() -> LicenseValidator:
    return LicenseValidator(hmac_secret=TEST_SECRET, algorithm="HS256")


def _issue(
    *,
    tier: LicenseTier = LicenseTier.PROFESSIONAL,
    expires_in_days: float = 365.0,
    org_id: str = "acme",
    agent_limit: int | None = None,
) -> str:
    expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)
    return sign_license(
        org_id=org_id,
        tier=tier,
        expires_at=expires_at,
        agent_limit=agent_limit,
        hmac_secret=TEST_SECRET,
        algorithm="HS256",
    )


# ---------------------------------------------------------------------- #
# Signing / verification
# ---------------------------------------------------------------------- #
def test_sign_and_validate_roundtrip() -> None:
    token = _issue(tier=LicenseTier.ENTERPRISE)
    v = _make_validator()
    license = v.validate_license(token)
    assert license.org_id == "acme"
    assert license.tier == "enterprise"
    assert license.agent_limit == 100


def test_tier_agent_limits() -> None:
    assert LicenseTier.agent_limit(LicenseTier.STARTER) == 10
    assert LicenseTier.agent_limit(LicenseTier.PROFESSIONAL) == 50
    assert LicenseTier.agent_limit(LicenseTier.ENTERPRISE) == 100
    assert LicenseTier.agent_limit(LicenseTier.UNLIMITED) == -1


def test_tamper_detection_rejects_modified_jwt() -> None:
    token = _issue()
    header, payload, sig = token.split(".")
    # flip a byte in the signature
    tampered_sig = ("A" + sig[1:]) if sig[0] != "A" else ("B" + sig[1:])
    tampered = f"{header}.{payload}.{tampered_sig}"
    v = _make_validator()
    with pytest.raises(LicenseSignatureError):
        v.validate_license(tampered)


def test_invalid_token_format_raises() -> None:
    v = _make_validator()
    with pytest.raises(LicenseSignatureError):
        v.validate_license("not-a-real-jwt")


# ---------------------------------------------------------------------- #
# Agent count enforcement
# ---------------------------------------------------------------------- #
def test_agent_count_under_limit_allowed() -> None:
    token = _issue(tier=LicenseTier.STARTER)
    v = _make_validator()
    lic = v.validate_license(token)
    assert v.check_agent_count(lic, 5) is True
    assert v.check_agent_count(lic, 10) is True


def test_agent_count_over_limit_denied() -> None:
    token = _issue(tier=LicenseTier.STARTER)
    v = _make_validator()
    lic = v.validate_license(token)
    assert v.check_agent_count(lic, 11) is False


def test_unlimited_tier_always_allows() -> None:
    token = _issue(tier=LicenseTier.UNLIMITED)
    v = _make_validator()
    lic = v.validate_license(token)
    assert v.check_agent_count(lic, 100_000) is True


# ---------------------------------------------------------------------- #
# Grace period behavior
# ---------------------------------------------------------------------- #
def test_active_status_for_fresh_license() -> None:
    token = _issue(expires_in_days=365)
    v = _make_validator()
    lic = v.validate_license(token)
    assert v.status(lic) == LicenseStatus.ACTIVE


def test_expiring_soon_within_30_days() -> None:
    token = _issue(expires_in_days=10)
    v = _make_validator()
    lic = v.validate_license(token)
    assert v.status(lic) == LicenseStatus.EXPIRING_SOON


def test_grace_period_within_30_days_after_expiry_allows() -> None:
    token = _issue(expires_in_days=-5)
    v = _make_validator()
    lic = v.validate_license(token)
    assert v.status(lic) == LicenseStatus.GRACE
    # Within grace, agent count check still enforces limit but allows
    assert v.check_agent_count(lic, 5) is True


def test_expired_beyond_grace_denies() -> None:
    token = _issue(expires_in_days=-(GRACE_PERIOD_DAYS + 5))
    v = _make_validator()
    lic = v.validate_license(token)
    assert v.status(lic) == LicenseStatus.EXPIRED
    assert v.check_agent_count(lic, 1) is False


def test_grace_period_boundary_exact() -> None:
    token = _issue(expires_in_days=-GRACE_PERIOD_DAYS + 0.5)
    v = _make_validator()
    lic = v.validate_license(token)
    assert v.status(lic) == LicenseStatus.GRACE


# ---------------------------------------------------------------------- #
# Metadata + issuance
# ---------------------------------------------------------------------- #
def test_metadata_preserved() -> None:
    expires_at = datetime.now(UTC) + timedelta(days=30)
    token = sign_license(
        org_id="acme",
        tier=LicenseTier.ENTERPRISE,
        expires_at=expires_at,
        metadata={"region": "us-east", "seats": 25},
        hmac_secret=TEST_SECRET,
        algorithm="HS256",
    )
    v = _make_validator()
    lic = v.validate_license(token)
    assert lic.metadata["region"] == "us-east"
    assert lic.metadata["seats"] == 25


def test_validator_requires_key_material() -> None:
    with pytest.raises(ValueError):
        LicenseValidator()


def test_missing_required_field_raises() -> None:
    # Manually craft a JWT missing org_id
    import jwt as _jwt

    bad = _jwt.encode({"tier": "starter"}, TEST_SECRET, algorithm="HS256")
    v = _make_validator()
    with pytest.raises(LicenseError):
        v.validate_license(bad)


# ---------------------------------------------------------------------- #
# CLI license generation
# ---------------------------------------------------------------------- #
def test_cli_generate_license(monkeypatch, capsys) -> None:
    monkeypatch.setenv("LICENSE_SIGNING_KEY", TEST_SECRET)
    monkeypatch.setenv("LICENSE_SIGNING_ALGORITHM", "HS256")

    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[3] / "scripts" / "generate_license.py"
    spec = importlib.util.spec_from_file_location("generate_license", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    rc = module.main(
        [
            "--org-id",
            "acme",
            "--tier",
            "professional",
            "--expires",
            "2099-01-01",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out.count(".") == 2  # JWT has 3 segments

    # Verify roundtrip
    v = _make_validator()
    lic = v.validate_license(out)
    assert lic.org_id == "acme"
    assert lic.tier == "professional"
    assert lic.agent_limit == 50


def test_cli_missing_key_errors(monkeypatch) -> None:
    monkeypatch.delenv("LICENSE_SIGNING_KEY", raising=False)

    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[3] / "scripts" / "generate_license.py"
    spec = importlib.util.spec_from_file_location("generate_license_missing", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    rc = module.main(
        [
            "--org-id",
            "acme",
            "--tier",
            "starter",
            "--expires",
            "2099-01-01",
        ]
    )
    assert rc == 2
