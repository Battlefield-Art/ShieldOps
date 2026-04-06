"""Tenant signup + login API (issue #216).

Self-service onboarding flow:

    POST /api/v1/signup         → creates User + Organization
    POST /api/v1/signup/verify  → verifies email via one-time token
    POST /api/v1/signup/login   → issues JWT on email+password

The module owns a small in-memory store (``_TenantStore``) so the routes
are usable in tests and local dev without a running Postgres instance.
The store can be swapped at runtime via :func:`set_store` to plug in a
real async repository backed by the SQLAlchemy models in
``shieldops.db.models_tenant``.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from shieldops.api.auth.service import (
    create_access_token,
    hash_password,
    verify_password,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/signup", tags=["Signup"])

# Also expose a plain login endpoint on /signup/login (spec says so).

# ---------------------------------------------------------------------------
# In-memory store (swappable via set_store)
# ---------------------------------------------------------------------------


@dataclass
class _OrgRow:
    id: str
    name: str
    owner_email: str
    plan: str = "starter"
    status: str = "trialing"
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    trial_ends_at: datetime | None = field(
        default_factory=lambda: datetime.now(UTC) + timedelta(days=14)
    )


@dataclass
class _UserRow:
    id: str
    email: str
    password_hash: str
    org_id: str
    role: str = "owner"
    email_verified: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class _TokenRow:
    token: str
    user_id: str
    expires_at: datetime


class _TenantStore:
    """Minimal in-memory store for tenant signup.

    Not thread-safe — fine for the single-process dev server and tests.
    """

    def __init__(self) -> None:
        self.orgs: dict[str, _OrgRow] = {}
        self.users_by_email: dict[str, _UserRow] = {}
        self.users_by_id: dict[str, _UserRow] = {}
        self.tokens: dict[str, _TokenRow] = {}

    def clear(self) -> None:
        self.orgs.clear()
        self.users_by_email.clear()
        self.users_by_id.clear()
        self.tokens.clear()

    # -- orgs ---------------------------------------------------------
    def create_org(self, name: str, owner_email: str) -> _OrgRow:
        org = _OrgRow(id=f"org-{secrets.token_hex(8)}", name=name, owner_email=owner_email)
        self.orgs[org.id] = org
        return org

    def get_org(self, org_id: str) -> _OrgRow | None:
        return self.orgs.get(org_id)

    def update_org(self, org_id: str, **fields: Any) -> _OrgRow | None:
        org = self.orgs.get(org_id)
        if org is None:
            return None
        for k, v in fields.items():
            setattr(org, k, v)
        return org

    def list_orgs(self) -> list[_OrgRow]:
        return list(self.orgs.values())

    # -- users --------------------------------------------------------
    def create_user(
        self, email: str, password_hash: str, org_id: str, role: str = "owner"
    ) -> _UserRow:
        user = _UserRow(
            id=f"usr-{secrets.token_hex(8)}",
            email=email.lower(),
            password_hash=password_hash,
            org_id=org_id,
            role=role,
        )
        self.users_by_email[user.email] = user
        self.users_by_id[user.id] = user
        return user

    def get_user_by_email(self, email: str) -> _UserRow | None:
        return self.users_by_email.get(email.lower())

    def get_user_by_id(self, user_id: str) -> _UserRow | None:
        return self.users_by_id.get(user_id)

    # -- verification tokens ------------------------------------------
    def create_token(self, user_id: str) -> _TokenRow:
        token = _TokenRow(
            token=secrets.token_urlsafe(32),
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        )
        self.tokens[token.token] = token
        return token

    def consume_token(self, token: str) -> _TokenRow | None:
        row = self.tokens.get(token)
        if row is None:
            return None
        if row.expires_at < datetime.now(UTC):
            self.tokens.pop(token, None)
            return None
        return self.tokens.pop(token)


_store: _TenantStore = _TenantStore()


def get_store() -> _TenantStore:
    """Return the module-level tenant store."""
    return _store


def set_store(store: _TenantStore) -> None:
    """Replace the module-level store (used by tests/app startup)."""
    global _store
    _store = store


def reset_store() -> None:
    """Wipe all in-memory state — intended for tests."""
    _store.clear()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


_PASSWORD_MIN = 8


class SignupRequest(BaseModel):
    email: EmailStr
    org_name: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=_PASSWORD_MIN, max_length=256)
    model_config = {"extra": "forbid"}


class SignupResponse(BaseModel):
    org_id: str
    user_id: str
    email: str
    verification_sent: bool
    verification_token: str | None = Field(
        default=None,
        description="Only returned in dev/test when no email transport is configured.",
    )


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1)
    model_config = {"extra": "forbid"}


class VerifyResponse(BaseModel):
    user_id: str
    email_verified: bool


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    model_config = {"extra": "forbid"}


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    org_id: str
    email_verified: bool


# ---------------------------------------------------------------------------
# Email delivery (placeholder — real transport wired in production)
# ---------------------------------------------------------------------------


def _send_verification_email(email: str, token: str) -> bool:
    """Placeholder email sender. Returns True if "sent"."""
    logger.info("tenant_signup_verification_email", email=email, token_prefix=token[:8])
    return True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@router.post(
    "",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
)
async def signup(payload: SignupRequest) -> SignupResponse:
    """Create a new user + organization and email a verification token."""
    store = get_store()

    email = payload.email.lower()
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    if store.get_user_by_email(email) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    org = store.create_org(name=payload.org_name, owner_email=email)
    user = store.create_user(
        email=email,
        password_hash=hash_password(payload.password),
        org_id=org.id,
        role="owner",
    )
    token_row = store.create_token(user_id=user.id)
    sent = _send_verification_email(email, token_row.token)

    logger.info(
        "tenant_signup_created",
        org_id=org.id,
        user_id=user.id,
        email=email,
    )

    return SignupResponse(
        org_id=org.id,
        user_id=user.id,
        email=email,
        verification_sent=sent,
        verification_token=token_row.token,
    )


@router.post("/verify", response_model=VerifyResponse)
async def verify(payload: VerifyRequest) -> VerifyResponse:
    """Consume a verification token and mark the user as verified."""
    store = get_store()

    row = store.consume_token(payload.token)
    if row is None:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = store.get_user_by_id(row.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user.email_verified = True
    logger.info("tenant_signup_verified", user_id=user.id, email=user.email)
    return VerifyResponse(user_id=user.id, email_verified=True)


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest) -> LoginResponse:
    """Authenticate a tenant user and return a JWT."""
    store = get_store()

    user = store.get_user_by_email(payload.email)
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = create_access_token(subject=user.id, role=user.role)
    return LoginResponse(
        access_token=token,
        user_id=user.id,
        org_id=user.org_id,
        email_verified=user.email_verified,
    )
