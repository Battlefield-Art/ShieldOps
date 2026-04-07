"""Test authenticator — static token → Principal mapping.

Satisfies :class:`shieldops.api.ws.core.ports.Authenticator`. Used by
contract tests to avoid constructing a real JWT validator. The
production adapter (``JwtAuthenticator``) lands in PR-2.
"""

from __future__ import annotations

from shieldops.api.ws.core.events import Principal


class StaticTokenAuthenticator:
    """Authenticator that resolves tokens from a pre-seeded dict.

    Usage::

        auth = StaticTokenAuthenticator({
            "t1": Principal(tenant_id="org-a", user_id="u1"),
            "t2": Principal(tenant_id="org-b", user_id="u2"),
        })
    """

    def __init__(
        self,
        tokens: dict[str, Principal],
        *,
        allowed_channels: dict[str, set[str]] | None = None,
    ) -> None:
        self._tokens = dict(tokens)
        # Optional per-token channel allowlist for tests that want to
        # exercise "this token can subscribe to investigation:* but not
        # admin:*" kinds of semantics.
        self._allowed = allowed_channels or {}

    async def authenticate(self, token: str, channel: str) -> Principal:
        if token not in self._tokens:
            raise PermissionError(f"unknown token: {token!r}")
        principal = self._tokens[token]
        allowed = self._allowed.get(token)
        if allowed is not None and channel not in allowed:
            raise PermissionError(f"token {token!r} not authorized for channel {channel!r}")
        return principal
