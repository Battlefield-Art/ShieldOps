"""Config package — exposes the singleton ``settings`` (FlatSettings).

RFC #241 PR-5 (#253): the legacy nested ``Settings`` class in
``settings.py`` (with its ``_FLAT_TO_NESTED`` registry, validator, and
``__getattr__`` shim) is deleted. The singleton now points directly at
:class:`FlatSettings`, which uses pydantic-settings natively for env var
binding — no validator footgun, no routing dict drift.

The public alias ``Settings = FlatSettings`` is preserved so existing
``from shieldops.config import Settings`` callers continue to work.
"""

from __future__ import annotations

from shieldops.config.flat import FlatSettings

# Public alias — keep ``Settings`` as a name so callers that import it
# as a type annotation (connectors, observability factory, remediation)
# don't have to change.
Settings = FlatSettings

# Module-level singleton — every consumer reads via ``from shieldops.config
# import settings``.
settings: FlatSettings = FlatSettings()

__all__ = ["FlatSettings", "Settings", "settings"]
