"""Sub-configuration models for decomposed Settings.

Only ``EnginesConfig`` is re-exported from this package. The other 15
non-engines sub-configs were inlined into
``src/shieldops/config/settings.py`` in RFC #241 PR-3 (#251) since nothing
outside ``settings.py`` imported them directly. ``EnginesConfig`` is kept
as its own module pending its Phase 3 decomposition PR.
"""

from shieldops.config.sub.engines import EnginesConfig

__all__ = ["EnginesConfig"]
