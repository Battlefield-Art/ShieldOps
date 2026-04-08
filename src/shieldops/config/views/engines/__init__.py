"""Views over the engines config — decomposed from sub/engines.py (RFC #241 PR-6 / #254).

Each sub-module exposes a read-only projection over a category of fields. The
underlying ``EnginesConfig`` model still holds the data (or, for fields that
have been deleted from the monolith, falls back to ``FlatSettings`` defaults
via its own ``__getattr__``). The views exist so that downstream tooling
(reports, validators, mock fixtures) can iterate over a coherent slice of
config without grepping the 1,820-LOC monolith.
"""

from shieldops.config.views.engines.enabled_flags import EnginesEnabledFlagsView
from shieldops.config.views.engines.retention import EnginesRetentionView
from shieldops.config.views.engines.thresholds import EnginesThresholdsView

__all__ = [
    "EnginesEnabledFlagsView",
    "EnginesRetentionView",
    "EnginesThresholdsView",
]
