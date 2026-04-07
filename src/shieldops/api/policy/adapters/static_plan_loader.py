"""Static plan loader — canned plan + usage dict for tests.

Implements :class:`shieldops.api.policy.ports.PlanLoader`. Production
loads plans from the DB via ``DbPlanLoader`` or from settings via
``SettingsPlanLoader`` — both land in PR-2.
"""

from __future__ import annotations

from shieldops.api.policy.types import Plan


class StaticPlanLoader:
    """Pre-seeded plan + usage data. Test-only.

    Usage::

        plans = StaticPlanLoader(
            plans={"org-a": Plan(tier="free", rps=5, burst=5, quotas={"agents": 10})},
            default=Plan(tier="starter", rps=10, burst=20),
        )
        plans.set_usage("org-a", "agents", 9)
    """

    def __init__(
        self,
        plans: dict[str, Plan] | None = None,
        *,
        default: Plan | None = None,
    ) -> None:
        self._plans: dict[str, Plan] = dict(plans or {})
        self._default = default or Plan(tier="starter", rps=10.0, burst=20)
        self._usage: dict[tuple[str, str], int] = {}

    async def load(self, org_id: str) -> Plan:
        return self._plans.get(org_id, self._default)

    async def get_usage(self, org_id: str, quota_name: str) -> int:
        return self._usage.get((org_id, quota_name), 0)

    # -- Test helpers ------------------------------------------------------

    def set_plan(self, org_id: str, plan: Plan) -> None:
        self._plans[org_id] = plan

    def set_usage(self, org_id: str, quota_name: str, value: int) -> None:
        self._usage[(org_id, quota_name)] = value
