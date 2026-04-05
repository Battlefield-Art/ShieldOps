"""Custom ShieldOps policies — define your own block/allow rules.

Demonstrates extending the default ShieldOps interceptor
with organization-specific tool governance policies.
"""

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.interceptor import ShieldOpsInterceptor


class CustomPolicyInterceptor(ShieldOpsInterceptor):
    """Extended interceptor with custom organization policies."""

    # Additional tools to block (beyond defaults)
    CUSTOM_BLOCKED = {"send_email_blast", "export_all_users", "bypass_auth"}

    # Tools that require extra scrutiny
    CUSTOM_HIGH_RISK = {"modify_billing", "change_subscription", "grant_admin"}

    def intercept(self, tool_name, args=None, agent_id=None):
        # Check custom blocked list first
        if tool_name.lower() in self.CUSTOM_BLOCKED:
            from shieldops.sdk.interceptor import InterceptResult

            return InterceptResult(
                decision="block" if self._config.is_enforce else "allow",
                risk_score=1.0,
                reasons=[f"Custom policy: {tool_name} is blocked by organization policy"],
            )

        # Check custom high-risk list
        result = super().intercept(tool_name, args, agent_id)

        if tool_name.lower() in self.CUSTOM_HIGH_RISK:
            # Elevate risk score for custom high-risk tools
            result.risk_score = max(result.risk_score, 0.8)
            result.reasons.append(f"Custom policy: {tool_name} is high-risk")

        return result


# Usage
config = SDKConfig(api_key="sk-demo-key", mode=SDKMode.ENFORCE, agent_id="custom-policy-demo")
interceptor = CustomPolicyInterceptor(config)

# Test custom policies
print("=== Custom Policy Demo ===\n")

# 1. Default blocked tool
result = interceptor.intercept("drop_table", {"table": "users"})
print(f"drop_table: {result.decision} (risk: {result.risk_score:.1f}) — default policy")

# 2. Custom blocked tool
result = interceptor.intercept("send_email_blast", {"recipients": "all"})
print(f"send_email_blast: {result.decision} (risk: {result.risk_score:.1f}) — custom policy")

# 3. Custom high-risk tool
result = interceptor.intercept("modify_billing", {"plan": "enterprise"})
print(f"modify_billing: {result.decision} (risk: {result.risk_score:.1f}) — custom high-risk")

# 4. Normal tool — passes through
result = interceptor.intercept("read_config", {"key": "app_name"})
print(f"read_config: {result.decision} (risk: {result.risk_score:.1f}) — normal")

print(f"\nAudit: {interceptor.get_audit_report()['total_events']} events recorded")
