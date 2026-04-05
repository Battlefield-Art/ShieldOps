"""Standalone ShieldOps SDK usage — no framework needed.

Demonstrates direct tool call interception, risk scoring,
and audit reporting without any AI framework dependency.
"""

import asyncio

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.interceptor import ShieldOpsInterceptor


async def main() -> None:
    # Configure SDK in enforce mode
    config = SDKConfig(api_key="sk-demo-key", mode=SDKMode.ENFORCE, agent_id="demo-agent")

    async with ShieldOpsInterceptor(config) as shield:
        # 1. Safe tool call — allowed
        result = shield.intercept("read_file", {"path": "/var/log/syslog"})
        print(f"read_file: decision={result.decision}, risk={result.risk_score:.2f}")

        # 2. High-risk tool call — audited but allowed
        result = shield.intercept("execute_command", {"cmd": "ps aux"})
        print(f"execute_command: decision={result.decision}, risk={result.risk_score:.2f}")

        # 3. Dangerous tool call — BLOCKED in enforce mode
        result = shield.intercept("drop_table", {"table": "users"})
        print(f"drop_table: decision={result.decision}, risk={result.risk_score:.2f}")
        if result.decision == "block":
            print(f"  Blocked! Reasons: {result.reasons}")

        # 4. Production environment increases risk
        result = shield.intercept("modify_security_group", {"env": "production", "action": "open"})
        print(f"modify_security_group: decision={result.decision}, risk={result.risk_score:.2f}")

        # 5. View audit report
        report = shield.get_audit_report()
        print("\nAudit Report:")
        print(f"  Total calls: {report['total_events']}")
        print(f"  Blocked: {report['total_blocks']}")
        print(f"  Mode: {report['mode']}")


if __name__ == "__main__":
    asyncio.run(main())
