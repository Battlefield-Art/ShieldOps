"""LangChain agent with ShieldOps governance.

Demonstrates adding ShieldOps interception to a LangChain agent
via the callback handler — one line of code for full audit trail.
"""

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.langchain import ShieldOpsCallbackHandler

# Configure ShieldOps SDK
config = SDKConfig(api_key="sk-demo-key", mode=SDKMode.AUDIT, agent_id="langchain-demo")

# Create the callback handler — this is the one line you add
shieldops_handler = ShieldOpsCallbackHandler(config=config)

# Use with any LangChain agent:
#
#   from langchain.agents import initialize_agent
#   agent = initialize_agent(
#       tools=my_tools,
#       llm=my_llm,
#       callbacks=[shieldops_handler],  # <-- add this
#   )
#
# Every tool call is now intercepted:
# - Risk scored (0.0 = safe, 1.0 = dangerous)
# - Blocked if in enforce mode and risk > threshold
# - Logged to ShieldOps audit trail
# - Visible in Agent Firewall dashboard

print("ShieldOps LangChain integration ready!")
print(f"Mode: {config.mode}")
print(f"Agent ID: {config.agent_id}")
print("Add 'callbacks=[shieldops_handler]' to your agent initialization.")
