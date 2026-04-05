"""CrewAI crew with ShieldOps audit trail.

Demonstrates wrapping a CrewAI crew with ShieldOps governance
for multi-agent orchestration security monitoring.
"""

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.crewai import ShieldOpsCrewAIWrapper

# Configure ShieldOps SDK in audit mode (observe, don't block)
config = SDKConfig(api_key="sk-demo-key", mode=SDKMode.AUDIT, agent_id="crewai-demo")

# Wrap your CrewAI crew:
#
#   from crewai import Crew, Agent, Task
#   crew = Crew(agents=[researcher, writer], tasks=[research_task, write_task])
#
#   # Add ShieldOps governance — one line:
#   secured_crew = ShieldOpsCrewAIWrapper(crew, config=config)
#
#   # Run as normal — all agent actions are now audited
#   result = secured_crew.kickoff()

wrapper = ShieldOpsCrewAIWrapper.__new__(ShieldOpsCrewAIWrapper)
print("ShieldOps CrewAI integration ready!")
print(f"Mode: {config.mode}")
print("Wrap your crew: ShieldOpsCrewAIWrapper(crew, config=config)")
