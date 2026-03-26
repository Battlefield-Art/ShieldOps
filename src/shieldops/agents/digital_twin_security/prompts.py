"""LLM prompt templates and response schemas for the Digital Twin Security Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SimulationAnalysisOutput(BaseModel):
    """Structured output for simulation result analysis."""

    critical_gaps: list[str] = Field(description="Critical security gaps discovered")
    attack_paths_viable: int = Field(description="Number of viable attack paths found")
    controls_effectiveness: float = Field(description="Overall controls effectiveness 0-1")
    summary: str = Field(description="Human-readable analysis summary")
    remediation_priorities: list[str] = Field(description="Ordered list of remediation priorities")


class PostureReportOutput(BaseModel):
    """Structured output for posture assessment report."""

    verdict: str = Field(description="Posture verdict: hardened/adequate/vulnerable/critical")
    risk_score: float = Field(description="Overall risk score 0-100")
    executive_summary: str = Field(description="Executive summary for stakeholders")
    top_findings: list[str] = Field(description="Top security findings")
    recommended_actions: list[str] = Field(description="Recommended remediation actions")


SYSTEM_ANALYZE = """\
You are an expert security analyst reviewing digital twin simulation results.

Given the simulation results from attack scenarios executed against a digital twin:
1. Identify critical security gaps where attacks succeeded
2. Assess the effectiveness of existing security controls
3. Map findings to MITRE ATT&CK techniques and kill chain stages
4. Prioritize remediation based on risk impact and exploitability

Focus on actionable findings that improve pre-deployment security posture.
Distinguish between control failures, misconfigurations, and architectural weaknesses."""


SYSTEM_REPORT = """\
You are a senior security architect generating a posture assessment report.

Given the full simulation analysis from digital twin security testing:
1. Determine the overall security posture verdict (hardened/adequate/vulnerable/critical)
2. Calculate a risk score considering attack success rate, severity, and blast radius
3. Write an executive summary suitable for CISO-level stakeholders
4. List the top findings ordered by business impact
5. Recommend specific, actionable remediation steps

Be precise and evidence-based. Reference specific simulation scenarios and control gaps."""
