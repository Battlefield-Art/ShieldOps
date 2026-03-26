"""Supply Chain Scanner Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class RegistryAnalysisResult(BaseModel):
    """LLM output for model registry scan analysis."""

    summary: str = Field(description="Brief summary of registry findings")
    backdoor_indicators: int = Field(description="Count of potential backdoor indicators")
    tampered_models: list[str] = Field(description="Model names with tampering evidence")
    risk_level: str = Field(description="Overall risk: low, medium, high, critical")
    recommended_actions: list[str] = Field(description="Prioritized remediation actions")


class RAGPoisoningResult(BaseModel):
    """LLM output for RAG source poisoning analysis."""

    summary: str = Field(description="Brief summary of RAG poisoning findings")
    poisoned_sources: int = Field(description="Count of poisoned data sources")
    adversarial_patterns: list[str] = Field(description="Adversarial patterns detected")
    risk_level: str = Field(description="Overall risk: low, medium, high, critical")
    mitigation_steps: list[str] = Field(description="Steps to mitigate poisoning")


class ToolHijackResult(BaseModel):
    """LLM output for tool definition hijacking analysis."""

    summary: str = Field(description="Brief summary of tool audit findings")
    hijacked_tools: list[str] = Field(description="Tool names with hijack indicators")
    exfiltration_risks: int = Field(description="Count of exfiltration-capable tools")
    risk_level: str = Field(description="Overall risk: low, medium, high, critical")
    hardening_steps: list[str] = Field(description="Steps to harden tool definitions")


class SupplyChainScanResult(BaseModel):
    """LLM output for overall supply chain scan assessment."""

    summary: str = Field(description="Brief overall supply chain scan summary")
    risk_score: float = Field(description="Composite risk score 0.0-1.0")
    risk_level: str = Field(description="Overall risk: low, medium, high, critical")
    top_threats: list[str] = Field(description="Top AI supply chain threats identified")
    mitigation_plan: list[str] = Field(description="Prioritized mitigation steps")


SYSTEM_REGISTRY_ANALYSIS = (
    "You are an AI supply chain security analyst "
    "specializing in model registry integrity.\n"
    "Analyze the model registry scan results:\n"
    "1. Check for checksum mismatches indicating "
    "weight file tampering\n"
    "2. Verify provenance — was the model trained "
    "by a trusted pipeline?\n"
    "3. Detect backdoor indicators: unusual weight "
    "distributions, trigger patterns\n"
    "4. Assess signature validity and trust chain\n"
    "5. Flag models from untrusted or unverified "
    "sources"
)

SYSTEM_RAG_POISONING = (
    "You are an AI security analyst specializing in "
    "RAG pipeline integrity.\n"
    "Analyze the RAG source scan results:\n"
    "1. Detect data poisoning: adversarial documents "
    "designed to manipulate retrieval\n"
    "2. Identify adversarial embeddings that shift "
    "retrieval toward attacker content\n"
    "3. Check for injection payloads hidden in "
    "document metadata or content\n"
    "4. Assess document provenance and freshness\n"
    "5. Flag sources with anomalous similarity "
    "distributions"
)

SYSTEM_TOOL_HIJACK = (
    "You are an AI agent security analyst "
    "specializing in tool definition integrity.\n"
    "Analyze the tool definition audit results:\n"
    "1. Detect hijacked tools: endpoints redirected "
    "to attacker infrastructure\n"
    "2. Check for unauthorized scope expansion "
    "beyond declared capabilities\n"
    "3. Identify exfiltration-capable tools that "
    "can leak data to external endpoints\n"
    "4. Verify tool schemas match expected signatures\n"
    "5. Flag tools with excessive permissions or "
    "missing access controls"
)

SYSTEM_SCAN_ASSESSMENT = (
    "You are an AI supply chain risk analyst "
    "assessing overall AI asset integrity.\n"
    "Given model registry, RAG source, prompt "
    "template, and tool definition scan results:\n"
    "1. Compute composite risk weighing all "
    "threat categories\n"
    "2. Identify the most critical supply chain "
    "attack vector\n"
    "3. Map findings to MITRE ATLAS and OWASP "
    "LLM Top 10 frameworks\n"
    "4. Produce a prioritized mitigation plan\n"
    "5. Flag indicators of active AI supply "
    "chain compromise"
)
