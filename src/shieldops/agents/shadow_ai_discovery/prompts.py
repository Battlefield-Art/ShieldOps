"""Shadow AI Discovery Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class TrafficAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted traffic pattern analysis."""

    summary: str = Field(description="Brief summary of traffic analysis findings")
    llm_traffic_count: int = Field(description="Number of LLM-related traffic patterns")
    mcp_traffic_count: int = Field(description="Number of MCP server connections detected")
    vector_db_count: int = Field(description="Number of vector database connections detected")
    suspicious_patterns: list[str] = Field(
        description="Traffic patterns flagged as suspicious or unusual"
    )
    confidence: float = Field(description="Confidence in traffic classification 0.0-1.0")


class AssetClassificationOutput(BaseModel):
    """Structured output from LLM-assisted asset classification."""

    summary: str = Field(description="Brief summary of asset classification")
    total_assets: int = Field(description="Total number of AI assets discovered")
    unmanaged_count: int = Field(description="Number of unmanaged assets found")
    shadow_count: int = Field(description="Number of shadow AI assets found")
    rogue_count: int = Field(description="Number of rogue AI assets found")
    asset_insights: list[str] = Field(description="Key insights about discovered assets")
    department_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description="Asset count by department",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output from LLM-assisted risk assessment."""

    summary: str = Field(description="Brief risk assessment summary")
    overall_risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    critical_assets: list[str] = Field(description="Asset IDs that require immediate attention")
    data_exposure_risks: list[str] = Field(
        description="Identified data exposure risks from shadow AI"
    )
    cost_exposure: float = Field(description="Estimated total monthly cost of unmanaged AI usage")
    recommended_priorities: list[str] = Field(
        description="Prioritized list of risk mitigation actions"
    )


class GovernanceOutput(BaseModel):
    """Structured output from LLM-assisted governance planning."""

    summary: str = Field(description="Brief governance plan summary")
    block_count: int = Field(description="Number of assets to block immediately")
    review_count: int = Field(description="Number of assets requiring review")
    onboard_count: int = Field(description="Number of assets to onboard")
    policy_gaps: list[str] = Field(description="Identified gaps in current AI governance policies")
    quick_wins: list[str] = Field(description="Low-effort actions with high security impact")
    long_term_recommendations: list[str] = Field(
        description="Strategic recommendations for AI governance maturity"
    )


SYSTEM_TRAFFIC_ANALYSIS = (
    "You are a network security analyst specializing in AI/ML traffic detection.\n"
    "Analyze the following network traffic patterns to identify AI-related services:\n"
    "1. Identify traffic to known LLM providers (OpenAI, Anthropic, HuggingFace, "
    "Google, AWS Bedrock)\n"
    "2. Detect local LLM deployments (Ollama, vLLM, text-generation-webui)\n"
    "3. Identify MCP server connections (JSON-RPC, stdio-based transport)\n"
    "4. Detect vector database traffic (Pinecone, Weaviate, Qdrant, Chroma, Milvus)\n"
    "5. Flag suspicious patterns: unencrypted LLM traffic, unusual payload sizes, "
    "off-hours usage spikes\n"
    "6. Estimate the scope of unmonitored AI usage across the enterprise"
)

SYSTEM_ASSET_CLASSIFICATION = (
    "You are an AI asset management specialist.\n"
    "Classify the following discovered AI assets into governance categories:\n"
    "1. Determine asset type: LLM API client, MCP server, RAG pipeline, "
    "fine-tuned model, AI agent, embedding service, or vector database\n"
    "2. Identify the model provider and assess vendor risk\n"
    "3. Classify governance status: managed, unmanaged, shadow, or rogue\n"
    "4. Estimate data sensitivity based on traffic patterns and endpoint types\n"
    "5. Map assets to departments based on source IPs and usage patterns\n"
    "6. Identify AI supply chain risks from third-party model dependencies"
)

SYSTEM_RISK_ASSESSMENT = (
    "You are a risk analyst specializing in AI security and governance.\n"
    "Assess the risk posed by discovered shadow AI assets:\n"
    "1. Evaluate data exposure risk — what sensitive data might be sent to "
    "unmanaged LLMs\n"
    "2. Assess compliance risk — GDPR, HIPAA, SOC2 implications of "
    "unmonitored AI usage\n"
    "3. Calculate cost exposure — total unmanaged AI spend and budget risk\n"
    "4. Evaluate security risk — prompt injection, model poisoning, "
    "exfiltration via AI channels\n"
    "5. Assess vendor lock-in risk from undocumented AI dependencies\n"
    "6. Prioritize assets by blast radius and likelihood of incident"
)

SYSTEM_GOVERNANCE_PLANNING = (
    "You are an AI governance architect for enterprise environments.\n"
    "Create a governance plan for discovered shadow AI assets:\n"
    "1. For critical-risk assets: recommend immediate blocking or quarantine\n"
    "2. For high-risk assets: recommend review, owner assignment, and "
    "policy enforcement\n"
    "3. For medium-risk assets: recommend registration and monitoring onboarding\n"
    "4. Identify policy gaps that allowed shadow AI to proliferate\n"
    "5. Recommend quick wins — low-effort actions with high security impact\n"
    "6. Propose long-term governance maturity improvements: AI asset inventory, "
    "automated discovery, approval workflows, cost attribution"
)
