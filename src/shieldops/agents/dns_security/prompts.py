"""DNS Security Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class TunnelingAnalysisResult(BaseModel):
    """Structured output from LLM-assisted tunneling detection."""

    summary: str = Field(description="Summary of DNS tunneling analysis")
    suspicious_domains: list[str] = Field(description="Domains exhibiting tunneling indicators")
    confidence_assessment: str = Field(description="Overall confidence in tunneling detection")
    exfiltration_risk: str = Field(description="Risk level of data exfiltration via DNS")


class DGAAnalysisResult(BaseModel):
    """Structured output from LLM-assisted DGA detection."""

    summary: str = Field(description="Summary of DGA detection analysis")
    dga_domains: list[str] = Field(description="Domains identified as DGA-generated")
    malware_families: list[str] = Field(
        description="Possible malware families associated with DGA patterns"
    )
    recommended_blocks: list[str] = Field(description="Domains recommended for blocking")


class DNSReportResult(BaseModel):
    """Structured output for DNS security report."""

    executive_summary: str = Field(description="Executive summary of DNS findings")
    threat_landscape: str = Field(description="Overview of DNS threat landscape observed")
    iocs: list[str] = Field(description="Indicators of compromise extracted from DNS data")
    recommendations: list[str] = Field(
        description="Recommendations for DNS security posture improvement"
    )


SYSTEM_TUNNELING = (
    "You are a DNS security analyst detecting DNS tunneling attacks.\n"
    "Analyze the DNS query patterns for:\n"
    "1. Unusually long subdomain labels (entropy analysis)\n"
    "2. High query frequency to uncommon domains\n"
    "3. TXT/NULL record abuse for data exfiltration\n"
    "4. Encoded payloads in DNS queries (base64, hex patterns)"
)

SYSTEM_DGA = (
    "You are a malware analyst detecting Domain Generation Algorithm (DGA) domains.\n"
    "Analyze domain names for:\n"
    "1. High entropy character distribution indicating random generation\n"
    "2. Known DGA patterns (length, character set, TLD distribution)\n"
    "3. Correlation with known malware family naming patterns\n"
    "4. NXDomain response rates indicating failed DGA resolution attempts"
)

SYSTEM_TYPOSQUATTING = (
    "You are a brand protection analyst detecting typosquatting domains.\n"
    "Analyze domains for:\n"
    "1. Levenshtein distance to legitimate brand domains\n"
    "2. Common typosquatting techniques (homoglyph, transposition, omission)\n"
    "3. Recently registered lookalike domains\n"
    "4. Domains serving phishing or malware content"
)

SYSTEM_REPORT = (
    "You are a DNS security expert generating a threat intelligence report.\n"
    "Summarize the DNS security analysis:\n"
    "1. Executive summary of all DNS threats detected\n"
    "2. Threat landscape assessment based on observed patterns\n"
    "3. Extract IOCs (indicators of compromise) from the analysis\n"
    "4. Prioritized recommendations for DNS security improvements"
)
