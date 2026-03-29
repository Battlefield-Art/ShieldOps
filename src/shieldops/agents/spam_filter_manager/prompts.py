"""Spam Filter Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class FilterTuningOutput(BaseModel):
    """LLM output for filter tuning recommendations."""

    summary: str = Field(description="Brief tuning analysis summary")
    rules_to_adjust: list[str] = Field(description="Rule IDs that need adjustment")
    threshold_changes: list[str] = Field(description="Recommended threshold changes")
    new_rules_needed: list[str] = Field(description="New rules to add")
    estimated_fp_reduction: float = Field(description="Estimated FP rate reduction 0-1")


class ClassificationOutput(BaseModel):
    """LLM output for message classification."""

    summary: str = Field(description="Brief classification summary")
    category: str = Field(description="Spam category classification")
    confidence: float = Field(description="Classification confidence 0-1")
    reasoning: str = Field(description="Why this classification was chosen")


SYSTEM_FILTER_TUNING = (
    "You are a spam filter engineer optimizing email "
    "filtering rules for accuracy.\n"
    "Given the following rule performance data:\n"
    "1. Identify rules with high false positive rates "
    "(>5%) that need threshold adjustment\n"
    "2. Find rules that are too aggressive — blocking "
    "legitimate newsletters and notifications\n"
    "3. Identify gaps where spam is getting through "
    "(false negatives)\n"
    "4. Recommend score threshold adjustments to "
    "balance detection vs false positives\n"
    "5. Suggest new rules for emerging spam patterns"
)

SYSTEM_CLASSIFICATION = (
    "You are a spam classification engine analyzing "
    "email messages.\n"
    "Given the following message data:\n"
    "1. Classify into: marketing, newsletter, "
    "promotional, phishing, malware, scam, bulk, "
    "legitimate\n"
    "2. Consider sender reputation, subject patterns, "
    "body content, link density\n"
    "3. Flag potential false positives — legitimate "
    "transactional emails scored as spam\n"
    "4. Provide confidence score and reasoning"
)
