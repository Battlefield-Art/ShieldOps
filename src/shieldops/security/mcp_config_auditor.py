"""MCP Config Auditor — audit MCP server configurations for security issues."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(StrEnum):
    AUTH = "auth"
    TRANSPORT = "transport"
    PERMISSIONS = "permissions"
    LOGGING = "logging"
    DATA_EXPOSURE = "data_exposure"
    CONFIGURATION = "configuration"


class AuditStatus(StrEnum):
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    WARNING = "warning"
    SKIPPED = "skipped"


# --- Models ---


class AuditFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    category: FindingCategory = FindingCategory.CONFIGURATION
    severity: FindingSeverity = FindingSeverity.MEDIUM
    description: str = ""
    remediation: str = ""
    config_path: str = ""
    timestamp: float = Field(default_factory=time.time)


class AuditRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: FindingCategory = FindingCategory.CONFIGURATION
    severity: FindingSeverity = FindingSeverity.MEDIUM
    check_field: str = ""
    expected_values: list[str] = Field(default_factory=list)
    forbidden_values: list[str] = Field(default_factory=list)
    description: str = ""


class MCPConfigAuditReport(BaseModel):
    total_audits: int = 0
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    custom_rules: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


_DEFAULT_RULES: list[AuditRule] = [
    AuditRule(
        name="auth_required",
        category=FindingCategory.AUTH,
        severity=FindingSeverity.CRITICAL,
        check_field="auth",
        forbidden_values=["none", ""],
        description="Authentication must be configured",
    ),
    AuditRule(
        name="secure_transport",
        category=FindingCategory.TRANSPORT,
        severity=FindingSeverity.HIGH,
        check_field="transport",
        forbidden_values=["http", "plaintext"],
        description="Transport must use TLS/encryption",
    ),
    AuditRule(
        name="logging_enabled",
        category=FindingCategory.LOGGING,
        severity=FindingSeverity.MEDIUM,
        check_field="logging",
        expected_values=["true", "enabled", "yes"],
        description="Audit logging should be enabled",
    ),
    AuditRule(
        name="no_wildcard_tools",
        category=FindingCategory.PERMISSIONS,
        severity=FindingSeverity.HIGH,
        check_field="allowed_tools",
        forbidden_values=["*"],
        description="Wildcard tool permissions are not allowed",
    ),
]


# --- Engine ---


class MCPConfigAuditor:
    """Audit MCP server configurations for security misconfigurations."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._findings: list[AuditFinding] = []
        self._rules: list[AuditRule] = list(_DEFAULT_RULES)
        self._audit_count: int = 0
        logger.info("mcp_config_auditor.initialized", max_records=max_records)

    def add_rule(
        self,
        name: str,
        category: FindingCategory = FindingCategory.CONFIGURATION,
        severity: FindingSeverity = FindingSeverity.MEDIUM,
        check_field: str = "",
        expected_values: list[str] | None = None,
        forbidden_values: list[str] | None = None,
        description: str = "",
    ) -> AuditRule:
        rule = AuditRule(
            name=name,
            category=category,
            severity=severity,
            check_field=check_field,
            expected_values=expected_values or [],
            forbidden_values=forbidden_values or [],
            description=description,
        )
        self._rules.append(rule)
        return rule

    def audit_config(self, config: dict[str, Any]) -> list[AuditFinding]:
        self._audit_count += 1
        findings: list[AuditFinding] = []
        for rule in self._rules:
            value = str(config.get(rule.check_field, "")).lower()
            finding = None
            if rule.forbidden_values and value in [v.lower() for v in rule.forbidden_values]:
                finding = AuditFinding(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    description=f"{rule.description}: found '{value}'",
                    remediation=f"Fix {rule.check_field} to avoid forbidden value '{value}'",
                    config_path=rule.check_field,
                )
            elif rule.expected_values and value not in [v.lower() for v in rule.expected_values]:
                finding = AuditFinding(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    description=f"{rule.description}: got '{value}'",
                    remediation=f"Set {rule.check_field} to one of {rule.expected_values}",
                    config_path=rule.check_field,
                )
            if finding:
                findings.append(finding)
                self._findings.append(finding)
        if len(self._findings) > self._max_records:
            self._findings = self._findings[-self._max_records :]
        return findings

    def detect_insecure_defaults(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        auth = str(config.get("auth", "")).lower()
        if auth in ("none", ""):
            issues.append({"field": "auth", "value": auth, "issue": "no_authentication"})
        transport = str(config.get("transport", "")).lower()
        if transport in ("http", "plaintext"):
            issues.append({"field": "transport", "value": transport, "issue": "insecure_transport"})
        return issues

    def detect_excessive_tool_permissions(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        tools = config.get("allowed_tools", [])
        if isinstance(tools, str):
            tools = [tools]
        if "*" in tools:
            issues.append({"field": "allowed_tools", "value": "*", "issue": "wildcard_tools"})
        if len(tools) > 50:
            issues.append(
                {"field": "allowed_tools", "count": len(tools), "issue": "excessive_tool_count"}
            )
        return issues

    def generate_report(self) -> MCPConfigAuditReport:
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for f in self._findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_category[f.category.value] = by_category.get(f.category.value, 0) + 1
        custom_rules = len(self._rules) - len(_DEFAULT_RULES)
        recs: list[str] = []
        critical = by_severity.get("critical", 0)
        if critical > 0:
            recs.append(f"{critical} critical finding(s) require immediate remediation")
        high = by_severity.get("high", 0)
        if high > 0:
            recs.append(f"{high} high-severity finding(s) need attention")
        if not recs:
            recs.append("MCP configurations pass all audit rules")
        return MCPConfigAuditReport(
            total_audits=self._audit_count,
            total_findings=len(self._findings),
            by_severity=by_severity,
            by_category=by_category,
            custom_rules=custom_rules,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_audits": self._audit_count,
            "total_findings": len(self._findings),
            "total_rules": len(self._rules),
            "custom_rules": len(self._rules) - len(_DEFAULT_RULES),
        }

    def clear_data(self) -> dict[str, str]:
        self._findings.clear()
        self._audit_count = 0
        self._rules = list(_DEFAULT_RULES)
        return {"status": "cleared"}
