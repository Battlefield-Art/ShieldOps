"""Code Security Scanner Agent — Tool functions for code security scanning."""

from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any

import structlog

from .models import (
    CodeScanResult,
    DependencyScanResult,
    FindingSeverity,
    IaCScanResult,
    PrioritizedFinding,
    Repository,
    ScanTarget,
)

logger = structlog.get_logger()

# -----------------------------------------------------------
# IaC misconfiguration rules
# -----------------------------------------------------------
_IAC_RULES: list[dict[str, Any]] = [
    {
        "id": "IAC-001",
        "pattern": re.compile(
            r'(?i)"Effect"\s*:\s*"Allow".*"Action"\s*:\s*"\*"',
            re.DOTALL,
        ),
        "title": "Wildcard IAM action allowed",
        "severity": FindingSeverity.CRITICAL,
        "resource_type": "iam_policy",
        "cis": "CIS 1.16",
        "remediation": "Restrict actions to least privilege",
    },
    {
        "id": "IAC-002",
        "pattern": re.compile(
            r"(?i)(?:publicly_accessible|public)\s*"
            r"[:=]\s*(?:true|yes|1)"
        ),
        "title": "Resource publicly accessible",
        "severity": FindingSeverity.HIGH,
        "resource_type": "network",
        "cis": "CIS 2.1",
        "remediation": "Disable public access; use private endpoints",
    },
    {
        "id": "IAC-003",
        "pattern": re.compile(r"(?i)(?:encrypted|encryption)\s*[:=]\s*(?:false|no|0)"),
        "title": "Encryption disabled",
        "severity": FindingSeverity.HIGH,
        "resource_type": "storage",
        "cis": "CIS 2.6",
        "remediation": "Enable encryption at rest and in transit",
    },
    {
        "id": "IAC-004",
        "pattern": re.compile(r"(?i)(?:logging|access_logs)\s*[:=]\s*(?:false|no|0)"),
        "title": "Logging disabled on resource",
        "severity": FindingSeverity.MEDIUM,
        "resource_type": "observability",
        "cis": "CIS 3.1",
        "remediation": "Enable access logging and audit trails",
    },
    {
        "id": "IAC-005",
        "pattern": re.compile(r'(?i)(?:cidr_blocks?|ingress)\s*[:=].*"0\.0\.0\.0/0"'),
        "title": "Unrestricted ingress (0.0.0.0/0)",
        "severity": FindingSeverity.HIGH,
        "resource_type": "security_group",
        "cis": "CIS 4.1",
        "remediation": "Restrict ingress to known CIDR ranges",
    },
]

# -----------------------------------------------------------
# Dependency vulnerability patterns (simulated CVE DB)
# -----------------------------------------------------------
_KNOWN_CVES: list[dict[str, Any]] = [
    {
        "package": "requests",
        "affected": "<2.31.0",
        "cve": "CVE-2023-32681",
        "cvss": 6.1,
        "severity": FindingSeverity.MEDIUM,
        "desc": "Unintended leak of Proxy-Authorization header",
        "fixed": "2.31.0",
        "ecosystem": "pypi",
    },
    {
        "package": "flask",
        "affected": "<2.3.2",
        "cve": "CVE-2023-30861",
        "cvss": 7.5,
        "severity": FindingSeverity.HIGH,
        "desc": "Cookie values visible on response redirect",
        "fixed": "2.3.2",
        "ecosystem": "pypi",
    },
    {
        "package": "lodash",
        "affected": "<4.17.21",
        "cve": "CVE-2021-23337",
        "cvss": 7.2,
        "severity": FindingSeverity.HIGH,
        "desc": "Command injection via template function",
        "fixed": "4.17.21",
        "ecosystem": "npm",
    },
    {
        "package": "axios",
        "affected": "<1.6.0",
        "cve": "CVE-2023-45857",
        "cvss": 6.5,
        "severity": FindingSeverity.MEDIUM,
        "desc": "XSRF-TOKEN exposed in cross-site requests",
        "fixed": "1.6.0",
        "ecosystem": "npm",
    },
    {
        "package": "langchain",
        "affected": "<0.1.0",
        "cve": "CVE-2024-LC001",
        "cvss": 9.1,
        "severity": FindingSeverity.CRITICAL,
        "desc": "Arbitrary code execution via prompt injection",
        "fixed": "0.1.0",
        "ecosystem": "pypi",
    },
]

# -----------------------------------------------------------
# SAST code patterns
# -----------------------------------------------------------
_CODE_RULES: list[dict[str, Any]] = [
    {
        "id": "CODE-001",
        "pattern": re.compile(r"(?i)(?:eval|exec)\s*\("),
        "title": "Dynamic code execution (eval/exec)",
        "severity": FindingSeverity.HIGH,
        "category": "injection",
        "cwe": "CWE-94",
    },
    {
        "id": "CODE-002",
        "pattern": re.compile(r"(?i)(?:pickle\.loads?|yaml\.(?:load|unsafe_load))\s*\("),
        "title": "Insecure deserialization",
        "severity": FindingSeverity.HIGH,
        "category": "deserialization",
        "cwe": "CWE-502",
    },
    {
        "id": "CODE-003",
        "pattern": re.compile(r"(?i)subprocess\.\w+\(.*shell\s*=\s*True"),
        "title": "Shell injection via subprocess",
        "severity": FindingSeverity.HIGH,
        "category": "injection",
        "cwe": "CWE-78",
    },
    {
        "id": "CODE-004",
        "pattern": re.compile(
            r'(?i)f["\'].*\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)',
            re.DOTALL,
        ),
        "title": "SQL injection via f-string",
        "severity": FindingSeverity.CRITICAL,
        "category": "injection",
        "cwe": "CWE-89",
    },
    {
        "id": "CODE-005",
        "pattern": re.compile(r"(?i)verify\s*=\s*False"),
        "title": "TLS verification disabled",
        "severity": FindingSeverity.MEDIUM,
        "category": "crypto",
        "cwe": "CWE-295",
    },
]

# -----------------------------------------------------------
# AI-specific scanning patterns
# -----------------------------------------------------------
_AI_RULES: list[dict[str, Any]] = [
    {
        "id": "AI-001",
        "pattern": re.compile(
            r"(?i)(?:user_input|user_message|query)\s*"
            r"(?:\+|\.format|%)"
        ),
        "title": "Prompt injection: unsanitized user input",
        "severity": FindingSeverity.CRITICAL,
        "category": "prompt_injection",
        "cwe": "CWE-77",
    },
    {
        "id": "AI-002",
        "pattern": re.compile(
            r'(?i)(?:tool|function)\s*[:=]\s*["\'](?:exec|eval|system|os\.)',
        ),
        "title": "Agent tool with dangerous capability",
        "severity": FindingSeverity.CRITICAL,
        "category": "agent_escape",
        "cwe": "CWE-250",
    },
    {
        "id": "AI-003",
        "pattern": re.compile(
            r"(?i)(?:system_prompt|system_message)\s*="
            r".*(?:ignore|disregard|forget)"
        ),
        "title": "Prompt template contains override keywords",
        "severity": FindingSeverity.HIGH,
        "category": "prompt_leakage",
        "cwe": "CWE-200",
    },
    {
        "id": "AI-004",
        "pattern": re.compile(
            r"(?i)(?:allow_dangerous|unsafe_mode|skip_validation)"
            r"\s*[:=]\s*(?:True|true|1|yes)"
        ),
        "title": "Agent safety guardrails disabled",
        "severity": FindingSeverity.CRITICAL,
        "category": "guardrail_bypass",
        "cwe": "CWE-284",
    },
    {
        "id": "AI-005",
        "pattern": re.compile(r"(?i)(?:rag|retrieval).*(?:no_filter|unfiltered|raw)"),
        "title": "RAG pipeline missing output filtering",
        "severity": FindingSeverity.HIGH,
        "category": "rag_security",
        "cwe": "CWE-116",
    },
]

# -----------------------------------------------------------
# File extension to ScanTarget mapping
# -----------------------------------------------------------
_EXT_MAP: dict[str, ScanTarget] = {
    ".tf": ScanTarget.TERRAFORM,
    ".tfvars": ScanTarget.TERRAFORM,
    ".template": ScanTarget.CLOUDFORMATION,
    ".yaml": ScanTarget.KUBERNETES_YAML,
    ".yml": ScanTarget.KUBERNETES_YAML,
    "Dockerfile": ScanTarget.DOCKERFILE,
    ".py": ScanTarget.PYTHON,
    ".js": ScanTarget.JAVASCRIPT,
    ".ts": ScanTarget.JAVASCRIPT,
    ".go": ScanTarget.GO,
}


def _infer_target_type(path: str) -> ScanTarget:
    """Infer scan target type from file path."""
    lower = path.lower()
    if "cloudformation" in lower or lower.endswith(".template"):
        return ScanTarget.CLOUDFORMATION
    if lower.endswith((".tf", ".tfvars")):
        return ScanTarget.TERRAFORM
    if "dockerfile" in lower:
        return ScanTarget.DOCKERFILE
    if "prompt" in lower and lower.endswith((".py", ".yaml", ".yml")):
        return ScanTarget.PROMPT_TEMPLATE
    if "agent" in lower and "config" in lower:
        return ScanTarget.AGENT_CONFIG
    for ext, target in _EXT_MAP.items():
        if lower.endswith(ext):
            return target
    return ScanTarget.PYTHON


def _hash_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic short hash ID."""
    raw = ":".join(parts)
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:12]


class CodeSecurityScannerToolkit:
    """Tools for shift-left code security scanning."""

    def __init__(
        self,
        git_client: Any | None = None,
        registry_client: Any | None = None,
    ) -> None:
        self._git_client = git_client
        self._registry_client = registry_client

    # -------------------------------------------------------
    # Repository discovery
    # -------------------------------------------------------

    async def discover_repositories(
        self,
        tenant_id: str,
        targets: list[str],
    ) -> list[Repository]:
        """Discover repositories and files to scan."""
        logger.info(
            "code_security_scanner.discover_repos",
            tenant_id=tenant_id,
            target_count=len(targets),
        )
        repos: list[Repository] = []
        for target in targets:
            languages = self._detect_languages(target)
            has_iac = any(target.lower().endswith(e) for e in (".tf", ".yaml", ".yml", ".template"))
            has_ai = any(kw in target.lower() for kw in ("prompt", "agent", "rag", "llm"))
            repo = Repository(
                id=_hash_id("repo-", target),
                name=self._extract_repo_name(target),
                url=target,
                branch="main",
                languages=languages,
                has_iac=has_iac,
                has_ai_code=has_ai,
                file_count=1,
            )
            repos.append(repo)
        return repos

    # -------------------------------------------------------
    # IaC scanning
    # -------------------------------------------------------

    async def scan_iac(
        self,
        repos: list[Repository],
        targets: list[str],
    ) -> list[IaCScanResult]:
        """Scan IaC files for misconfigurations."""
        logger.info(
            "code_security_scanner.scan_iac",
            target_count=len(targets),
        )
        findings: list[IaCScanResult] = []
        repo_map = {r.url: r for r in repos}

        for target in targets:
            target_type = _infer_target_type(target)
            if target_type not in (
                ScanTarget.TERRAFORM,
                ScanTarget.CLOUDFORMATION,
                ScanTarget.KUBERNETES_YAML,
                ScanTarget.DOCKERFILE,
            ):
                continue

            lines = await self._read_file(target)
            repo = repo_map.get(target)
            repo_id = repo.id if repo else ""

            for line_num, line in enumerate(lines, start=1):
                for rule in _IAC_RULES:
                    if rule["pattern"].search(line):
                        fid = _hash_id(
                            "iac-",
                            target,
                            str(line_num),
                            rule["id"],
                        )
                        findings.append(
                            IaCScanResult(
                                id=fid,
                                repo_id=repo_id,
                                target_type=target_type,
                                file_path=target,
                                line_number=line_num,
                                rule_id=rule["id"],
                                severity=rule["severity"],
                                title=rule["title"],
                                description=rule["title"],
                                resource_type=rule["resource_type"],
                                remediation=rule["remediation"],
                                cis_benchmark=rule["cis"],
                            )
                        )
        return self._dedupe_by_id(findings)

    # -------------------------------------------------------
    # Dependency scanning (SCA)
    # -------------------------------------------------------

    async def scan_dependencies(
        self,
        repos: list[Repository],
        targets: list[str],
    ) -> list[DependencyScanResult]:
        """Scan dependency manifests for known CVEs."""
        logger.info(
            "code_security_scanner.scan_deps",
            target_count=len(targets),
        )
        findings: list[DependencyScanResult] = []
        repo_map = {r.url: r for r in repos}

        for target in targets:
            lines = await self._read_file(target)
            content = "\n".join(lines)
            repo = repo_map.get(target)
            repo_id = repo.id if repo else ""

            for cve in _KNOWN_CVES:
                pkg = cve["package"]
                if pkg in content.lower():
                    fid = _hash_id(
                        "dep-",
                        target,
                        cve["cve"],
                    )
                    findings.append(
                        DependencyScanResult(
                            id=fid,
                            repo_id=repo_id,
                            package_name=pkg,
                            installed_version="unknown",
                            fixed_version=cve["fixed"],
                            cve_id=cve["cve"],
                            severity=cve["severity"],
                            cvss_score=cve["cvss"],
                            description=cve["desc"],
                            is_direct=True,
                            ecosystem=cve["ecosystem"],
                        )
                    )
        return self._dedupe_by_id(findings)

    # -------------------------------------------------------
    # Application code scanning (SAST + AI-specific)
    # -------------------------------------------------------

    async def scan_application_code(
        self,
        repos: list[Repository],
        targets: list[str],
    ) -> list[CodeScanResult]:
        """Scan application code for SAST + AI-specific vulns."""
        logger.info(
            "code_security_scanner.scan_code",
            target_count=len(targets),
        )
        findings: list[CodeScanResult] = []
        repo_map = {r.url: r for r in repos}

        for target in targets:
            lines = await self._read_file(target)
            repo = repo_map.get(target)
            repo_id = repo.id if repo else ""

            # Standard SAST rules
            for line_num, line in enumerate(lines, start=1):
                for rule in _CODE_RULES:
                    if rule["pattern"].search(line):
                        fid = _hash_id(
                            "code-",
                            target,
                            str(line_num),
                            rule["id"],
                        )
                        snippet = line.strip()[:80]
                        findings.append(
                            CodeScanResult(
                                id=fid,
                                repo_id=repo_id,
                                file_path=target,
                                line_number=line_num,
                                rule_id=rule["id"],
                                severity=rule["severity"],
                                category=rule["category"],
                                title=rule["title"],
                                description=rule["title"],
                                snippet=snippet,
                                cwe_id=rule["cwe"],
                                is_ai_specific=False,
                            )
                        )

            # AI-specific rules
            for line_num, line in enumerate(lines, start=1):
                for rule in _AI_RULES:
                    if rule["pattern"].search(line):
                        fid = _hash_id(
                            "ai-",
                            target,
                            str(line_num),
                            rule["id"],
                        )
                        snippet = line.strip()[:80]
                        findings.append(
                            CodeScanResult(
                                id=fid,
                                repo_id=repo_id,
                                file_path=target,
                                line_number=line_num,
                                rule_id=rule["id"],
                                severity=rule["severity"],
                                category=rule["category"],
                                title=rule["title"],
                                description=rule["title"],
                                snippet=snippet,
                                cwe_id=rule["cwe"],
                                is_ai_specific=True,
                            )
                        )
        return self._dedupe_by_id(findings)

    # -------------------------------------------------------
    # Prioritization
    # -------------------------------------------------------

    def prioritize_findings(
        self,
        iac: list[IaCScanResult],
        deps: list[DependencyScanResult],
        code: list[CodeScanResult],
    ) -> list[PrioritizedFinding]:
        """Merge and prioritize all findings by risk score."""
        logger.info(
            "code_security_scanner.prioritize",
            iac=len(iac),
            deps=len(deps),
            code=len(code),
        )
        results: list[PrioritizedFinding] = []

        sev_scores = {
            FindingSeverity.CRITICAL: 1.0,
            FindingSeverity.HIGH: 0.8,
            FindingSeverity.MEDIUM: 0.5,
            FindingSeverity.LOW: 0.2,
            FindingSeverity.INFO: 0.1,
        }

        for f in iac:
            score = sev_scores.get(f.severity, 0.5)
            results.append(
                PrioritizedFinding(
                    id=str(uuid.uuid4())[:8],
                    source_finding_id=f.id,
                    finding_type="iac",
                    severity=f.severity,
                    priority_score=score,
                    title=f.title,
                    description=f.description,
                    file_path=f.file_path,
                    remediation=f.remediation,
                    is_exploitable=f.severity
                    in (
                        FindingSeverity.CRITICAL,
                        FindingSeverity.HIGH,
                    ),
                    tags=[f.cis_benchmark, f.resource_type],
                )
            )

        for f in deps:
            score = min(f.cvss_score / 10.0, 1.0)
            results.append(
                PrioritizedFinding(
                    id=str(uuid.uuid4())[:8],
                    source_finding_id=f.id,
                    finding_type="dependency",
                    severity=f.severity,
                    priority_score=score,
                    title=f"{f.package_name} {f.cve_id}",
                    description=f.description,
                    file_path="",
                    remediation=(f"Upgrade {f.package_name} to {f.fixed_version}"),
                    is_exploitable=f.cvss_score >= 7.0,
                    tags=[f.ecosystem, f.cve_id],
                )
            )

        for f in code:
            score = sev_scores.get(f.severity, 0.5)
            if f.is_ai_specific:
                score = min(score + 0.15, 1.0)
            results.append(
                PrioritizedFinding(
                    id=str(uuid.uuid4())[:8],
                    source_finding_id=f.id,
                    finding_type="code",
                    severity=f.severity,
                    priority_score=score,
                    title=f.title,
                    description=f.description,
                    file_path=f.file_path,
                    remediation="",
                    is_exploitable=f.severity
                    in (
                        FindingSeverity.CRITICAL,
                        FindingSeverity.HIGH,
                    ),
                    is_ai_specific=f.is_ai_specific,
                    tags=[f.cwe_id, f.category],
                )
            )

        results.sort(key=lambda r: r.priority_score, reverse=True)
        return results

    # -------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------

    async def _read_file(self, target: str) -> list[str]:
        """Read file content from git client or local fs."""
        if self._git_client:
            try:
                content = await self._git_client.read_file(target)
                if isinstance(content, str):
                    return content.splitlines()
                return list(content)
            except Exception:
                logger.debug(
                    "code_security_scanner.read.git_fallback",
                    target=target,
                )
        try:
            with open(target) as fh:
                return fh.readlines()
        except (OSError, FileNotFoundError):
            logger.debug(
                "code_security_scanner.read.not_found",
                target=target,
            )
            return []

    @staticmethod
    def _extract_repo_name(path: str) -> str:
        """Extract a human-readable repo name from path."""
        parts = path.replace("\\", "/").split("/")
        for i, part in enumerate(parts):
            if part in (".git", "src", "lib", "app"):
                return "/".join(parts[max(0, i - 1) : i]) or parts[0]
        return parts[-1] if parts else "unknown"

    @staticmethod
    def _detect_languages(path: str) -> list[str]:
        """Detect languages from file extension."""
        lower = path.lower()
        langs: list[str] = []
        ext_lang = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".go": "go",
            ".tf": "hcl",
            ".yaml": "yaml",
            ".yml": "yaml",
        }
        for ext, lang in ext_lang.items():
            if lower.endswith(ext):
                langs.append(lang)
        return langs or ["unknown"]

    @staticmethod
    def _dedupe_by_id(
        items: list[Any],
    ) -> list[Any]:
        """Deduplicate a list of models by their id field."""
        seen: set[str] = set()
        result: list[Any] = []
        for item in items:
            fid = item.id if hasattr(item, "id") else ""
            if fid not in seen:
                seen.add(fid)
                result.append(item)
        return result
