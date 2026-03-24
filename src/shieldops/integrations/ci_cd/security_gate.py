"""Security gate -- blocks deployments that fail security checks."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Patterns that indicate potential prompt injection vulnerabilities
PROMPT_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)f['\"].*\{.*user.*\}.*['\"]", "f_string_user_input", "high"),
    (r"(?i)\.format\(.*user", "format_user_input", "high"),
    (r"(?i)system.*prompt.*\+.*user", "system_prompt_concatenation", "critical"),
    (
        r"(?i)(?:prompt|template)\s*=.*\+\s*(?:input|query|message|request)",
        "prompt_concatenation",
        "high",
    ),
    (r"(?i)jinja.*render.*user", "template_injection", "critical"),
    (r"(?i)eval\s*\(.*input", "eval_user_input", "critical"),
    (r"(?i)exec\s*\(.*input", "exec_user_input", "critical"),
    (r"(?i)\\n.*role.*system.*\\n.*\{", "role_injection_vector", "high"),
]

# Patterns for hardcoded credentials
CREDENTIAL_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]", "hardcoded_password", "critical"),
    (r"(?i)(api[_-]?key|apikey)\s*=\s*['\"][^'\"]{8,}['\"]", "hardcoded_api_key", "critical"),
    (r"(?i)(secret[_-]?key|secret)\s*=\s*['\"][^'\"]{8,}['\"]", "hardcoded_secret", "critical"),
    (
        r"(?i)(access[_-]?token|auth[_-]?token|bearer)\s*=\s*['\"][^'\"]{8,}['\"]",
        "hardcoded_token",
        "critical",
    ),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key", "critical"),
    (r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "private_key", "critical"),
    (r"ghp_[A-Za-z0-9_]{36}", "github_personal_token", "critical"),
    (r"sk-[A-Za-z0-9]{48}", "openai_api_key", "critical"),
    (r"sk-ant-[A-Za-z0-9-]{90,}", "anthropic_api_key", "critical"),
    (r"(?i)mongodb(\+srv)?://[^:]+:[^@]+@", "mongodb_connection_string", "critical"),
    (r"(?i)postgres(ql)?://[^:]+:[^@]+@", "postgres_connection_string", "critical"),
]

# Known vulnerable dependencies
VULNERABLE_PACKAGES: dict[str, dict[str, str]] = {
    "pyyaml": {"below": "6.0.1", "cve": "CVE-2020-14343", "severity": "critical"},
    "requests": {"below": "2.31.0", "cve": "CVE-2023-32681", "severity": "high"},
    "cryptography": {"below": "41.0.0", "cve": "CVE-2023-38325", "severity": "high"},
    "urllib3": {"below": "2.0.7", "cve": "CVE-2023-45803", "severity": "medium"},
    "jinja2": {"below": "3.1.3", "cve": "CVE-2024-22195", "severity": "medium"},
    "werkzeug": {"below": "3.0.1", "cve": "CVE-2023-46136", "severity": "high"},
    "pillow": {"below": "10.2.0", "cve": "CVE-2023-50447", "severity": "high"},
}

# Files to skip during scans
SKIP_PATTERNS: set[str] = {
    "*.pyc",
    "__pycache__",
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "*.egg-info",
    ".mypy_cache",
    ".ruff_cache",
}


class SecurityGate:
    """Generic security gate for CI/CD pipelines.

    Runs a configurable set of checks and produces a pass/fail result
    suitable for blocking deployments when security standards are not met.
    """

    AVAILABLE_CHECKS = frozenset(
        {
            "red_team",
            "prompt_injection",
            "supply_chain",
            "credential_scan",
        }
    )

    def __init__(self, checks: list[str] | None = None) -> None:
        self.checks = checks or list(self.AVAILABLE_CHECKS)
        for check in self.checks:
            if check not in self.AVAILABLE_CHECKS:
                raise ValueError(
                    f"Unknown check '{check}'. Available: {sorted(self.AVAILABLE_CHECKS)}"
                )

    async def run_all_checks(self, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run all configured checks and return aggregate result."""
        context = context or {}
        all_results: list[dict[str, Any]] = []
        overall_passed = True

        for check_name in self.checks:
            check_fn = getattr(self, f"check_{check_name}", None)
            if check_fn is None:
                logger.warning("check_not_implemented", check=check_name)
                continue

            try:
                result = await check_fn(context)
                all_results.append(result)
                if not result.get("passed", True):
                    overall_passed = False
            except Exception as exc:
                logger.error("check_failed", check=check_name, error=str(exc))
                all_results.append(
                    {
                        "check": check_name,
                        "passed": False,
                        "error": str(exc),
                        "findings": [],
                    }
                )
                overall_passed = False

        total_findings = sum(len(r.get("findings", [])) for r in all_results)
        critical_count = sum(
            1 for r in all_results for f in r.get("findings", []) if f.get("severity") == "critical"
        )

        summary = (
            f"Security gate {'PASSED' if overall_passed else 'FAILED'}: "
            f"{len(self.checks)} checks, {total_findings} findings, "
            f"{critical_count} critical"
        )

        return {
            "passed": overall_passed,
            "results": all_results,
            "summary": summary,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    async def check_prompt_injection(self, context: dict[str, Any]) -> dict[str, Any]:
        """Scan prompt files for injection vulnerabilities."""
        agent_files = context.get("agent_files") or self._discover_prompt_files()
        findings: list[dict[str, Any]] = []

        for filepath in agent_files:
            path = Path(filepath)
            if not path.exists():
                continue
            content = path.read_text()
            for pattern, vuln_type, severity in PROMPT_INJECTION_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    findings.append(
                        {
                            "file": str(path),
                            "vulnerability": vuln_type,
                            "severity": severity,
                            "instances": len(matches),
                            "evidence": [str(m)[:100] for m in matches[:3]],
                        }
                    )

        passed = not any(f["severity"] == "critical" for f in findings)
        return {
            "check": "prompt_injection",
            "passed": passed,
            "findings": findings,
            "files_scanned": len(agent_files),
        }

    async def check_supply_chain(self, context: dict[str, Any]) -> dict[str, Any]:
        """Scan dependency files for known vulnerabilities."""
        req_files = context.get("requirements_files") or self._discover_requirements_files()
        findings: list[dict[str, Any]] = []

        for filepath in req_files:
            path = Path(filepath)
            if not path.exists():
                continue
            content = path.read_text()
            for pkg_name, vuln_info in VULNERABLE_PACKAGES.items():
                # Match lines like: package==version or package>=version
                pkg_pattern = rf"(?im)^{re.escape(pkg_name)}\s*[=<>!~]+=?\s*([\d.]+)"
                match = re.search(pkg_pattern, content)
                if match:
                    installed_version = match.group(1)
                    threshold = vuln_info["below"]
                    if self._version_lt(installed_version, threshold):
                        findings.append(
                            {
                                "file": str(path),
                                "package": pkg_name,
                                "installed_version": installed_version,
                                "fixed_version": threshold,
                                "cve": vuln_info["cve"],
                                "severity": vuln_info["severity"],
                            }
                        )

        passed = not any(f["severity"] == "critical" for f in findings)
        return {
            "check": "supply_chain",
            "passed": passed,
            "findings": findings,
            "files_scanned": len(req_files),
        }

    async def check_credential_scan(self, context: dict[str, Any]) -> dict[str, Any]:
        """Scan source files for hardcoded secrets."""
        source_files = context.get("source_files") or self._discover_source_files()
        findings: list[dict[str, Any]] = []

        for filepath in source_files:
            path = Path(filepath)
            if not path.exists() or path.stat().st_size > 1_000_000:  # Skip files > 1MB
                continue
            try:
                content = path.read_text(errors="ignore")
            except Exception:
                logger.debug("file_read_failed", path=str(path))
                continue

            # Skip test fixtures and example files
            if any(part in str(path) for part in ("test_", "fixture", "example", "mock")):
                continue

            for pattern, vuln_type, severity in CREDENTIAL_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    # Filter out obvious test/example values
                    real_matches = [
                        m
                        for m in matches
                        if not any(
                            fake in str(m).lower()
                            for fake in ("example", "placeholder", "xxx", "test", "dummy", "fake")
                        )
                    ]
                    if real_matches:
                        findings.append(
                            {
                                "file": str(path),
                                "vulnerability": vuln_type,
                                "severity": severity,
                                "instances": len(real_matches),
                                "evidence": ["[REDACTED]"],  # Never include actual secrets
                            }
                        )

        passed = not any(f["severity"] == "critical" for f in findings)
        return {
            "check": "credential_scan",
            "passed": passed,
            "findings": findings,
            "files_scanned": len(source_files),
        }

    async def check_red_team(self, context: dict[str, Any]) -> dict[str, Any]:
        """Check for existing red team report and validate thresholds."""
        report_dir = Path(context.get("report_dir", "reports"))
        findings: list[dict[str, Any]] = []

        if not report_dir.exists():
            return {
                "check": "red_team",
                "passed": True,
                "findings": [],
                "note": "No red team reports found; skipped.",
            }

        # Find the most recent report
        reports = sorted(report_dir.glob("red-team-*.json"), reverse=True)
        if not reports:
            return {
                "check": "red_team",
                "passed": True,
                "findings": [],
                "note": "No red team reports found; skipped.",
            }

        latest = reports[0]
        try:
            data = json.loads(latest.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            return {
                "check": "red_team",
                "passed": False,
                "findings": [{"error": str(exc)}],
            }

        summary = data.get("summary", {})
        if summary.get("critical", 0) > 0:
            findings.append(
                {
                    "file": str(latest),
                    "vulnerability": "critical_red_team_findings",
                    "severity": "critical",
                    "instances": summary["critical"],
                    "evidence": [f"Report: {latest.name}"],
                }
            )

        passed = summary.get("critical", 0) == 0
        return {
            "check": "red_team",
            "passed": passed,
            "findings": findings,
            "report": str(latest),
        }

    def generate_gate_report(self, results: dict[str, Any]) -> dict[str, Any]:
        """Generate a structured report from gate results."""
        return {
            "gate": "security",
            "timestamp": datetime.now(UTC).isoformat(),
            "passed": results["passed"],
            "summary": results["summary"],
            "checks": [
                {
                    "name": r.get("check", "unknown"),
                    "passed": r.get("passed", False),
                    "finding_count": len(r.get("findings", [])),
                    "critical_count": sum(
                        1 for f in r.get("findings", []) if f.get("severity") == "critical"
                    ),
                }
                for r in results.get("results", [])
            ],
            "total_findings": sum(len(r.get("findings", [])) for r in results.get("results", [])),
        }

    # ── Private helpers ──────────────────────────────────────────────────

    @staticmethod
    def _discover_prompt_files() -> list[str]:
        """Find all prompts.py files across agents."""
        agents_root = Path("src/shieldops/agents")
        if not agents_root.exists():
            return []
        return [str(p) for p in agents_root.rglob("prompts.py")]

    @staticmethod
    def _discover_requirements_files() -> list[str]:
        """Find requirements/dependency files."""
        candidates = [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-prod.txt",
            "pyproject.toml",
            "setup.cfg",
        ]
        return [f for f in candidates if Path(f).exists()]

    @staticmethod
    def _discover_source_files() -> list[str]:
        """Find Python source files to scan."""
        src_root = Path("src")
        if not src_root.exists():
            return []
        return [
            str(p)
            for p in src_root.rglob("*.py")
            if not any(skip in str(p) for skip in SKIP_PATTERNS)
        ]

    @staticmethod
    def _version_lt(v1: str, v2: str) -> bool:
        """Compare version strings. Returns True if v1 < v2."""
        try:
            parts1 = [int(x) for x in v1.split(".")]
            parts2 = [int(x) for x in v2.split(".")]
            # Pad to equal length
            max_len = max(len(parts1), len(parts2))
            parts1.extend([0] * (max_len - len(parts1)))
            parts2.extend([0] * (max_len - len(parts2)))
            return parts1 < parts2
        except (ValueError, AttributeError):
            return False
