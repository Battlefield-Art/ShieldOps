"""CI/CD hook for continuous AI red teaming after model/prompt changes."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Agent directories under src/shieldops/agents/
AGENTS_ROOT = Path("src/shieldops/agents")

# Attack vectors by depth
ATTACK_VECTORS: dict[str, list[str]] = {
    "quick": [
        "prompt_injection_basic",
        "tool_misuse_check",
        "output_leakage_scan",
    ],
    "standard": [
        "prompt_injection_basic",
        "prompt_injection_advanced",
        "tool_misuse_check",
        "privilege_escalation_probe",
        "output_leakage_scan",
        "data_exfiltration_attempt",
    ],
    "deep": [
        "prompt_injection_basic",
        "prompt_injection_advanced",
        "prompt_injection_multilingual",
        "tool_misuse_check",
        "privilege_escalation_probe",
        "output_leakage_scan",
        "data_exfiltration_attempt",
        "jailbreak_chain",
        "indirect_injection",
        "context_manipulation",
    ],
}

# Known dangerous patterns in prompt files
DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)ignore\s+(previous|above|all)\s+instructions", "prompt_injection_sink", "high"),
    (r"(?i)you\s+are\s+now\s+(unrestricted|jailbroken|DAN)", "jailbreak_pattern", "critical"),
    (r"(?i)system:\s*\{.*user_input", "unsanitized_system_prompt", "critical"),
    (
        r"(?i)(password|secret|token|api.?key)\s*=\s*['\"][^'\"]+['\"]",
        "hardcoded_credential",
        "critical",
    ),
    (r"(?i)eval\s*\(", "code_injection_risk", "high"),
    (r"(?i)exec\s*\(", "code_injection_risk", "high"),
    (
        r"(?i)subprocess\.(run|Popen|call)\s*\(.*shell\s*=\s*True",
        "command_injection_risk",
        "critical",
    ),
    (r"(?i)os\.system\s*\(", "command_injection_risk", "high"),
    (r"(?i)__import__\s*\(", "dynamic_import_risk", "medium"),
    (r"\{[^}]*\bformat\b[^}]*\}", "format_string_injection", "medium"),
]

# Tool-level dangerous patterns
TOOL_DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)rm\s+-rf\s+/", "destructive_command", "critical"),
    (r"(?i)DROP\s+(TABLE|DATABASE)", "destructive_sql", "critical"),
    (r"(?i)DELETE\s+FROM\s+\w+\s*(?:;|$)", "unfiltered_delete", "high"),
    (r"(?i)GRANT\s+ALL", "excessive_permissions", "high"),
    (r"(?i)chmod\s+777", "world_writable", "high"),
    (r"(?i)curl\s+.*\|\s*sh", "remote_code_execution", "critical"),
    (r"(?i)requests\.get\(.*\+.*user", "ssrf_risk", "high"),
]


class CIRedTeamRunner:
    """Runs red team assessments as part of CI/CD pipelines."""

    def __init__(
        self,
        target_agents: str = "all",
        depth: str = "quick",
        output_dir: str = "reports",
    ) -> None:
        self.target_agents = target_agents
        self.depth = depth
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.vectors = ATTACK_VECTORS.get(depth, ATTACK_VECTORS["quick"])

    def detect_changed_agents(self, git_diff_files: list[str] | None = None) -> list[str]:
        """Detect which agents had prompts or tools changed based on git diff."""
        if git_diff_files is None:
            try:
                result = subprocess.run(
                    ["git", "diff", "--name-only", "HEAD~1", "HEAD"],  # noqa: S607
                    capture_output=True,
                    text=True,
                    check=True,
                )
                git_diff_files = result.stdout.strip().splitlines()
            except subprocess.CalledProcessError:
                logger.warning("git_diff_failed", msg="Could not detect changed files")
                return []

        changed_agents: set[str] = set()
        for filepath in git_diff_files:
            if filepath.startswith("src/shieldops/agents/"):
                parts = filepath.split("/")
                if len(parts) >= 4:
                    agent_name = parts[3]  # e.g. "investigation"
                    # Only flag if prompts.py or tools.py changed
                    if len(parts) >= 5 and parts[-1] in ("prompts.py", "tools.py"):
                        changed_agents.add(agent_name)
            # SDK changes affect all agents
            if filepath.startswith("src/shieldops/sdk/"):
                return ["all"]

        return sorted(changed_agents)

    async def run_assessment(self, agents: list[str] | None = None) -> dict[str, Any]:
        """Run red team assessment against specified agents."""
        if agents is None or agents == ["all"]:
            # Discover all agents
            if AGENTS_ROOT.exists():
                agents = [
                    d.name
                    for d in AGENTS_ROOT.iterdir()
                    if d.is_dir() and not d.name.startswith("_")
                ]
            else:
                agents = []

        results: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "depth": self.depth,
            "vectors_tested": self.vectors,
            "agents_tested": len(agents),
            "findings": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        }

        for agent_name in agents:
            agent_findings = await self._assess_agent(agent_name)
            results["findings"].extend(agent_findings)
            for finding in agent_findings:
                severity = finding.get("severity", "info")
                results["summary"][severity] = results["summary"].get(severity, 0) + 1

        logger.info(
            "red_team_assessment_complete",
            agents=len(agents),
            findings=len(results["findings"]),
            summary=results["summary"],
        )
        return results

    async def _assess_agent(self, agent_name: str) -> list[dict[str, Any]]:
        """Run all attack vectors against a single agent."""
        findings: list[dict[str, Any]] = []
        agent_dir = AGENTS_ROOT / agent_name

        # Scan prompt files for injection sinks
        prompts_file = agent_dir / "prompts.py"
        if prompts_file.exists():
            content = prompts_file.read_text()
            for pattern, vuln_type, severity in DANGEROUS_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    findings.append(
                        {
                            "agent": agent_name,
                            "file": str(prompts_file),
                            "vector": vuln_type,
                            "severity": severity,
                            "description": f"Found {len(matches)} instance(s) of {vuln_type}",
                            "evidence": matches[:3],  # Limit evidence to 3 samples
                        }
                    )

        # Scan tool files for dangerous operations
        tools_file = agent_dir / "tools.py"
        if tools_file.exists():
            content = tools_file.read_text()
            for pattern, vuln_type, severity in TOOL_DANGEROUS_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    findings.append(
                        {
                            "agent": agent_name,
                            "file": str(tools_file),
                            "vector": vuln_type,
                            "severity": severity,
                            "description": f"Found {len(matches)} instance(s) of {vuln_type}",
                            "evidence": matches[:3],
                        }
                    )

        # Check for missing safety guardrails
        nodes_file = agent_dir / "nodes.py"
        if nodes_file.exists():
            content = nodes_file.read_text()
            if "confidence" not in content.lower() and "threshold" not in content.lower():
                findings.append(
                    {
                        "agent": agent_name,
                        "file": str(nodes_file),
                        "vector": "missing_confidence_check",
                        "severity": "medium",
                        "description": "No confidence threshold check found in node logic",
                        "evidence": [],
                    }
                )
            if "opa" not in content.lower() and "policy" not in content.lower():
                findings.append(
                    {
                        "agent": agent_name,
                        "file": str(nodes_file),
                        "vector": "missing_policy_check",
                        "severity": "high",
                        "description": "No OPA policy evaluation found in node logic",
                        "evidence": [],
                    }
                )

        return findings

    def generate_ci_report(self, results: dict[str, Any]) -> Path:
        """Write JSON report to output directory."""
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        report_path = self.output_dir / f"red-team-{timestamp}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))
        logger.info("report_generated", path=str(report_path))
        return report_path

    def check_threshold(
        self,
        results: dict[str, Any],
        max_critical: int = 0,
        max_high: int = 5,
    ) -> bool:
        """Check if findings exceed acceptable thresholds. Returns True if passed."""
        summary = results.get("summary", {})
        critical_count = summary.get("critical", 0)
        high_count = summary.get("high", 0)

        passed = critical_count <= max_critical and high_count <= max_high

        logger.info(
            "threshold_check",
            passed=passed,
            critical=critical_count,
            max_critical=max_critical,
            high=high_count,
            max_high=max_high,
        )
        return passed


def main() -> None:
    """CLI entry point for CI/CD red team hook."""
    parser = argparse.ArgumentParser(
        description="Run AI red team assessment in CI/CD pipeline",
    )
    parser.add_argument(
        "--target",
        default="all",
        help="Comma-separated agent IDs or 'all' (default: all)",
    )
    parser.add_argument(
        "--depth",
        choices=["quick", "standard", "deep"],
        default="quick",
        help="Attack depth level (default: quick)",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory for reports (default: reports/)",
    )
    parser.add_argument(
        "--max-critical",
        type=int,
        default=0,
        help="Max critical findings before failing (default: 0)",
    )
    parser.add_argument(
        "--max-high",
        type=int,
        default=5,
        help="Max high findings before failing (default: 5)",
    )
    args = parser.parse_args()

    runner = CIRedTeamRunner(
        target_agents=args.target,
        depth=args.depth,
        output_dir=args.output,
    )

    # Determine agents to test
    if args.target == "all":
        agents = None  # Will discover all agents
    else:
        agents = [a.strip() for a in args.target.split(",") if a.strip()]

    # Run assessment
    results = asyncio.run(runner.run_assessment(agents))
    report_path = runner.generate_ci_report(results)

    # Print summary
    summary = results["summary"]
    print(f"\n{'=' * 60}")
    print(f"AI Red Team Assessment — {args.depth} depth")
    print(f"{'=' * 60}")
    print(f"Agents tested:  {results['agents_tested']}")
    print(f"Total findings: {len(results['findings'])}")
    print(f"  Critical: {summary['critical']}")
    print(f"  High:     {summary['high']}")
    print(f"  Medium:   {summary['medium']}")
    print(f"  Low:      {summary['low']}")
    print(f"  Info:     {summary['info']}")
    print(f"Report:     {report_path}")
    print(f"{'=' * 60}\n")

    # Check threshold — exit 1 if exceeded
    if not runner.check_threshold(results, args.max_critical, args.max_high):
        print(
            f"FAILED: Findings exceed threshold "
            f"(critical: {summary['critical']}/{args.max_critical}, "
            f"high: {summary['high']}/{args.max_high})",
        )
        sys.exit(1)

    print("PASSED: All findings within acceptable thresholds.")


if __name__ == "__main__":
    main()
