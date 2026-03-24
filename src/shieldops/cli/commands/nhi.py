"""CLI commands for Non-Human Identity (NHI) Registry management."""
# mypy: disable-error-code="misc,untyped-decorator"

from __future__ import annotations

import click
import structlog

logger = structlog.get_logger()


@click.group()
def nhi() -> None:
    """Manage the Non-Human Identity (NHI) Registry."""


@nhi.command()
@click.option(
    "--provider",
    type=click.Choice(["aws", "gcp", "azure", "k8s", "all"]),
    default="all",
    help="Cloud provider to scan.",
)
@click.option("--deep", is_flag=True, help="Enable deep scan (slower, checks permissions).")
def scan(provider: str, deep: bool) -> None:
    """Scan for non-human identities across cloud providers."""
    targets = [provider] if provider != "all" else ["aws", "gcp", "azure", "k8s"]
    click.echo("NHI Discovery Scan")
    click.echo("=" * 50)
    for target in targets:
        click.echo(f"  Scanning {target.upper()}...")
        # Demo output
        counts = {"aws": 47, "gcp": 23, "azure": 31, "k8s": 89}
        count = counts.get(target, 0)
        click.echo(f"    Found {count} non-human identities")
    click.echo("-" * 50)
    total = sum(counts.get(t, 0) for t in targets)
    click.echo(click.style(f"Total identities discovered: {total}", fg="cyan", bold=True))
    if deep:
        click.echo("  Running deep permission analysis...")
        click.echo(click.style("  12 over-privileged identities found", fg="yellow"))
        click.echo(click.style("  3 identities with admin access", fg="red"))


@nhi.command("list")
@click.option(
    "--type",
    "identity_type",
    type=click.Choice(["service_account", "ai_agent", "bot", "api_key", "all"]),
    default="all",
    help="Filter by identity type.",
)
@click.option(
    "--risk",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Filter by risk level.",
)
@click.option("--stale", is_flag=True, help="Show only stale (unused) identities.")
def list_identities(identity_type: str, risk: str | None, stale: bool) -> None:
    """List registered non-human identities."""
    click.echo("Non-Human Identity Registry")
    click.echo("=" * 75)
    click.echo(f"{'Identity':<30} {'Type':<18} {'Provider':<10} {'Risk':<10} {'Last Used':<12}")
    click.echo("-" * 75)
    identities = [
        ("ci-deploy-sa@proj.iam", "service_account", "gcp", "low", "2h ago"),
        ("shieldops-agent-prod", "ai_agent", "aws", "medium", "5m ago"),
        ("github-actions-oidc", "service_account", "aws", "low", "1h ago"),
        ("data-pipeline-bot", "bot", "k8s", "high", "95d ago"),
        ("legacy-api-key-v1", "api_key", "azure", "critical", "180d ago"),
        ("ml-training-sa", "ai_agent", "gcp", "medium", "12h ago"),
    ]
    for name, itype, prov, rlevel, last in identities:
        if identity_type != "all" and itype != identity_type:
            continue
        if risk and rlevel != risk:
            continue
        if stale and "d ago" not in last:
            continue
        risk_color = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "red",
        }[rlevel]
        click.echo(
            f"{name:<30} {itype:<18} {prov:<10} {click.style(rlevel, fg=risk_color):<18} {last:<12}"
        )


@nhi.command("shadow-ai")
def shadow_ai() -> None:
    """Detect shadow AI services and unregistered agents."""
    click.echo("Shadow AI Detection Scan")
    click.echo("=" * 60)
    click.echo("Scanning network traffic for unregistered AI endpoints...")
    click.echo()
    findings = [
        ("10.0.3.42:8080", "OpenAI-compatible API", "high", "Unregistered LLM proxy"),
        ("k8s/ns-dev/ollama-7b", "Local LLM deployment", "medium", "No governance policy"),
        ("lambda:ai-summarizer", "AWS Lambda + Bedrock", "low", "Missing NHI registration"),
    ]
    click.echo(f"{'Endpoint':<28} {'Type':<24} {'Risk':<10} {'Issue':<25}")
    click.echo("-" * 60)
    for endpoint, stype, risk, issue in findings:
        risk_color = {"low": "green", "medium": "yellow", "high": "red"}[risk]
        click.echo(f"{endpoint:<28} {stype:<24} {click.style(risk, fg=risk_color):<18} {issue:<25}")
    click.echo()
    click.echo(click.style(f"Found {len(findings)} shadow AI instances", fg="yellow", bold=True))


@nhi.command()
def orphaned() -> None:
    """Find orphaned non-human identities (no owner, stale, or unused)."""
    click.echo("Orphaned NHI Discovery")
    click.echo("=" * 65)
    click.echo(f"{'Identity':<30} {'Provider':<10} {'Days Idle':<12} {'Reason':<18}")
    click.echo("-" * 65)
    orphans = [
        ("legacy-api-key-v1", "azure", 180, "No activity"),
        ("data-pipeline-bot", "k8s", 95, "Owner departed"),
        ("test-sa-2024@proj.iam", "gcp", 142, "No owner tag"),
        ("staging-deploy-role", "aws", 67, "Environment deleted"),
    ]
    for name, prov, days, reason in orphans:
        color = "red" if days > 90 else "yellow"
        click.echo(f"{name:<30} {prov:<10} {click.style(str(days), fg=color):<20} {reason:<18}")
    click.echo()
    click.echo(click.style(f"Total orphaned identities: {len(orphans)}", fg="red", bold=True))
    click.echo("  Run 'shieldops nhi scan --deep' to analyze permissions for cleanup")
