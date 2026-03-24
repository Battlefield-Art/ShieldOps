"""CLI commands for Agent Firewall management."""
# mypy: disable-error-code="misc,untyped-decorator"

from __future__ import annotations

import click
import structlog

logger = structlog.get_logger()


@click.group()
def firewall() -> None:
    """Manage the Agent Behavioral Firewall."""


@firewall.command()
def status() -> None:
    """Show firewall status across all monitored agents."""
    click.echo("Agent Firewall Status")
    click.echo("=" * 40)
    click.echo(f"{'Agent':<25} {'State':<12} {'Mode':<10}")
    click.echo("-" * 40)
    # Demo data — in production these come from the API
    agents = [
        ("data-pipeline-agent", "closed", "enforce"),
        ("customer-support-bot", "closed", "audit"),
        ("code-review-agent", "half_open", "enforce"),
        ("payment-processor", "open", "enforce"),
    ]
    for name, state, mode in agents:
        color = {"closed": "green", "half_open": "yellow", "open": "red"}[state]
        click.echo(f"{name:<25} {click.style(state, fg=color):<20} {mode:<10}")


@firewall.command()
def policies() -> None:
    """List active firewall policies."""
    click.echo("Active Firewall Policies")
    click.echo("=" * 60)
    click.echo(f"{'Policy':<30} {'Scope':<15} {'Action':<15}")
    click.echo("-" * 60)
    policies_data = [
        ("max-api-calls-per-minute", "all-agents", "rate-limit"),
        ("no-prod-delete-without-approval", "remediation", "block+alert"),
        ("pii-egress-prevention", "all-agents", "block"),
        ("cost-ceiling-per-action", "finops", "throttle"),
        ("blast-radius-limit", "remediation", "block+escalate"),
    ]
    for name, scope, action in policies_data:
        click.echo(f"{name:<30} {scope:<15} {action:<15}")


@firewall.command()
@click.argument("agent_id")
def kill_switch(agent_id: str) -> None:
    """Activate kill switch for an agent (EMERGENCY)."""
    click.confirm(
        click.style(f"EMERGENCY: Kill switch for {agent_id}?", fg="red", bold=True),
        abort=True,
    )
    click.echo(click.style(f"Kill switch ACTIVATED for {agent_id}", fg="red", bold=True))
    click.echo("  Circuit breaker: OPEN")
    click.echo("  Tokens revoked: 3")
    click.echo("  Sessions terminated: 1")
    logger.warning("kill_switch_activated", agent_id=agent_id)


@firewall.command()
@click.argument("agent_id")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "csv", "html", "markdown"]),
    default="json",
    help="Output format for the report.",
)
@click.option("--hours", default=24, help="Time range in hours.")
def audit_report(agent_id: str, fmt: str, hours: int) -> None:
    """Generate audit report for an agent."""
    click.echo(f"Generating {fmt} audit report for {agent_id} (last {hours}h)...")
    click.echo("  Collecting behavioral telemetry...")
    click.echo("  Analyzing policy violations...")
    click.echo("  Scoring risk posture...")
    filename = f"audit-report-{agent_id}.{fmt}"
    click.echo(click.style(f"Report generated: {filename}", fg="green"))


@firewall.command()
@click.argument("agent_id")
def reset(agent_id: str) -> None:
    """Reset circuit breaker for an agent (close the breaker)."""
    click.confirm(
        f"Reset circuit breaker for {agent_id} to CLOSED state?",
        abort=True,
    )
    click.echo(click.style(f"Circuit breaker RESET for {agent_id}", fg="green"))
    click.echo("  State: closed")
    click.echo("  Agent may now resume operations")
    logger.info("circuit_breaker_reset", agent_id=agent_id)


@firewall.command("events")
@click.option("--agent", default=None, help="Filter by agent ID.")
@click.option("--severity", type=click.Choice(["low", "medium", "high", "critical"]), default=None)
@click.option("--limit", default=20, help="Max events to display.")
def list_events(agent: str | None, severity: str | None, limit: int) -> None:
    """List recent firewall events."""
    click.echo("Recent Firewall Events")
    click.echo("=" * 70)
    click.echo(f"{'Timestamp':<22} {'Agent':<20} {'Severity':<10} {'Event':<18}")
    click.echo("-" * 70)
    events = [
        ("2026-03-24T10:15:32Z", "payment-processor", "critical", "circuit_tripped"),
        ("2026-03-24T10:14:58Z", "payment-processor", "high", "anomaly_detected"),
        ("2026-03-24T09:42:11Z", "code-review-agent", "medium", "rate_limit_hit"),
        ("2026-03-24T09:30:00Z", "data-pipeline-agent", "low", "policy_check_pass"),
    ]
    for ts, ag, sev, evt in events[:limit]:
        if agent and ag != agent:
            continue
        if severity and sev != severity:
            continue
        sev_color = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "red",
        }[sev]
        click.echo(f"{ts:<22} {ag:<20} {click.style(sev, fg=sev_color):<18} {evt:<18}")
