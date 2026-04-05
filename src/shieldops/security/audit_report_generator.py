"""Agent Audit Report Exporter — generates audit reports for enterprise customers."""

from __future__ import annotations

import csv
import io
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ReportFormat(StrEnum):
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    MARKDOWN = "markdown"


class ReportScope(StrEnum):
    SINGLE_AGENT = "single_agent"
    ALL_AGENTS = "all_agents"
    TIME_RANGE = "time_range"
    CUSTOM = "custom"


class ReportSection(StrEnum):
    SUMMARY = "summary"
    TOOL_CALLS = "tool_calls"
    ANOMALIES = "anomalies"
    POLICY_VIOLATIONS = "policy_violations"
    RISK_TIMELINE = "risk_timeline"
    RECOMMENDATIONS = "recommendations"


# --- Models ---


class AuditReportRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    scope: ReportScope = ReportScope.SINGLE_AGENT
    format: ReportFormat = ReportFormat.JSON
    sections_included: list[ReportSection] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    file_path: str = ""
    size_bytes: int = 0
    requested_by: str = ""


class ReportConfig(BaseModel):
    agent_id: str = ""
    scope: ReportScope = ReportScope.SINGLE_AGENT
    format: ReportFormat = ReportFormat.JSON
    time_range_hours: int = 24
    include_sections: list[ReportSection] = Field(default_factory=lambda: list(ReportSection))
    include_raw_data: bool = False
    compliance_framework: str | None = None


class AuditReportSummary(BaseModel):
    total_reports: int = 0
    by_format: dict[str, int] = Field(default_factory=dict)
    by_scope: dict[str, int] = Field(default_factory=dict)
    avg_generation_time_ms: float = 0.0
    generated_at: float = Field(default_factory=time.time)


# --- Severity color coding for HTML ---

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#2563eb",
}


# --- Engine ---


class AuditReportGenerator:
    """Generates audit reports from firewall, interceptor, and baseline data."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[AuditReportRecord] = []
        self._generation_times: list[float] = []
        logger.info("audit_report_generator.initialized", max_records=max_records)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_if_needed(self) -> None:
        while len(self._records) > self._max_records:
            self._records.pop(0)

    def _extract_tool_calls(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract tool call records from combined data sources."""
        calls: list[dict[str, Any]] = []
        for source_key in ("firewall_data", "interceptor_data", "baseline_data"):
            source = data.get(source_key, {})
            if isinstance(source, dict):
                for item in source.get("tool_calls", source.get("records", [])):  # type: ignore[union-attr]
                    if isinstance(item, dict):
                        calls.append(item)
            elif isinstance(source, list):
                calls.extend(item for item in source if isinstance(item, dict))
        return calls

    def _extract_anomalies(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract anomaly records from data."""
        anomalies: list[dict[str, Any]] = []
        for source in data.values():
            if isinstance(source, dict):
                for item in source.get("anomalies", []):
                    if isinstance(item, dict):
                        anomalies.append(item)
        return anomalies

    def _extract_violations(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract policy violation records from data."""
        violations: list[dict[str, Any]] = []
        for source in data.values():
            if isinstance(source, dict):
                for item in source.get("policy_violations", source.get("violations", [])):  # type: ignore[union-attr]
                    if isinstance(item, dict):
                        violations.append(item)
        return violations

    # ------------------------------------------------------------------
    # Core report generation
    # ------------------------------------------------------------------

    def generate_report(
        self,
        config: ReportConfig,
        firewall_data: dict[str, Any] | None = None,
        interceptor_data: dict[str, Any] | None = None,
        baseline_data: dict[str, Any] | None = None,
    ) -> AuditReportRecord:
        """Generate an audit report in the configured format."""
        start_ms = time.time() * 1000.0
        combined_data: dict[str, Any] = {
            "firewall_data": firewall_data or {},
            "interceptor_data": interceptor_data or {},
            "baseline_data": baseline_data or {},
        }

        if config.format == ReportFormat.JSON:
            content = self.generate_json_report(config.agent_id, combined_data)
            content_str = str(content)
        elif config.format == ReportFormat.CSV:
            content_str = self.generate_csv_report(config.agent_id, combined_data)
        elif config.format == ReportFormat.HTML:
            content_str = self.generate_html_report(config.agent_id, combined_data)
        elif config.format == ReportFormat.MARKDOWN:
            content_str = self.generate_markdown_report(config.agent_id, combined_data)
        else:
            content_str = str(self.generate_json_report(config.agent_id, combined_data))

        elapsed_ms = time.time() * 1000.0 - start_ms
        self._generation_times.append(elapsed_ms)

        record = AuditReportRecord(
            agent_id=config.agent_id,
            scope=config.scope,
            format=config.format,
            sections_included=config.include_sections,
            size_bytes=len(content_str.encode()),
        )
        self._records.append(record)
        self._evict_if_needed()

        logger.info(
            "audit_report_generator.report_generated",
            report_id=record.id,
            format=config.format.value,
            size_bytes=record.size_bytes,
            elapsed_ms=round(elapsed_ms, 2),
        )
        return record

    def generate_json_report(self, agent_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """Generate a structured JSON audit report with all sections."""
        tool_calls = self._extract_tool_calls(data)
        anomalies = self._extract_anomalies(data)
        violations = self._extract_violations(data)
        summary = self.get_executive_summary(data)

        return {
            "report_type": "agent_audit",
            "agent_id": agent_id,
            "generated_at": time.time(),
            "sections": {
                "executive_summary": summary,
                "tool_calls": {
                    "total": len(tool_calls),
                    "records": tool_calls,
                },
                "anomalies": {
                    "total": len(anomalies),
                    "records": anomalies,
                },
                "policy_violations": {
                    "total": len(violations),
                    "records": violations,
                },
                "risk_timeline": self._build_risk_timeline(tool_calls),
                "recommendations": self._build_recommendations(summary, anomalies, violations),
            },
        }

    def generate_csv_report(self, agent_id: str, data: dict[str, Any]) -> str:
        """Generate a CSV report of all tool calls."""
        tool_calls = self._extract_tool_calls(data)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "timestamp",
                "tool_name",
                "decision",
                "risk_score",
                "latency_ms",
                "data_bytes",
                "anomaly_detected",
            ]
        )
        for call in tool_calls:
            writer.writerow(
                [
                    call.get("timestamp", ""),
                    call.get("tool_name", call.get("name", "")),
                    call.get("decision", call.get("status", "")),
                    call.get("risk_score", 0.0),
                    call.get("latency_ms", 0),
                    call.get("data_bytes", 0),
                    call.get("anomaly_detected", False),
                ]
            )
        return output.getvalue()

    def generate_html_report(self, agent_id: str, data: dict[str, Any]) -> str:
        """Generate a professional HTML audit report with inline CSS."""
        summary = self.get_executive_summary(data)
        tool_calls = self._extract_tool_calls(data)
        anomalies = self._extract_anomalies(data)
        violations = self._extract_violations(data)
        recommendations = self._build_recommendations(summary, anomalies, violations)

        anomaly_pct = summary.get("anomaly_rate", 0)
        risk_color = _SEVERITY_COLORS.get(
            "critical" if anomaly_pct > 10 else "high" if anomaly_pct > 5 else "medium",
            "#2563eb",
        )

        # Build tool-calls table rows
        tc_rows = ""
        for call in tool_calls[:100]:
            tc_rows += (
                f"<tr>"
                f"<td>{call.get('timestamp', '-')}</td>"
                f"<td>{call.get('tool_name', call.get('name', '-'))}</td>"
                f"<td>{call.get('decision', call.get('status', '-'))}</td>"
                f"<td>{call.get('risk_score', 0.0):.2f}</td>"
                f"<td>{call.get('latency_ms', 0)}</td>"
                f"<td>{call.get('data_bytes', 0)}</td>"
                f"<td>{'Yes' if call.get('anomaly_detected') else 'No'}</td>"
                f"</tr>\n"
            )

        # Build violations list
        viol_items = ""
        for v in violations[:50]:
            viol_items += f"<li>{v.get('description', v.get('policy', 'Unknown'))}</li>\n"

        # Build recommendations list
        rec_items = ""
        for r in recommendations:
            rec_items += f"<li>{r}</li>\n"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ShieldOps Audit Report — {agent_id}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         margin: 40px; color: #1a1a2e; background: #fafafa; }}
  h1 {{ color: #0f172a; border-bottom: 3px solid #2563eb; padding-bottom: 8px; }}
  h2 {{ color: #1e293b; margin-top: 32px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;
                   margin: 20px 0; }}
  .metric {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
             padding: 16px; text-align: center; }}
  .metric .value {{ font-size: 28px; font-weight: 700; color: #0f172a; }}
  .metric .label {{ font-size: 13px; color: #64748b; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th {{ background: #1e293b; color: #fff; padding: 10px 12px; text-align: left;
       font-size: 13px; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #e2e8f0; font-size: 13px; }}
  tr:hover {{ background: #f1f5f9; }}
  .risk-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
                 color: #fff; font-size: 12px; font-weight: 600; }}
  .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0;
             color: #94a3b8; font-size: 12px; }}
</style>
</head>
<body>
<h1>ShieldOps Agent Audit Report</h1>
<p><strong>Agent:</strong> {agent_id} &nbsp;|&nbsp;
   <strong>Generated:</strong> {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}</p>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="metric">
    <div class="value">{summary.get("total_calls", 0)}</div>
    <div class="label">Total Tool Calls</div>
  </div>
  <div class="metric">
    <div class="value" style="color:#dc2626">{summary.get("blocked_calls", 0)}</div>
    <div class="label">Blocked Calls</div>
  </div>
  <div class="metric">
    <div class="value" style="color:{risk_color}">{anomaly_pct:.1f}%</div>
    <div class="label">Anomaly Rate</div>
  </div>
  <div class="metric">
    <div class="value">{summary.get("avg_risk_score", 0):.2f}</div>
    <div class="label">Avg Risk Score</div>
  </div>
  <div class="metric">
    <div class="value">{summary.get("compliance_status", "N/A")}</div>
    <div class="label">Compliance Status</div>
  </div>
  <div class="metric">
    <div class="value">{len(summary.get("top_risks", []))}</div>
    <div class="label">Top Risks Identified</div>
  </div>
</div>

<h2>Tool Calls ({len(tool_calls)})</h2>
<table>
<tr><th>Timestamp</th><th>Tool</th><th>Decision</th><th>Risk Score</th>
    <th>Latency (ms)</th><th>Data (bytes)</th><th>Anomaly</th></tr>
{tc_rows if tc_rows else '<tr><td colspan="7">No tool calls recorded</td></tr>'}
</table>

<h2>Policy Violations ({len(violations)})</h2>
<ul>{viol_items if viol_items else "<li>No policy violations detected</li>"}</ul>

<h2>Recommendations</h2>
<ul>{rec_items if rec_items else "<li>No recommendations at this time</li>"}</ul>

<div class="footer">
  Generated by ShieldOps Audit Report Generator &mdash; Confidential
</div>
</body>
</html>"""

    def generate_markdown_report(self, agent_id: str, data: dict[str, Any]) -> str:
        """Generate a Markdown audit report for GitHub/docs."""
        summary = self.get_executive_summary(data)
        tool_calls = self._extract_tool_calls(data)
        anomalies = self._extract_anomalies(data)
        violations = self._extract_violations(data)
        recommendations = self._build_recommendations(summary, anomalies, violations)

        lines: list[str] = [
            "# ShieldOps Agent Audit Report",
            "",
            f"**Agent:** {agent_id}  ",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "",
            "## Executive Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Tool Calls | {summary.get('total_calls', 0)} |",
            f"| Blocked Calls | {summary.get('blocked_calls', 0)} |",
            f"| Anomaly Rate | {summary.get('anomaly_rate', 0):.1f}% |",
            f"| Avg Risk Score | {summary.get('avg_risk_score', 0):.2f} |",
            f"| Compliance Status | {summary.get('compliance_status', 'N/A')} |",
            "",
            f"## Tool Calls ({len(tool_calls)})",
            "",
            "| Timestamp | Tool | Decision | Risk | Latency | Anomaly |",
            "|-----------|------|----------|------|---------|---------|",
        ]
        for call in tool_calls[:50]:
            lines.append(
                f"| {call.get('timestamp', '-')} "
                f"| {call.get('tool_name', call.get('name', '-'))} "
                f"| {call.get('decision', call.get('status', '-'))} "
                f"| {call.get('risk_score', 0.0):.2f} "
                f"| {call.get('latency_ms', 0)}ms "
                f"| {'Yes' if call.get('anomaly_detected') else 'No'} |"
            )

        lines.extend(
            [
                "",
                f"## Policy Violations ({len(violations)})",
                "",
            ]
        )
        for v in violations[:30]:
            lines.append(f"- {v.get('description', v.get('policy', 'Unknown'))}")

        lines.extend(["", "## Recommendations", ""])
        for r in recommendations:
            lines.append(f"- {r}")

        lines.extend(
            [
                "",
                "---",
                "*Generated by ShieldOps Audit Report Generator*",
            ]
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def get_executive_summary(self, data: dict[str, Any]) -> dict[str, Any]:
        """Build an executive summary from combined data."""
        tool_calls = self._extract_tool_calls(data)
        anomalies = self._extract_anomalies(data)
        violations = self._extract_violations(data)

        total = len(tool_calls)
        blocked = sum(
            1 for c in tool_calls if c.get("decision") in ("blocked", "denied", "rejected")
        )
        anomaly_count = len(anomalies) + sum(1 for c in tool_calls if c.get("anomaly_detected"))
        anomaly_rate = (anomaly_count / total * 100.0) if total else 0.0
        risk_scores = [
            c.get("risk_score", 0.0)
            for c in tool_calls
            if isinstance(c.get("risk_score"), (int, float))
        ]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

        # Top risks from violations
        top_risks = [v.get("description", v.get("policy", "Unknown")) for v in violations[:5]]

        compliance_status = "compliant" if not violations else "non_compliant"

        return {
            "total_calls": total,
            "blocked_calls": blocked,
            "anomaly_rate": round(anomaly_rate, 2),
            "avg_risk_score": round(avg_risk, 4),
            "top_risks": top_risks,
            "compliance_status": compliance_status,
        }

    # ------------------------------------------------------------------
    # Internal helpers for report sections
    # ------------------------------------------------------------------

    def _build_risk_timeline(self, tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build a risk-over-time timeline from tool call data."""
        timeline: list[dict[str, Any]] = []
        for call in tool_calls:
            ts = call.get("timestamp")
            risk = call.get("risk_score", 0.0)
            if ts is not None:
                timeline.append({"timestamp": ts, "risk_score": risk})
        return sorted(timeline, key=lambda x: str(x.get("timestamp", "")))

    def _build_recommendations(
        self,
        summary: dict[str, Any],
        anomalies: list[dict[str, Any]],
        violations: list[dict[str, Any]],
    ) -> list[str]:
        """Generate actionable recommendations based on findings."""
        recs: list[str] = []
        anomaly_rate = summary.get("anomaly_rate", 0.0)
        if anomaly_rate > 10:
            recs.append(f"Anomaly rate is {anomaly_rate:.1f}% — review agent tool access policies.")
        if anomaly_rate > 5:
            recs.append("Consider tightening baseline thresholds for anomaly detection.")
        if summary.get("blocked_calls", 0) > 0:
            recs.append(
                f"{summary['blocked_calls']} calls were blocked — audit blocked tool "
                f"patterns for false positives."
            )
        if violations:
            recs.append(
                f"{len(violations)} policy violation(s) detected — remediate and "
                f"update OPA policies."
            )
        if summary.get("avg_risk_score", 0) > 0.7:
            recs.append("Average risk score exceeds 0.7 — escalate to security team for review.")
        if not recs:
            recs.append("No actionable findings — agent operations within normal parameters.")
        return recs

    # ------------------------------------------------------------------
    # Reporting & lifecycle
    # ------------------------------------------------------------------

    def generate_report_summary(self) -> AuditReportSummary:
        """Generate a summary of all reports generated."""
        by_format: dict[str, int] = {}
        by_scope: dict[str, int] = {}
        for rec in self._records:
            by_format[rec.format.value] = by_format.get(rec.format.value, 0) + 1
            by_scope[rec.scope.value] = by_scope.get(rec.scope.value, 0) + 1

        avg_time = (
            sum(self._generation_times) / len(self._generation_times)
            if self._generation_times
            else 0.0
        )
        return AuditReportSummary(
            total_reports=len(self._records),
            by_format=by_format,
            by_scope=by_scope,
            avg_generation_time_ms=round(avg_time, 2),
        )

    def get_stats(self) -> dict[str, Any]:
        """Return quick summary statistics."""
        summary = self.generate_report_summary()
        return {
            "total_reports": summary.total_reports,
            "by_format": summary.by_format,
            "by_scope": summary.by_scope,
            "avg_generation_time_ms": summary.avg_generation_time_ms,
        }

    def clear_data(self) -> dict[str, str]:
        """Clear all stored report records."""
        count = len(self._records)
        self._records.clear()
        self._generation_times.clear()
        logger.info("audit_report_generator.cleared", records_removed=count)
        return {"status": "cleared", "records_removed": str(count)}
