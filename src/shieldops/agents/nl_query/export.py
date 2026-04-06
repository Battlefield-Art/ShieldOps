"""NL Query export — convert query results to markdown, CSV, and PDF."""

from __future__ import annotations

import csv
import io
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def export_to_markdown(result: dict[str, Any]) -> str:
    """Render a query result as a GitHub-flavored markdown table."""
    rows: list[dict[str, Any]] = result.get("rows", []) or []
    if not rows:
        return "_No results._"
    headers = list(rows[0].keys())
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        cells = [str(row.get(h, "")).replace("|", "\\|") for h in headers]
        lines.append("| " + " | ".join(cells) + " |")
    summary = result.get("summary")
    if summary:
        lines.insert(0, f"**Summary:** {summary}\n")
    return "\n".join(lines)


def export_to_csv(result: dict[str, Any]) -> bytes:
    """Render a query result as CSV bytes."""
    rows: list[dict[str, Any]] = result.get("rows", []) or []
    buf = io.StringIO()
    if not rows:
        return b""
    headers = list(rows[0].keys())
    writer = csv.DictWriter(buf, fieldnames=headers)
    writer.writeheader()
    for row in rows:
        writer.writerow({h: row.get(h, "") for h in headers})
    return buf.getvalue().encode("utf-8")


def export_to_pdf(result: dict[str, Any]) -> bytes:
    """Render a query result as a minimal PDF. Falls back to markdown bytes
    if reportlab is not installed."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table
    except ImportError:
        logger.warning("nl_query.export.pdf_fallback", reason="reportlab not installed")
        return export_to_markdown(result).encode("utf-8")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story: list[Any] = []
    story.append(Paragraph("ShieldOps NL Query Result", styles["Title"]))
    story.append(Spacer(1, 12))
    if result.get("summary"):
        story.append(Paragraph(str(result["summary"]), styles["Normal"]))
        story.append(Spacer(1, 12))
    rows: list[dict[str, Any]] = result.get("rows", []) or []
    if rows:
        headers = list(rows[0].keys())
        data = [headers] + [[str(r.get(h, "")) for h in headers] for r in rows]
        story.append(Table(data))
    doc.build(story)
    return buf.getvalue()
