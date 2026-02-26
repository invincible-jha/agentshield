"""Report formatters — JSON, Markdown, and HTML.

Each formatter accepts a list of
:class:`~agentshield.core.scanner.Finding` objects and returns a
formatted string.  Formatters are pure functions wrapped in lightweight
classes to allow subclassing and registry-based selection.
"""
from __future__ import annotations

import html as html_lib
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from agentshield.core.scanner import Finding, FindingSeverity


class BaseFormatter(ABC):
    """Abstract base for all report formatters."""

    @abstractmethod
    def format(self, findings: list[Finding]) -> str:
        """Render *findings* as a formatted string.

        Parameters
        ----------
        findings:
            The list of findings to include in the report.

        Returns
        -------
        str
            The formatted report content.
        """


class JsonFormatter(BaseFormatter):
    """Render findings as a JSON document.

    Parameters
    ----------
    indent:
        Number of spaces used for JSON indentation.  Defaults to 2.
    """

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def format(self, findings: list[Finding]) -> str:
        report_dict: dict[str, object] = {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "total_findings": len(findings),
            "severity_counts": _count_severities(findings),
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(report_dict, indent=self.indent, ensure_ascii=False)


class MarkdownFormatter(BaseFormatter):
    """Render findings as a Markdown document."""

    def format(self, findings: list[Finding]) -> str:
        lines: list[str] = []
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.append("# agentshield Security Report")
        lines.append("")
        lines.append(f"**Generated:** {now}")
        lines.append(f"**Total findings:** {len(findings)}")
        lines.append("")

        if not findings:
            lines.append("_No security findings detected._")
            return "\n".join(lines)

        severity_counts = _count_severities(findings)
        lines.append("## Summary")
        lines.append("")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count:
                icon = _severity_icon(severity)
                lines.append(f"- {icon} **{severity.upper()}**: {count}")
        lines.append("")

        lines.append("## Findings")
        lines.append("")

        grouped: dict[str, list[Finding]] = {}
        for finding in findings:
            grouped.setdefault(finding.severity.value, []).append(finding)

        for severity_value in ["critical", "high", "medium", "low", "info"]:
            group = grouped.get(severity_value, [])
            if not group:
                continue
            icon = _severity_icon(severity_value)
            lines.append(f"### {icon} {severity_value.upper()}")
            lines.append("")
            for idx, finding in enumerate(group, start=1):
                lines.append(f"#### {idx}. [{finding.scanner_name}] {finding.category}")
                lines.append("")
                lines.append(f"**Message:** {finding.message}")
                if finding.details:
                    lines.append("")
                    lines.append("**Details:**")
                    lines.append("")
                    lines.append("```json")
                    lines.append(
                        json.dumps(finding.details, indent=2, ensure_ascii=False)
                    )
                    lines.append("```")
                lines.append("")

        return "\n".join(lines)


class HtmlFormatter(BaseFormatter):
    """Render findings as a self-contained HTML document."""

    def format(self, findings: list[Finding]) -> str:
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        rows = "\n".join(self._finding_row(f) for f in findings)

        empty_note = (
            '<p class="empty">No security findings detected.</p>' if not findings else ""
        )
        table = (
            f"""
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Scanner</th>
                  <th>Category</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {rows}
              </tbody>
            </table>
            """
            if findings
            else ""
        )

        severity_counts = _count_severities(findings)
        summary_items = "".join(
            f'<li><span class="badge {sev}">{sev.upper()}: {cnt}</span></li>'
            for sev, cnt in severity_counts.items()
            if cnt
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>agentshield Security Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           margin: 2rem; color: #1a1a1a; background: #f8f8f8; }}
    h1   {{ color: #111; border-bottom: 2px solid #e74c3c; padding-bottom: .4rem; }}
    .meta {{ color: #555; font-size: .9rem; margin-bottom: 1.5rem; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff;
             box-shadow: 0 1px 4px rgba(0,0,0,.1); border-radius: 6px;
             overflow: hidden; }}
    th, td {{ padding: .6rem 1rem; text-align: left; border-bottom: 1px solid #eee; }}
    th   {{ background: #2c3e50; color: #fff; font-weight: 600; }}
    tr:last-child td {{ border-bottom: none; }}
    .badge {{ display: inline-block; padding: .2rem .6rem; border-radius: 4px;
              font-size: .75rem; font-weight: 700; text-transform: uppercase; }}
    .critical {{ background: #c0392b; color: #fff; }}
    .high     {{ background: #e67e22; color: #fff; }}
    .medium   {{ background: #f1c40f; color: #333; }}
    .low      {{ background: #27ae60; color: #fff; }}
    .info     {{ background: #2980b9; color: #fff; }}
    .empty    {{ color: #27ae60; font-style: italic; }}
    ul.summary {{ list-style: none; padding: 0; display: flex; gap: .5rem;
                  flex-wrap: wrap; margin-bottom: 1rem; }}
  </style>
</head>
<body>
  <h1>agentshield Security Report</h1>
  <div class="meta">
    Generated: {html_lib.escape(now)} &nbsp;|&nbsp;
    Total findings: <strong>{len(findings)}</strong>
  </div>
  <ul class="summary">{summary_items}</ul>
  {empty_note}
  {table}
</body>
</html>
"""

    @staticmethod
    def _finding_row(finding: Finding) -> str:
        sev = finding.severity.value
        return (
            f"<tr>"
            f'<td><span class="badge {sev}">{html_lib.escape(sev.upper())}</span></td>'
            f"<td>{html_lib.escape(finding.scanner_name)}</td>"
            f"<td>{html_lib.escape(finding.category)}</td>"
            f"<td>{html_lib.escape(finding.message)}</td>"
            f"</tr>"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _count_severities(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {s.value: 0 for s in FindingSeverity}
    for finding in findings:
        counts[finding.severity.value] += 1
    # Remove zero-count entries for cleanliness.
    return {k: v for k, v in counts.items() if v > 0}


def _severity_icon(severity: str) -> str:
    return {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "low": "[LOW]",
        "info": "[INFO]",
    }.get(severity.lower(), "")
