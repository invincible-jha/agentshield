"""HTMLReporter — write scan results to a self-contained HTML report.

Produces a readable, colour-coded HTML document from a collection of
:class:`~agentshield.core.result.SecurityReport` objects.  The document
uses inline CSS so that it can be opened without any external assets.
"""
from __future__ import annotations

import html
from pathlib import Path

from agentshield.core.result import SecurityReport
from agentshield.core.scanner import FindingSeverity
from agentshield.reporting.summary import SecuritySummary

# ---------------------------------------------------------------------------
# Severity colour palette (background colour for table rows / badges)
# ---------------------------------------------------------------------------

_SEVERITY_COLOURS: dict[str, str] = {
    FindingSeverity.CRITICAL.value: "#c0392b",
    FindingSeverity.HIGH.value: "#e74c3c",
    FindingSeverity.MEDIUM.value: "#e67e22",
    FindingSeverity.LOW.value: "#f1c40f",
    FindingSeverity.INFO.value: "#3498db",
}

_SEVERITY_TEXT_COLOURS: dict[str, str] = {
    FindingSeverity.CRITICAL.value: "#ffffff",
    FindingSeverity.HIGH.value: "#ffffff",
    FindingSeverity.MEDIUM.value: "#ffffff",
    FindingSeverity.LOW.value: "#2c3e50",
    FindingSeverity.INFO.value: "#ffffff",
}

_INLINE_CSS = """
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f8f9fa;
    color: #2c3e50;
    margin: 0;
    padding: 2rem;
    line-height: 1.6;
}
h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 0.5rem; }
h2 { color: #34495e; margin-top: 2rem; }
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
}
.stat-card {
    background: #fff;
    border-radius: 8px;
    padding: 1rem 1.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.08);
    text-align: center;
}
.stat-card .value { font-size: 2rem; font-weight: 700; color: #2c3e50; }
.stat-card .label { font-size: 0.85rem; color: #7f8c8d; margin-top: 0.25rem; }
table {
    width: 100%;
    border-collapse: collapse;
    background: #fff;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 2px 4px rgba(0,0,0,0.08);
    margin-top: 1rem;
}
th {
    background: #2c3e50;
    color: #fff;
    padding: 0.75rem 1rem;
    text-align: left;
    font-weight: 600;
    font-size: 0.9rem;
}
td { padding: 0.65rem 1rem; border-bottom: 1px solid #ecf0f1; font-size: 0.9rem; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #f5f6fa; }
.badge {
    display: inline-block;
    padding: 0.2em 0.65em;
    border-radius: 12px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    text-transform: uppercase;
}
.no-findings { color: #27ae60; font-weight: 600; padding: 1rem 0; }
.details-pre {
    background: #f4f6f9;
    border: 1px solid #dde1e7;
    border-radius: 4px;
    padding: 0.4rem 0.6rem;
    font-size: 0.8rem;
    max-width: 420px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
}
""".strip()


class HTMLReporter:
    """Generate self-contained HTML security reports.

    Example
    -------
    ::

        reporter = HTMLReporter()
        path = reporter.generate(reports, Path("report.html"))
        print("Report written to", path)
    """

    def generate(
        self, results: list[SecurityReport], output_path: Path
    ) -> Path:
        """Write a full HTML report for *results* to *output_path*.

        Parameters
        ----------
        results:
            Ordered list of :class:`~agentshield.core.result.SecurityReport`
            objects to include.
        output_path:
            Filesystem path for the output HTML file.  Parent directories
            must already exist.

        Returns
        -------
        Path
            The resolved absolute path of the written file.
        """
        resolved = output_path.resolve()
        document = self._render_document(results)
        resolved.write_text(document, encoding="utf-8")
        return resolved

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------

    def _render_document(self, results: list[SecurityReport]) -> str:
        summary = SecuritySummary.from_results(results)
        summary_html = self._render_summary(summary)
        scans_html = self._render_scans(results)

        return (
            "<!DOCTYPE html>\n"
            "<html lang='en'>\n"
            "<head>\n"
            "<meta charset='UTF-8'>\n"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
            "<title>AgentShield Security Report</title>\n"
            f"<style>{_INLINE_CSS}</style>\n"
            "</head>\n"
            "<body>\n"
            "<h1>AgentShield Security Report</h1>\n"
            f"{summary_html}\n"
            f"{scans_html}\n"
            "</body>\n"
            "</html>\n"
        )

    def _render_summary(self, summary: SecuritySummary) -> str:
        pass_rate = (
            round(summary.passed / summary.total_scans * 100, 1)
            if summary.total_scans > 0
            else 100.0
        )

        cards: list[str] = [
            self._stat_card(str(summary.total_scans), "Total Scans"),
            self._stat_card(str(summary.passed), "Passed"),
            self._stat_card(str(summary.failed), "Failed"),
            self._stat_card(f"{pass_rate}%", "Pass Rate"),
        ]

        severity_order = [
            FindingSeverity.CRITICAL.value,
            FindingSeverity.HIGH.value,
            FindingSeverity.MEDIUM.value,
            FindingSeverity.LOW.value,
            FindingSeverity.INFO.value,
        ]
        for sev in severity_order:
            count = summary.by_severity.get(sev, 0)
            if count > 0:
                cards.append(self._stat_card(str(count), sev.upper()))

        cards_html = "\n".join(cards)
        return (
            "<h2>Summary</h2>\n"
            f"<div class='summary-grid'>{cards_html}</div>\n"
        )

    def _stat_card(self, value: str, label: str) -> str:
        return (
            "<div class='stat-card'>"
            f"<div class='value'>{html.escape(value)}</div>"
            f"<div class='label'>{html.escape(label)}</div>"
            "</div>"
        )

    def _render_scans(self, results: list[SecurityReport]) -> str:
        if not results:
            return "<p>No scan results to display.</p>"

        rows: list[str] = []
        for scan_index, report in enumerate(results, start=1):
            for finding in report.findings:
                bg_colour = _SEVERITY_COLOURS.get(finding.severity.value, "#95a5a6")
                text_colour = _SEVERITY_TEXT_COLOURS.get(
                    finding.severity.value, "#ffffff"
                )
                badge = (
                    f"<span class='badge' style='background:{bg_colour};"
                    f"color:{text_colour}'>"
                    f"{html.escape(finding.severity.value.upper())}</span>"
                )
                details_str = ", ".join(
                    f"{html.escape(k)}: {html.escape(str(v))}"
                    for k, v in finding.details.items()
                )
                rows.append(
                    "<tr>"
                    f"<td>{scan_index}</td>"
                    f"<td>{html.escape(report.phase)}</td>"
                    f"<td>{html.escape(finding.scanner_name)}</td>"
                    f"<td>{badge}</td>"
                    f"<td>{html.escape(finding.category)}</td>"
                    f"<td>{html.escape(finding.message)}</td>"
                    f"<td><pre class='details-pre'>{details_str}</pre></td>"
                    "</tr>"
                )

        if not rows:
            return (
                "<h2>Findings</h2>\n"
                "<p class='no-findings'>No findings detected across all scans.</p>\n"
            )

        table = (
            "<table>\n"
            "<thead><tr>"
            "<th>#</th>"
            "<th>Phase</th>"
            "<th>Scanner</th>"
            "<th>Severity</th>"
            "<th>Category</th>"
            "<th>Message</th>"
            "<th>Details</th>"
            "</tr></thead>\n"
            "<tbody>\n"
            + "\n".join(rows)
            + "\n</tbody>\n</table>"
        )

        return f"<h2>Findings ({len(rows)})</h2>\n{table}\n"
