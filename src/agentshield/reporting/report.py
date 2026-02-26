"""SecurityReportGenerator — create detailed security reports.

The generator delegates to the three concrete formatters in
:mod:`agentshield.reporting.formatters`.  It can be used standalone or
is called automatically by
:meth:`~agentshield.core.pipeline.SecurityPipeline.generate_report`.
"""
from __future__ import annotations

from agentshield.core.scanner import Finding
from agentshield.reporting.formatters import (
    HtmlFormatter,
    JsonFormatter,
    MarkdownFormatter,
)


class SecurityReportGenerator:
    """High-level report generator.

    Wraps the three concrete formatters and exposes a clean interface for
    generating reports from a list of
    :class:`~agentshield.core.scanner.Finding` objects.

    Example
    -------
    ::

        generator = SecurityReportGenerator()
        markdown_report = generator.generate_markdown(pipeline.findings)
        html_report     = generator.generate_html(pipeline.findings)
        json_report     = generator.generate_json(pipeline.findings)
    """

    def __init__(self) -> None:
        self._json_formatter = JsonFormatter()
        self._markdown_formatter = MarkdownFormatter()
        self._html_formatter = HtmlFormatter()

    def generate_json(self, findings: list[Finding]) -> str:
        """Generate a JSON report.

        Parameters
        ----------
        findings:
            All findings to include.

        Returns
        -------
        str
            A valid JSON document.
        """
        return self._json_formatter.format(findings)

    def generate_markdown(self, findings: list[Finding]) -> str:
        """Generate a Markdown report.

        Parameters
        ----------
        findings:
            All findings to include.

        Returns
        -------
        str
            A Markdown document suitable for display in GitHub, Notion, etc.
        """
        return self._markdown_formatter.format(findings)

    def generate_html(self, findings: list[Finding]) -> str:
        """Generate a self-contained HTML report.

        Parameters
        ----------
        findings:
            All findings to include.

        Returns
        -------
        str
            A complete HTML document that can be opened in a browser.
        """
        return self._html_formatter.format(findings)

    def generate(self, findings: list[Finding], format: str) -> str:
        """Generate a report in the specified format.

        Parameters
        ----------
        findings:
            All findings to include.
        format:
            One of ``"json"``, ``"markdown"``, or ``"html"``.

        Returns
        -------
        str
            The formatted report.

        Raises
        ------
        ValueError
            If *format* is not one of the supported values.
        """
        if format == "json":
            return self.generate_json(findings)
        if format in ("markdown", "md"):
            return self.generate_markdown(findings)
        if format == "html":
            return self.generate_html(findings)
        raise ValueError(
            f"Unsupported format {format!r}. Choose one of: 'json', 'markdown', 'html'."
        )
