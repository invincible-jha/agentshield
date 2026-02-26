"""JSONReporter — write scan results to structured JSON files.

Produces machine-readable JSON reports from collections of
:class:`~agentshield.core.result.SecurityReport` objects.
"""
from __future__ import annotations

import json
from pathlib import Path

from agentshield.core.result import SecurityReport
from agentshield.reporting.summary import SecuritySummary


class JSONReporter:
    """Generate JSON reports from agentshield scan results.

    Example
    -------
    ::

        reporter = JSONReporter()

        # Write a full report to disk:
        output_path = reporter.generate(reports, Path("report.json"))

        # Get a summary as a JSON string:
        summary_str = reporter.summary_json(reports)
    """

    def generate(
        self, results: list[SecurityReport], output_path: Path
    ) -> Path:
        """Write a full JSON report for *results* to *output_path*.

        The report contains a summary block followed by a detailed listing
        of every finding across all scans.

        Parameters
        ----------
        results:
            Ordered list of :class:`~agentshield.core.result.SecurityReport`
            objects to include.
        output_path:
            Filesystem path for the output JSON file.  Parent directories
            must already exist.

        Returns
        -------
        Path
            The resolved absolute path of the written file.
        """
        resolved = output_path.resolve()
        payload = self._build_payload(results)
        resolved.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return resolved

    def summary_json(self, results: list[SecurityReport]) -> str:
        """Return the summary block as a compact JSON string.

        Parameters
        ----------
        results:
            Ordered list of :class:`~agentshield.core.result.SecurityReport`
            objects to summarise.

        Returns
        -------
        str
            A valid JSON document containing only the summary statistics.
        """
        summary = SecuritySummary.from_results(results)
        return json.dumps(summary.to_dict(), indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_payload(self, results: list[SecurityReport]) -> dict[str, object]:
        summary = SecuritySummary.from_results(results)
        scans: list[dict[str, object]] = [report.to_dict() for report in results]
        return {
            "agentshield_report": {
                "summary": summary.to_dict(),
                "scans": scans,
            }
        }
