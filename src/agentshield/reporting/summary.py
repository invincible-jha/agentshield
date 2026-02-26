"""SecuritySummary — aggregated statistics over a collection of scan results.

Provides :class:`SecuritySummary`, a lightweight dataclass that collapses a
list of :class:`~agentshield.core.result.SecurityReport` objects into a
concise statistics record suitable for dashboards, logging, and report headers.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agentshield.core.result import SecurityReport
from agentshield.core.scanner import FindingSeverity
from agentshield.owasp.mapper import OWASPMapper


@dataclass
class SecuritySummary:
    """Aggregated statistics over one or more :class:`SecurityReport` instances.

    Attributes
    ----------
    total_scans:
        Total number of :class:`SecurityReport` objects included in this summary.
    passed:
        Number of reports that produced no findings.
    failed:
        Number of reports that produced at least one finding.
    by_severity:
        Finding count keyed by severity level string (``"info"``, ``"low"``,
        ``"medium"``, ``"high"``, ``"critical"``).
    by_scanner:
        Finding count keyed by scanner name string.
    by_owasp:
        Finding count keyed by OWASP category value string
        (e.g. ``"ASI01:PromptInjection"``).

    Example
    -------
    ::

        reports = [await pipeline.scan_input(text) for text in inputs]
        summary = SecuritySummary.from_results(reports)
        print(summary.failed, "scans had findings")
    """

    total_scans: int = 0
    passed: int = 0
    failed: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_scanner: dict[str, int] = field(default_factory=dict)
    by_owasp: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_results(cls, results: list[SecurityReport]) -> SecuritySummary:
        """Build a :class:`SecuritySummary` from a list of security reports.

        Parameters
        ----------
        results:
            Ordered list of :class:`~agentshield.core.result.SecurityReport`
            objects to aggregate.  May be empty.

        Returns
        -------
        SecuritySummary
            Aggregated statistics.
        """
        mapper = OWASPMapper()

        by_severity: dict[str, int] = {sev.value: 0 for sev in FindingSeverity}
        by_scanner: dict[str, int] = {}
        by_owasp: dict[str, int] = {}

        total = len(results)
        passed = 0
        failed = 0

        for report in results:
            if report.is_clean:
                passed += 1
            else:
                failed += 1

            for finding in report.findings:
                # Severity tally.
                sev_key = finding.severity.value
                by_severity[sev_key] = by_severity.get(sev_key, 0) + 1

                # Scanner tally.
                by_scanner[finding.scanner_name] = (
                    by_scanner.get(finding.scanner_name, 0) + 1
                )

                # OWASP tally.
                for owasp_cat in mapper.map_result(finding):
                    by_owasp[owasp_cat.value] = by_owasp.get(owasp_cat.value, 0) + 1

        # Remove zero-count severity entries for cleaner output.
        by_severity_clean = {k: v for k, v in by_severity.items() if v > 0}

        return cls(
            total_scans=total,
            passed=passed,
            failed=failed,
            by_severity=by_severity_clean,
            by_scanner=by_scanner,
            by_owasp=by_owasp,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the summary to a plain Python dictionary.

        Returns
        -------
        dict[str, object]
            All fields as plain Python types.
        """
        return {
            "total_scans": self.total_scans,
            "passed": self.passed,
            "failed": self.failed,
            "pass_rate": (
                round(self.passed / self.total_scans, 4)
                if self.total_scans > 0
                else 1.0
            ),
            "by_severity": self.by_severity,
            "by_scanner": self.by_scanner,
            "by_owasp": self.by_owasp,
        }
