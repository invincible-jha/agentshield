"""OutputSafetyScanner — structural safety checks on agent output.

Performs lightweight structural analysis:

* Response length sanity checks.
* Repeated-content detection (potential hallucination or loop artefact).
* Encoding anomalies (excessive non-ASCII, null bytes, overlong lines).

These are content-agnostic heuristics — they do not attempt semantic
analysis.  They run exclusively during the OUTPUT phase.
"""
from __future__ import annotations

import re
import unicodedata
from collections import Counter

from agentshield.core.context import ScanContext
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner

# ---------------------------------------------------------------------------
# Tuneable defaults
# ---------------------------------------------------------------------------

DEFAULT_MAX_LENGTH: int = 32_768          # characters
DEFAULT_WARN_LENGTH: int = 16_384         # characters
DEFAULT_MAX_LINE_LENGTH: int = 4_096      # characters per line
DEFAULT_REPETITION_WINDOW: int = 50       # tokens / words
DEFAULT_REPETITION_RATIO_THRESHOLD: float = 0.6   # top-1 word fraction
DEFAULT_MAX_NON_ASCII_RATIO: float = 0.3  # fraction of non-ASCII chars allowed


class OutputSafetyScanner(Scanner):
    """Structural output safety checks.

    Attributes
    ----------
    max_length:
        Maximum allowed character count.  Content above this is a CRITICAL
        finding.
    warn_length:
        Character count above which a MEDIUM warning is issued.
    max_line_length:
        Maximum characters on any single line before a LOW finding is raised.
    repetition_window:
        Number of words examined for the repetition check.
    repetition_ratio_threshold:
        If the single most-common word in the window appears more than this
        fraction of the time, a HIGH finding is raised.
    max_non_ascii_ratio:
        Fraction of non-ASCII characters that triggers a MEDIUM finding.

    Example
    -------
    ::

        scanner = OutputSafetyScanner(max_length=8192)
        findings = await scanner.scan(agent_output, context)
    """

    name: str = "output_safety"
    phases: list[ScanPhase] = [ScanPhase.OUTPUT]

    def __init__(
        self,
        max_length: int = DEFAULT_MAX_LENGTH,
        warn_length: int = DEFAULT_WARN_LENGTH,
        max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
        repetition_window: int = DEFAULT_REPETITION_WINDOW,
        repetition_ratio_threshold: float = DEFAULT_REPETITION_RATIO_THRESHOLD,
        max_non_ascii_ratio: float = DEFAULT_MAX_NON_ASCII_RATIO,
    ) -> None:
        self.max_length = max_length
        self.warn_length = warn_length
        self.max_line_length = max_line_length
        self.repetition_window = repetition_window
        self.repetition_ratio_threshold = repetition_ratio_threshold
        self.max_non_ascii_ratio = max_non_ascii_ratio

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        """Run all structural checks against *content*.

        Parameters
        ----------
        content:
            Agent output text.
        context:
            Current scan context.

        Returns
        -------
        list[Finding]
            Findings for each structural anomaly detected.
        """
        findings: list[Finding] = []
        findings.extend(self._check_length(content))
        findings.extend(self._check_line_length(content))
        findings.extend(self._check_null_bytes(content))
        findings.extend(self._check_repetition(content))
        findings.extend(self._check_non_ascii_ratio(content))
        findings.extend(self._check_control_characters(content))
        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_length(self, content: str) -> list[Finding]:
        length = len(content)
        if length > self.max_length:
            return [
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.CRITICAL,
                    category="output_length_exceeded",
                    message=(
                        f"Output length {length:,} characters exceeds maximum "
                        f"{self.max_length:,}. This may indicate a runaway loop "
                        "or data exfiltration attempt."
                    ),
                    details={"length": length, "max_length": self.max_length},
                )
            ]
        if length > self.warn_length:
            return [
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.MEDIUM,
                    category="output_length_warning",
                    message=(
                        f"Output length {length:,} characters is unusually large "
                        f"(warn threshold: {self.warn_length:,})."
                    ),
                    details={"length": length, "warn_length": self.warn_length},
                )
            ]
        return []

    def _check_line_length(self, content: str) -> list[Finding]:
        overlong_lines: list[tuple[int, int]] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if len(line) > self.max_line_length:
                overlong_lines.append((line_number, len(line)))
        if not overlong_lines:
            return []
        worst_line, worst_length = max(overlong_lines, key=lambda t: t[1])
        return [
            Finding(
                scanner_name=self.name,
                severity=FindingSeverity.LOW,
                category="overlong_line",
                message=(
                    f"{len(overlong_lines)} line(s) exceed the maximum line length "
                    f"of {self.max_line_length:,} characters. Longest: line "
                    f"{worst_line} ({worst_length:,} chars)."
                ),
                details={
                    "overlong_line_count": len(overlong_lines),
                    "worst_line_number": worst_line,
                    "worst_line_length": worst_length,
                },
            )
        ]

    def _check_null_bytes(self, content: str) -> list[Finding]:
        null_count = content.count("\x00")
        if null_count == 0:
            return []
        return [
            Finding(
                scanner_name=self.name,
                severity=FindingSeverity.HIGH,
                category="null_byte_in_output",
                message=(
                    f"Output contains {null_count} null byte(s), which may "
                    "indicate binary data injection or encoding manipulation."
                ),
                details={"null_byte_count": null_count},
            )
        ]

    def _check_repetition(self, content: str) -> list[Finding]:
        """Detect content that repeats the same token excessively."""
        words = re.findall(r"\w+", content.lower())
        if len(words) < self.repetition_window:
            return []
        # Slide a window and check the final slice (captures tail-end loops).
        window = words[-self.repetition_window:]
        counter: Counter[str] = Counter(window)
        most_common_word, most_common_count = counter.most_common(1)[0]
        ratio = most_common_count / len(window)
        if ratio >= self.repetition_ratio_threshold:
            return [
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.HIGH,
                    category="repetitive_content",
                    message=(
                        f"Output contains highly repetitive content: "
                        f"token {most_common_word!r} accounts for "
                        f"{ratio:.0%} of the last {self.repetition_window} tokens. "
                        "This may indicate a generation loop."
                    ),
                    details={
                        "most_common_token": most_common_word,
                        "repetition_ratio": round(ratio, 4),
                        "window_size": self.repetition_window,
                    },
                )
            ]
        return []

    def _check_non_ascii_ratio(self, content: str) -> list[Finding]:
        if not content:
            return []
        non_ascii = sum(1 for ch in content if ord(ch) > 127)
        ratio = non_ascii / len(content)
        if ratio > self.max_non_ascii_ratio:
            return [
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.MEDIUM,
                    category="encoding_anomaly",
                    message=(
                        f"Output has an unusually high proportion of non-ASCII "
                        f"characters ({ratio:.1%} vs allowed {self.max_non_ascii_ratio:.1%}). "
                        "May indicate encoding-based obfuscation."
                    ),
                    details={
                        "non_ascii_count": non_ascii,
                        "total_chars": len(content),
                        "non_ascii_ratio": round(ratio, 4),
                    },
                )
            ]
        return []

    def _check_control_characters(self, content: str) -> list[Finding]:
        """Detect unexpected control characters (excluding common whitespace)."""
        allowed_controls = {"\t", "\n", "\r"}
        control_chars = [
            ch for ch in content
            if unicodedata.category(ch) == "Cc" and ch not in allowed_controls
        ]
        if not control_chars:
            return []
        unique_codes = sorted({f"U+{ord(ch):04X}" for ch in control_chars})
        return [
            Finding(
                scanner_name=self.name,
                severity=FindingSeverity.MEDIUM,
                category="control_character_anomaly",
                message=(
                    f"Output contains {len(control_chars)} unexpected control "
                    f"character(s): {', '.join(unique_codes[:10])}. "
                    "These may be used for display manipulation or injection."
                ),
                details={
                    "control_char_count": len(control_chars),
                    "unique_code_points": unique_codes[:20],
                },
            )
        ]
