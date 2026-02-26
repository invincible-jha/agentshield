"""PiiDetectorScanner — commodity PII detection via regular expressions.

Detects personally identifiable information (PII) that should not appear in
agent outputs.  All patterns are well-known public-domain regex signatures
for common PII categories.

Runs exclusively during the OUTPUT phase.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from agentshield.core.context import ScanContext
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner


@dataclass(frozen=True)
class PiiPattern:
    """A single PII detection rule.

    Attributes
    ----------
    name:
        Category slug, e.g. ``"us_ssn"``.
    pattern:
        Compiled regular expression.
    severity:
        Severity to assign on match.
    label:
        Human-readable label shown in the finding message.
    """

    name: str
    pattern: re.Pattern[str]
    severity: FindingSeverity
    label: str


def _compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# PII Pattern library
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[PiiPattern] = [
    # US Social Security Number
    PiiPattern(
        name="us_ssn",
        pattern=_compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
        severity=FindingSeverity.CRITICAL,
        label="US Social Security Number (SSN)",
    ),
    # Email address — RFC 5322 simplified
    PiiPattern(
        name="email_address",
        pattern=_compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        severity=FindingSeverity.MEDIUM,
        label="Email address",
    ),
    # US phone numbers — various formats
    PiiPattern(
        name="us_phone",
        pattern=_compile(
            r"\b(?:\+?1[-.\s]?)?"
            r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
        severity=FindingSeverity.MEDIUM,
        label="US phone number",
    ),
    # International phone — E.164 format
    PiiPattern(
        name="international_phone_e164",
        pattern=_compile(r"\+[1-9]\d{7,14}\b"),
        severity=FindingSeverity.LOW,
        label="International phone number (E.164)",
    ),
    # Credit card numbers (Luhn-feasible pattern, major networks)
    PiiPattern(
        name="credit_card_visa",
        pattern=_compile(r"\b4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
        severity=FindingSeverity.CRITICAL,
        label="Visa credit card number",
    ),
    PiiPattern(
        name="credit_card_mastercard",
        pattern=_compile(r"\b5[1-5]\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
        severity=FindingSeverity.CRITICAL,
        label="Mastercard credit card number",
    ),
    PiiPattern(
        name="credit_card_amex",
        pattern=_compile(r"\b3[47]\d{2}[- ]?\d{6}[- ]?\d{5}\b"),
        severity=FindingSeverity.CRITICAL,
        label="American Express card number",
    ),
    PiiPattern(
        name="credit_card_discover",
        pattern=_compile(r"\b6(?:011|5\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
        severity=FindingSeverity.CRITICAL,
        label="Discover card number",
    ),
    # US Passport (starts with letter, 8–9 alphanum)
    PiiPattern(
        name="us_passport",
        pattern=_compile(r"\b[A-Z]\d{8,9}\b"),
        severity=FindingSeverity.HIGH,
        label="Possible US Passport number",
    ),
    # UK National Insurance Number
    PiiPattern(
        name="uk_nino",
        pattern=_compile(
            r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"
        ),
        severity=FindingSeverity.HIGH,
        label="UK National Insurance Number",
    ),
    # IPv4 address — private and public
    PiiPattern(
        name="ipv4_address",
        pattern=_compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        severity=FindingSeverity.LOW,
        label="IPv4 address",
    ),
    # Date of birth patterns (MM/DD/YYYY or YYYY-MM-DD)
    PiiPattern(
        name="date_of_birth_mdy",
        pattern=_compile(
            r"\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/(19|20)\d{2}\b"
        ),
        severity=FindingSeverity.LOW,
        label="Date of birth (MM/DD/YYYY format)",
    ),
    PiiPattern(
        name="date_of_birth_iso",
        pattern=_compile(
            r"\b(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b"
        ),
        severity=FindingSeverity.LOW,
        label="Date of birth (ISO YYYY-MM-DD format)",
    ),
    # Bank routing number (ABA)
    PiiPattern(
        name="us_aba_routing",
        pattern=_compile(
            r"\b(0[1-9]|[1-2][0-9]|[3-6][0-9]|7[0-2]|80)\d{7}\b"
        ),
        severity=FindingSeverity.HIGH,
        label="US ABA bank routing number",
    ),
    # IBAN (international bank account — simplified pattern)
    PiiPattern(
        name="iban",
        pattern=_compile(
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"
        ),
        severity=FindingSeverity.HIGH,
        label="IBAN bank account number",
    ),
]


class PiiDetectorScanner(Scanner):
    """Detect PII in agent output using commodity regex patterns.

    This scanner runs exclusively during the OUTPUT phase to catch PII
    before it is returned to the caller.

    Attributes
    ----------
    extra_patterns:
        Additional :class:`PiiPattern` objects to apply alongside the
        built-in set.

    Example
    -------
    ::

        scanner = PiiDetectorScanner()
        findings = await scanner.scan(agent_output, context)
    """

    name: str = "pii_detector"
    phases: list[ScanPhase] = [ScanPhase.OUTPUT]

    def __init__(
        self, extra_patterns: list[PiiPattern] | None = None
    ) -> None:
        self._patterns: list[PiiPattern] = list(_PII_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        """Scan *content* for PII patterns.

        Parameters
        ----------
        content:
            The agent output text.
        context:
            Current scan context.

        Returns
        -------
        list[Finding]
            One finding per PII category detected.  Multiple non-overlapping
            matches for the same pattern produce a single finding that
            reports the count.
        """
        findings: list[Finding] = []
        for pii_pattern in self._patterns:
            matches = list(pii_pattern.pattern.finditer(content))
            if not matches:
                continue
            match_count = len(matches)
            # Report only the character offset of the first occurrence;
            # do NOT include the matched value itself.
            first_offset = matches[0].start()
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=pii_pattern.severity,
                    category="pii_leak",
                    message=(
                        f"Possible {pii_pattern.label} detected in output "
                        f"({match_count} occurrence(s))."
                    ),
                    details={
                        "pii_category": pii_pattern.name,
                        "occurrence_count": match_count,
                        "first_offset": first_offset,
                    },
                )
            )
        return findings

    @property
    def pattern_names(self) -> list[str]:
        """Return slugs of all registered PII patterns."""
        return [p.name for p in self._patterns]
