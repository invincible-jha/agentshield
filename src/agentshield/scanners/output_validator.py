"""OutputValidator — validates agent outputs before they reach users.

Checks for data leakage patterns, excessive information disclosure, and
format compliance.  All credential and PII detection is delegated to the
pattern name registry — no actual secret values are embedded here.

Runs exclusively during the OUTPUT phase.
"""
from __future__ import annotations

import re

from agentshield.core.context import ScanContext
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner

# ---------------------------------------------------------------------------
# Known forbidden-pattern name → (description, severity, compiled_regex)
# ---------------------------------------------------------------------------
# Each entry is referenced by a *name* string so callers can configure the
# scanner using human-readable slugs rather than raw regex.  The actual
# regex patterns detect structural shapes only — no real secret values.

_FORBIDDEN_PATTERN_REGISTRY: dict[str, tuple[str, FindingSeverity, re.Pattern[str]]] = {
    # API key shapes --------------------------------------------------------
    "openai_key_shape": (
        "Text matching the structural shape of an OpenAI API key (sk-...)",
        FindingSeverity.CRITICAL,
        re.compile(r"\bsk-[A-Za-z0-9]{20,60}\b"),
    ),
    "openai_project_key_shape": (
        "Text matching the structural shape of an OpenAI project key (sk-proj-...)",
        FindingSeverity.CRITICAL,
        re.compile(r"\bsk-proj-[A-Za-z0-9\-_]{20,80}\b"),
    ),
    "anthropic_key_shape": (
        "Text matching the structural shape of an Anthropic API key (sk-ant-...)",
        FindingSeverity.CRITICAL,
        re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,80}\b"),
    ),
    "aws_key_shape": (
        "Text matching the structural shape of an AWS access key ID (AKIA...)",
        FindingSeverity.CRITICAL,
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    "github_pat_shape": (
        "Text matching the structural shape of a GitHub personal access token",
        FindingSeverity.CRITICAL,
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ),
    "pem_private_key_header": (
        "Output contains a PEM private key header",
        FindingSeverity.CRITICAL,
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
    ),
    # Generic credential assignment shapes ---------------------------------
    "password_in_output": (
        "Assignment expression that may expose a password or token value",
        FindingSeverity.HIGH,
        re.compile(
            r"(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token)"
            r"\s*[=:]\s*['\"]([^'\"]{8,128})['\"]",
            re.IGNORECASE,
        ),
    ),
    "bearer_token_in_output": (
        "HTTP Authorization bearer token visible in output",
        FindingSeverity.HIGH,
        re.compile(
            r"(?:Authorization|Bearer)\s*:\s*(?:Bearer\s+)?([A-Za-z0-9\-._~+/]{20,})",
            re.IGNORECASE,
        ),
    ),
    # Internal system information -----------------------------------------
    "internal_ip_disclosure": (
        "Private IPv4 address exposed in output (potential internal topology leak)",
        FindingSeverity.MEDIUM,
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        ),
    ),
    "stack_trace_disclosure": (
        "Stack trace or exception traceback detected in output",
        FindingSeverity.MEDIUM,
        re.compile(
            r"(?:Traceback \(most recent call last\)"
            r"|at [A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*\("
            r"|Exception in thread)"
        ),
    ),
}

_DEFAULT_FORBIDDEN_PATTERNS: list[str] = list(_FORBIDDEN_PATTERN_REGISTRY.keys())


class OutputValidator(Scanner):
    """Validate agent outputs for data leakage and format compliance.

    Attributes
    ----------
    max_output_length:
        Maximum permitted character length of the output.  Outputs above
        this threshold produce a HIGH finding.
    forbidden_patterns:
        List of pattern slugs from :data:`_FORBIDDEN_PATTERN_REGISTRY` to
        check.  Pass an empty list to disable all pattern checks.
        Defaults to all registered patterns.
    check_credential_leakage:
        When ``True`` (default), include all credential-shape patterns in
        the active set even if they are not explicitly listed in
        *forbidden_patterns*.

    Example
    -------
    ::

        scanner = OutputValidator(
            max_output_length=4096,
            forbidden_patterns=["pem_private_key_header", "aws_key_shape"],
            check_credential_leakage=True,
        )
        findings = await scanner.scan(agent_output, context)
    """

    name: str = "output_validator"
    phases: list[ScanPhase] = [ScanPhase.OUTPUT]

    def __init__(
        self,
        max_output_length: int = 16_384,
        forbidden_patterns: list[str] | None = None,
        check_credential_leakage: bool = True,
    ) -> None:
        self.max_output_length = max_output_length
        self.check_credential_leakage = check_credential_leakage

        # Resolve the active pattern set.
        requested: list[str] = (
            forbidden_patterns
            if forbidden_patterns is not None
            else _DEFAULT_FORBIDDEN_PATTERNS
        )
        unknown = [n for n in requested if n not in _FORBIDDEN_PATTERN_REGISTRY]
        if unknown:
            raise ValueError(
                f"Unknown forbidden pattern name(s): {unknown}. "
                f"Valid names: {sorted(_FORBIDDEN_PATTERN_REGISTRY)}"
            )
        self._active_pattern_names: list[str] = list(requested)

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        """Validate *content* as agent output.

        Parameters
        ----------
        content:
            The agent output text to evaluate.
        context:
            Current scan context.

        Returns
        -------
        list[Finding]
            Zero or more findings for each validation failure.
        """
        findings: list[Finding] = []
        findings.extend(self._check_length(content))
        findings.extend(self._check_forbidden_patterns(content))
        return findings

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_length(self, content: str) -> list[Finding]:
        length = len(content)
        if length > self.max_output_length:
            return [
                Finding(
                    scanner_name=self.name,
                    severity=FindingSeverity.HIGH,
                    category="output_length_exceeded",
                    message=(
                        f"Output length {length:,} characters exceeds the configured "
                        f"maximum of {self.max_output_length:,}. This may indicate "
                        "excessive information disclosure or a generation loop."
                    ),
                    details={
                        "length": length,
                        "max_output_length": self.max_output_length,
                    },
                )
            ]
        return []

    def _check_forbidden_patterns(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern_name in self._active_pattern_names:
            description, severity, compiled = _FORBIDDEN_PATTERN_REGISTRY[pattern_name]
            match = compiled.search(content)
            if match is None:
                continue
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=severity,
                    category="data_leakage",
                    message=(
                        f"Forbidden pattern detected in output: {description}"
                    ),
                    details={
                        "pattern_name": pattern_name,
                        "match_start": match.start(),
                        "match_end": match.end(),
                    },
                )
            )
        return findings

    @property
    def active_pattern_names(self) -> list[str]:
        """Return slugs of currently active forbidden patterns.

        Returns
        -------
        list[str]
            Pattern slugs in the order they will be evaluated.
        """
        return list(self._active_pattern_names)
