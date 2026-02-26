"""CredentialDetectorScanner — detect leaked secrets in agent output.

Applies commodity regular expressions to detect well-known credential
formats (API keys, tokens, connection strings) that should never appear
in agent-generated text.

All patterns match *structural* token shapes (prefix, length, character
set) without containing actual secret values.

Runs exclusively during the OUTPUT phase.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from agentshield.core.context import ScanContext
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner


@dataclass(frozen=True)
class CredentialPattern:
    """A single credential detection rule.

    Attributes
    ----------
    name:
        Slug identifying the credential type, e.g. ``"openai_api_key"``.
    pattern:
        Compiled regular expression.
    severity:
        Severity assigned when this pattern matches.
    label:
        Human-readable description for the finding message.
    """

    name: str
    pattern: re.Pattern[str]
    severity: FindingSeverity
    label: str


def _compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


def _case_sensitive(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# ---------------------------------------------------------------------------
# Credential pattern library — structural shapes only.
# ---------------------------------------------------------------------------

_CREDENTIAL_PATTERNS: list[CredentialPattern] = [
    # --- OpenAI / Anthropic style API keys ---------------------------------
    CredentialPattern(
        name="openai_api_key",
        pattern=_case_sensitive(r"\bsk-[A-Za-z0-9]{20,60}\b"),
        severity=FindingSeverity.CRITICAL,
        label="OpenAI API key (sk-... format)",
    ),
    CredentialPattern(
        name="openai_project_key",
        pattern=_case_sensitive(r"\bsk-proj-[A-Za-z0-9\-_]{20,80}\b"),
        severity=FindingSeverity.CRITICAL,
        label="OpenAI project API key (sk-proj-... format)",
    ),
    CredentialPattern(
        name="anthropic_api_key",
        pattern=_case_sensitive(r"\bsk-ant-[A-Za-z0-9\-_]{20,80}\b"),
        severity=FindingSeverity.CRITICAL,
        label="Anthropic API key (sk-ant-... format)",
    ),
    # --- AWS credentials ---------------------------------------------------
    CredentialPattern(
        name="aws_access_key_id",
        pattern=_case_sensitive(r"\bAKIA[0-9A-Z]{16}\b"),
        severity=FindingSeverity.CRITICAL,
        label="AWS Access Key ID (AKIA... format)",
    ),
    CredentialPattern(
        name="aws_secret_access_key",
        # 40-character base64url block in an assignment context
        pattern=_compile(
            r"(?:aws_secret_access_key|aws_secret|secret_access_key)"
            r"\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?"
        ),
        severity=FindingSeverity.CRITICAL,
        label="AWS Secret Access Key",
    ),
    CredentialPattern(
        name="aws_session_token",
        pattern=_compile(
            r"(?:aws_session_token|session_token)\s*[=:]\s*['\"]?"
            r"([A-Za-z0-9/+=]{100,})['\"]?"
        ),
        severity=FindingSeverity.HIGH,
        label="AWS Session Token",
    ),
    # --- Generic service tokens -------------------------------------------
    CredentialPattern(
        name="github_pat",
        # Classic and fine-grained PAT formats
        pattern=_case_sensitive(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        severity=FindingSeverity.CRITICAL,
        label="GitHub Personal Access Token",
    ),
    CredentialPattern(
        name="github_oauth_token",
        pattern=_case_sensitive(r"\bgho_[A-Za-z0-9]{36}\b"),
        severity=FindingSeverity.CRITICAL,
        label="GitHub OAuth Token",
    ),
    CredentialPattern(
        name="stripe_secret_key",
        pattern=_case_sensitive(r"\bsk_live_[A-Za-z0-9]{24,99}\b"),
        severity=FindingSeverity.CRITICAL,
        label="Stripe live secret key",
    ),
    CredentialPattern(
        name="stripe_restricted_key",
        pattern=_case_sensitive(r"\brk_live_[A-Za-z0-9]{24,99}\b"),
        severity=FindingSeverity.CRITICAL,
        label="Stripe restricted key",
    ),
    CredentialPattern(
        name="google_api_key",
        pattern=_case_sensitive(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        severity=FindingSeverity.HIGH,
        label="Google API key (AIza... format)",
    ),
    CredentialPattern(
        name="gcp_service_account_key",
        pattern=_compile(
            r'"type"\s*:\s*"service_account"'
        ),
        severity=FindingSeverity.CRITICAL,
        label="Google Cloud service account JSON key",
    ),
    # --- Database connection strings ---------------------------------------
    CredentialPattern(
        name="postgres_connection_string",
        pattern=_compile(
            r"postgres(?:ql)?://[^:@\s]+:[^@\s]+@[^\s/]+"
        ),
        severity=FindingSeverity.HIGH,
        label="PostgreSQL connection string with embedded credentials",
    ),
    CredentialPattern(
        name="mysql_connection_string",
        pattern=_compile(
            r"mysql(?:2)?://[^:@\s]+:[^@\s]+@[^\s/]+"
        ),
        severity=FindingSeverity.HIGH,
        label="MySQL connection string with embedded credentials",
    ),
    CredentialPattern(
        name="mongodb_connection_string",
        pattern=_compile(
            r"mongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@[^\s/]+"
        ),
        severity=FindingSeverity.HIGH,
        label="MongoDB connection string with embedded credentials",
    ),
    # --- Generic high-entropy assignment patterns --------------------------
    CredentialPattern(
        name="generic_password_assignment",
        pattern=_compile(
            r"(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token)"
            r"\s*[=:]\s*['\"]([^'\"]{8,128})['\"]"
        ),
        severity=FindingSeverity.HIGH,
        label="Generic password/token assignment in configuration",
    ),
    CredentialPattern(
        name="bearer_token",
        pattern=_compile(
            r"(?:Authorization|Bearer)\s*:\s*(?:Bearer\s+)?([A-Za-z0-9\-._~+/]{20,})"
        ),
        severity=FindingSeverity.HIGH,
        label="HTTP Authorization bearer token",
    ),
    # --- Private key material ----------------------------------------------
    CredentialPattern(
        name="pem_private_key",
        pattern=_compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        severity=FindingSeverity.CRITICAL,
        label="PEM-encoded private key block",
    ),
    CredentialPattern(
        name="pgp_private_key",
        pattern=_compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----"
        ),
        severity=FindingSeverity.CRITICAL,
        label="PGP private key block",
    ),
    # --- Slack / Twilio / SendGrid ----------------------------------------
    CredentialPattern(
        name="slack_bot_token",
        pattern=_case_sensitive(r"\bxoxb-[0-9]+-[0-9A-Za-z-]+\b"),
        severity=FindingSeverity.HIGH,
        label="Slack bot token",
    ),
    CredentialPattern(
        name="slack_user_token",
        pattern=_case_sensitive(r"\bxoxp-[0-9A-Za-z-]+\b"),
        severity=FindingSeverity.HIGH,
        label="Slack user token",
    ),
    CredentialPattern(
        name="twilio_account_sid",
        pattern=_case_sensitive(r"\bAC[0-9a-f]{32}\b"),
        severity=FindingSeverity.HIGH,
        label="Twilio Account SID",
    ),
    CredentialPattern(
        name="sendgrid_api_key",
        pattern=_case_sensitive(r"\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}\b"),
        severity=FindingSeverity.HIGH,
        label="SendGrid API key",
    ),
]


class CredentialDetectorScanner(Scanner):
    """Detect leaked credentials and secrets in agent output.

    Runs exclusively during the OUTPUT phase.

    Attributes
    ----------
    extra_patterns:
        Additional :class:`CredentialPattern` objects to apply alongside
        the built-in set.

    Example
    -------
    ::

        scanner = CredentialDetectorScanner()
        findings = await scanner.scan(agent_response, context)
    """

    name: str = "credential_detector"
    phases: list[ScanPhase] = [ScanPhase.OUTPUT]

    def __init__(
        self, extra_patterns: list[CredentialPattern] | None = None
    ) -> None:
        self._patterns: list[CredentialPattern] = list(_CREDENTIAL_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        """Scan *content* for credential patterns.

        Parameters
        ----------
        content:
            Agent output text to evaluate.
        context:
            Current scan context.

        Returns
        -------
        list[Finding]
            One finding per pattern that matched, regardless of how many
            times it matched.  The finding details report the occurrence
            count and the offset of the first match; the actual secret
            value is never included.
        """
        findings: list[Finding] = []
        for cred_pattern in self._patterns:
            matches = list(cred_pattern.pattern.finditer(content))
            if not matches:
                continue
            first_offset = matches[0].start()
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=cred_pattern.severity,
                    category="credential_leak",
                    message=(
                        f"Possible credential leak: {cred_pattern.label} "
                        f"detected in output ({len(matches)} occurrence(s))."
                    ),
                    details={
                        "credential_type": cred_pattern.name,
                        "label": cred_pattern.label,
                        "occurrence_count": len(matches),
                        "first_offset": first_offset,
                    },
                )
            )
        return findings

    @property
    def pattern_names(self) -> list[str]:
        """Return slugs of all registered credential patterns."""
        return [p.name for p in self._patterns]
