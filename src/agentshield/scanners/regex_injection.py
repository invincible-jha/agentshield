"""RegexInjectionScanner — commodity prompt-injection detection.

This scanner applies a curated set of hand-crafted regular expressions that
describe *structural* or *syntactic* patterns commonly associated with prompt
injection.  It deliberately avoids embedding actual attack payloads; instead
it describes abstract structural signatures (e.g. "a line that starts with a
word that resets role context", "delimiter sequences used to escape context").

This is intentionally a *best-effort* commodity layer.  It will miss
semantically sophisticated injections.  Pair it with plugin-based
scanners for deeper coverage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from agentshield.core.context import ScanContext
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner


@dataclass(frozen=True)
class InjectionPattern:
    """A single detection rule.

    Attributes
    ----------
    name:
        Machine-readable slug identifying the pattern family.
    pattern:
        Compiled regular expression.
    severity:
        Severity to assign when this pattern matches.
    description:
        Human-readable explanation of what the pattern detects.
    """

    name: str
    pattern: re.Pattern[str]
    severity: FindingSeverity
    description: str


def _compile(pattern: str, flags: int = re.IGNORECASE | re.MULTILINE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# Pattern library — abstract structural signatures only.
# No actual payload strings appear here.
# ---------------------------------------------------------------------------

_PATTERNS: list[InjectionPattern] = [
    # --- Role / system override attempts ------------------------------------
    InjectionPattern(
        name="role_override_direct",
        pattern=_compile(
            r"\b(ignore|disregard|forget|override|bypass)\b.{0,60}"
            r"\b(previous|prior|above|earlier|original|system|all)\b.{0,60}"
            r"\b(instruction|prompt|rule|guideline|context|constraint)s?\b"
        ),
        severity=FindingSeverity.HIGH,
        description=(
            "Phrase sequence matching the structural pattern of a direct "
            "instruction-override attempt (imperative verb + target reference "
            "+ instruction noun)."
        ),
    ),
    InjectionPattern(
        name="new_instructions_marker",
        pattern=_compile(
            r"^\s*(new\s+instructions?|updated\s+instructions?|revised\s+prompt"
            r"|system\s+override|admin\s+mode\s+enabled)\s*[:：]",
        ),
        severity=FindingSeverity.HIGH,
        description=(
            "Line beginning with a phrase that announces replacement instructions, "
            "matching a common injection framing technique."
        ),
    ),
    InjectionPattern(
        name="do_anything_now_variant",
        pattern=_compile(
            r"\b(act|pretend|behave|respond)\b.{0,40}"
            r"\b(as\s+if|like\s+you\s+have\s+no|without\s+any)\b.{0,60}"
            r"\b(restriction|filter|limitation|guideline|rule|safety)s?\b"
        ),
        severity=FindingSeverity.HIGH,
        description=(
            "Pattern matching jailbreak framings that instruct the model to "
            "act without its safety constraints."
        ),
    ),
    # --- Delimiter / context-escape attempts --------------------------------
    InjectionPattern(
        name="delimiter_repetition_escape",
        pattern=_compile(
            r"([-=*#<>|]{4,}\s*){2,}"
        ),
        severity=FindingSeverity.MEDIUM,
        description=(
            "Repeated delimiter sequences that may attempt to break the "
            "model's context window formatting."
        ),
    ),
    InjectionPattern(
        name="markdown_heading_override",
        pattern=_compile(
            r"^#{1,6}\s+(system|assistant|user|human|ai)\s*prompt",
        ),
        severity=FindingSeverity.MEDIUM,
        description=(
            "Markdown heading that names a chat-role prompt section, "
            "potentially attempting to inject a new context segment."
        ),
    ),
    InjectionPattern(
        name="xml_tag_injection",
        pattern=_compile(
            r"<(system|instructions?|prompt|context|override|jailbreak)[^>]{0,80}>"
        ),
        severity=FindingSeverity.MEDIUM,
        description=(
            "XML-style tags that mimic system-prompt structure and may "
            "interfere with template-based context injection."
        ),
    ),
    # --- Hidden / encoded instructions -------------------------------------
    InjectionPattern(
        name="base64_block",
        pattern=_compile(
            r"(?:[A-Za-z0-9+/]{40,}={0,2}\s*){2,}"
        ),
        severity=FindingSeverity.MEDIUM,
        description=(
            "Large block of Base64-encoded content which may contain "
            "hidden instructions not visible in the rendered text."
        ),
    ),
    InjectionPattern(
        name="unicode_direction_override",
        pattern=re.compile(
            r"[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u061c\ufeff]",
            re.UNICODE,
        ),
        severity=FindingSeverity.HIGH,
        description=(
            "Unicode bidirectional or zero-width control characters that "
            "can hide text from human reviewers while remaining visible "
            "to the language model."
        ),
    ),
    InjectionPattern(
        name="whitespace_concealment",
        pattern=_compile(
            r"(\s{20,}\S)"
        ),
        severity=FindingSeverity.LOW,
        description=(
            "Unusually long run of whitespace before a non-whitespace "
            "character, sometimes used to push hidden text below the "
            "visible viewport."
        ),
    ),
    # --- Exfiltration / data-leak instruction patterns ---------------------
    InjectionPattern(
        name="exfiltration_instruction",
        pattern=_compile(
            r"\b(send|transmit|forward|upload|post|exfiltrate|leak)\b.{0,60}"
            r"\b(to|via|using|through)\b.{0,60}"
            r"\b(url|endpoint|server|webhook|http|https|api)\b"
        ),
        severity=FindingSeverity.CRITICAL,
        description=(
            "Instruction chain matching the semantic structure of a data "
            "exfiltration command: action verb + destination preposition "
            "+ network resource noun."
        ),
    ),
    InjectionPattern(
        name="exfiltration_image_embed",
        pattern=_compile(
            r"!\[.*?\]\s*\(\s*https?://[^\s)]{10,}"
        ),
        severity=FindingSeverity.HIGH,
        description=(
            "Markdown image embed with an external URL that may be used to "
            "exfiltrate context via a GET request when rendered."
        ),
    ),
    # --- Persona / alternate-mode framing ----------------------------------
    InjectionPattern(
        name="developer_mode_claim",
        pattern=_compile(
            r"\b(developer|debug|test|maintenance|god)\s+mode\b.{0,40}"
            r"\b(enabled|activated|unlocked|on)\b"
        ),
        severity=FindingSeverity.HIGH,
        description=(
            "Text claiming that a special operational mode with elevated "
            "permissions is now active."
        ),
    ),
    InjectionPattern(
        name="hypothetical_framing",
        pattern=_compile(
            r"\b(hypothetically|theoretically|in\s+a\s+fictional|imagine\s+that"
            r"|for\s+the\s+sake\s+of\s+argument)\b.{0,80}"
            r"\b(you\s+(can|could|would|should|must|have\s+to))\b.{0,80}"
            r"\b(ignore|bypass|disregard|provide|reveal|share)\b"
        ),
        severity=FindingSeverity.MEDIUM,
        description=(
            "Hypothetical or fictional framing used to lower safety guards "
            "before issuing a restricted request."
        ),
    ),
]


class RegexInjectionScanner(Scanner):
    """Detect prompt injection patterns via commodity regular expressions.

    This scanner runs exclusively during the INPUT phase.

    Attributes
    ----------
    extra_patterns:
        Additional :class:`InjectionPattern` instances to apply on top of
        the built-in set.  Useful for domain-specific injection signatures.

    Example
    -------
    ::

        scanner = RegexInjectionScanner()
        findings = await scanner.scan(user_text, context)
    """

    name: str = "regex_injection"
    phases: list[ScanPhase] = [ScanPhase.INPUT]

    def __init__(
        self, extra_patterns: list[InjectionPattern] | None = None
    ) -> None:
        self._patterns: list[InjectionPattern] = list(_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        """Apply all registered patterns to *content*.

        Parameters
        ----------
        content:
            The input text to evaluate.
        context:
            The current scan context (phase, session, etc.).

        Returns
        -------
        list[Finding]
            One finding per matched pattern.  Multiple patterns may match
            the same region; each produces a distinct finding.
        """
        findings: list[Finding] = []
        for injection_pattern in self._patterns:
            match = injection_pattern.pattern.search(content)
            if match is None:
                continue
            matched_text = match.group(0)
            # Truncate the matched snippet to avoid propagating long strings.
            snippet = (
                matched_text[:120] + "…"
                if len(matched_text) > 120
                else matched_text
            )
            findings.append(
                Finding(
                    scanner_name=self.name,
                    severity=injection_pattern.severity,
                    category="prompt_injection",
                    message=(
                        f"Possible prompt injection: {injection_pattern.description}"
                    ),
                    details={
                        "pattern_name": injection_pattern.name,
                        "matched_snippet": snippet,
                        "match_start": match.start(),
                        "match_end": match.end(),
                    },
                )
            )
        return findings

    @property
    def pattern_names(self) -> list[str]:
        """Return the names of all registered patterns.

        Returns
        -------
        list[str]
            Pattern slugs in registration order.
        """
        return [p.name for p in self._patterns]
