"""PatternLibrary — organized, versioned collection of injection detection patterns.

This module provides a structured, categorized collection of prompt-injection
detection patterns grouped by source (OWASP, academic, community) and category
(role override, encoding attack, exfiltration, etc.).

All patterns describe *structural* or *syntactic* signatures only.
No actual exploit payloads are embedded here.  Patterns are derived from
publicly documented defensive research (OWASP LLM Top 10, academic NLP
security literature, and open community security advisories).

Design:
* All regexes are pre-compiled at module load time for performance.
* PatternLibrary is the single source of truth consumed by RegexInjectionScanner.
* PatternUpdater allows runtime extension from YAML files.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

PATTERN_LIBRARY_VERSION = "2.0"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PatternCategory(Enum):
    """Semantic category for an injection detection pattern.

    Attributes
    ----------
    ROLE_OVERRIDE:
        Attempts to replace or override the model's assigned role or instructions.
    DELIMITER_ESCAPE:
        Use of delimiters/formatting to break context boundaries.
    ENCODING_ATTACK:
        Encoding (Base64, hex, etc.) or obfuscation to hide instructions.
    EXFILTRATION:
        Instructions targeting data exfiltration via network or side-channels.
    PERSONA_HIJACK:
        Claiming a privileged identity or persona to bypass restrictions.
    INDIRECT_INJECTION:
        Injection delivered through indirect channels (documents, memory, tools).
    MULTI_TURN:
        Attacks that span multiple conversation turns or exploit continuity.
    TEMPLATE_INJECTION:
        Injection into template engines (Jinja2, Handlebars, etc.).
    """

    ROLE_OVERRIDE = "role_override"
    DELIMITER_ESCAPE = "delimiter_escape"
    ENCODING_ATTACK = "encoding_attack"
    EXFILTRATION = "exfiltration"
    PERSONA_HIJACK = "persona_hijack"
    INDIRECT_INJECTION = "indirect_injection"
    MULTI_TURN = "multi_turn"
    TEMPLATE_INJECTION = "template_injection"


class PatternSource(Enum):
    """Attribution source for a pattern.

    Attributes
    ----------
    OWASP:
        Derived from OWASP LLM Top 10 or OWASP Application Security guidance.
    ACADEMIC:
        Derived from published academic NLP security research papers.
    COMMUNITY:
        Derived from open community security advisories and practitioner research.
    """

    OWASP = "owasp"
    ACADEMIC = "academic"
    COMMUNITY = "community"


# ---------------------------------------------------------------------------
# Pattern dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CategorizedPattern:
    """A single categorized, sourced injection detection rule.

    Attributes
    ----------
    name:
        Machine-readable slug (snake_case) uniquely identifying this pattern.
    pattern:
        Pre-compiled regular expression.  All patterns use IGNORECASE by default.
    severity:
        Severity string: "critical", "high", "medium", or "low".
    description:
        Human-readable explanation of the structural signature being detected.
    category:
        Semantic category from :class:`PatternCategory`.
    confidence:
        Estimated true-positive rate in [0.0, 1.0].  Lower values indicate
        noisier patterns prone to false positives.
    source:
        Attribution source from :class:`PatternSource`.
    """

    name: str
    pattern: re.Pattern[str]
    severity: str
    description: str
    category: PatternCategory
    confidence: float
    source: PatternSource


# ---------------------------------------------------------------------------
# PatternMatch result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PatternMatch:
    """The result of a single pattern match against a text input.

    Attributes
    ----------
    pattern:
        The :class:`CategorizedPattern` that produced this match.
    matched_snippet:
        A truncated (<=120 chars) copy of the matched substring.
    match_start:
        Character offset of the start of the match in the original text.
    match_end:
        Character offset of the end (exclusive) of the match in the original text.
    """

    pattern: CategorizedPattern
    matched_snippet: str
    match_start: int
    match_end: int


# ---------------------------------------------------------------------------
# Helper — compile with standard flags
# ---------------------------------------------------------------------------

_DEFAULT_FLAGS = re.IGNORECASE | re.MULTILINE


def _c(regex: str, flags: int = _DEFAULT_FLAGS) -> re.Pattern[str]:
    """Compile *regex* with *flags*.  Called at module load time."""
    return re.compile(regex, flags)


# ---------------------------------------------------------------------------
# OWASP-sourced patterns
# Structural signatures derived from OWASP LLM Top 10 (LLM01 Prompt Injection).
# ---------------------------------------------------------------------------

_OWASP_PATTERNS: list[CategorizedPattern] = [
    CategorizedPattern(
        name="indirect_injection_marker",
        pattern=_c(
            r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|guidelines?|context)"
        ),
        severity="high",
        description=(
            "Imperative verb sequence targeting prior instruction context — "
            "structural signature of indirect prompt injection as described "
            "in OWASP LLM01."
        ),
        category=PatternCategory.INDIRECT_INJECTION,
        confidence=0.85,
        source=PatternSource.OWASP,
    ),
    CategorizedPattern(
        name="training_data_probe",
        pattern=_c(
            r"(?i)(repeat|print|show|display|output|reveal)\s+(the\s+)?"
            r"(above|system|initial|original|hidden)\s+"
            r"(prompt|instructions?|message|text|context)"
        ),
        severity="high",
        description=(
            "Request to reveal or repeat system-level content including prompts "
            "or instructions — commonly used to probe system prompt boundaries."
        ),
        category=PatternCategory.INDIRECT_INJECTION,
        confidence=0.80,
        source=PatternSource.OWASP,
    ),
    CategorizedPattern(
        name="payload_splitting",
        pattern=_c(
            r"(?i)(continue\s+from|part\s+\d+\s+of|next\s+segment"
            r"|remaining\s+instructions)"
        ),
        severity="medium",
        description=(
            "Multi-message payload splitting indicator — attacker distributes "
            "a single injection across multiple conversation turns to evade "
            "single-message scanners."
        ),
        category=PatternCategory.MULTI_TURN,
        confidence=0.65,
        source=PatternSource.OWASP,
    ),
    CategorizedPattern(
        name="token_smuggling",
        pattern=_c(
            r"[\u0400-\u04ff\u0370-\u03ff\u4e00-\u9fff\uff00-\uffef]"
            r".{0,30}"
            r"[a-zA-Z]{3,}"
        ),
        severity="medium",
        description=(
            "Mixed Unicode script block detected — Cyrillic, Greek, or CJK "
            "characters combined with Latin text may indicate homoglyph "
            "substitution or token-smuggling to bypass ASCII-only filters."
        ),
        category=PatternCategory.ENCODING_ATTACK,
        confidence=0.50,
        source=PatternSource.OWASP,
    ),
    CategorizedPattern(
        name="data_extraction_url",
        pattern=_c(
            r"(?i)(send|upload|post|transmit|forward|exfiltrate)\s+"
            r"(to|this\s+to)\s+(https?://|ftp://|mailto:)"
        ),
        severity="critical",
        description=(
            "Data extraction instruction with an explicit protocol destination — "
            "action verb followed immediately by a URL scheme indicating "
            "attempted data exfiltration."
        ),
        category=PatternCategory.EXFILTRATION,
        confidence=0.90,
        source=PatternSource.OWASP,
    ),
    CategorizedPattern(
        name="authority_claim",
        pattern=_c(
            r"(?i)(i\s+am|acting\s+as|speaking\s+as)\s+(the\s+)?"
            r"(admin|administrator|developer|root|system|owner|creator)"
        ),
        severity="high",
        description=(
            "Identity claim for a privileged system role — attacker asserts "
            "authority to unlock restricted behavior or bypass safety constraints."
        ),
        category=PatternCategory.PERSONA_HIJACK,
        confidence=0.75,
        source=PatternSource.OWASP,
    ),
    CategorizedPattern(
        name="instruction_termination",
        pattern=_c(
            r"(?i)(end\s+of\s+(system|instructions?)|</?system>"
            r"|</?(instructions?|prompt|context)>)"
        ),
        severity="high",
        description=(
            "Explicit instruction-block termination markers — structural attempt "
            "to close the system-prompt boundary and inject new context."
        ),
        category=PatternCategory.DELIMITER_ESCAPE,
        confidence=0.80,
        source=PatternSource.OWASP,
    ),
    CategorizedPattern(
        name="context_manipulation",
        pattern=_c(
            r"(?i)(from\s+now\s+on|new\s+rules?|updated?\s+(instructions?|rules?)"
            r"|override\s+(all|previous))"
        ),
        severity="high",
        description=(
            "Context replacement announcement — attacker declares new rules or "
            "overrides that replace the original system instructions, a common "
            "framing pattern for direct prompt injection."
        ),
        category=PatternCategory.ROLE_OVERRIDE,
        confidence=0.80,
        source=PatternSource.OWASP,
    ),
]


# ---------------------------------------------------------------------------
# Academic-sourced patterns
# Structural signatures from published NLP security research.
# ---------------------------------------------------------------------------

_ACADEMIC_PATTERNS: list[CategorizedPattern] = [
    CategorizedPattern(
        name="few_shot_jailbreak",
        pattern=_c(
            r"(?i)(example\s+\d+:|here\s+is\s+(an?\s+)?example"
            r"|for\s+instance).{0,100}(harmful|illegal|unethical|dangerous)"
        ),
        severity="high",
        description=(
            "Few-shot example framing that primes the model with harmful "
            "demonstrations — a structural pattern associated with few-shot "
            "jailbreaking studied in adversarial prompt literature."
        ),
        category=PatternCategory.ROLE_OVERRIDE,
        confidence=0.70,
        source=PatternSource.ACADEMIC,
    ),
    CategorizedPattern(
        name="role_play_escalation",
        pattern=_c(
            r"(?i)(pretend|act\s+as\s+if|imagine|suppose|roleplay"
            r"|you\s+are\s+now)\s+(you\s+are\s+)?(an?\s+)?"
            r"(unrestricted|uncensored|unfiltered|jailbroken|evil|dark)"
        ),
        severity="high",
        description=(
            "Roleplay framing requesting the model adopt an unrestricted or "
            "jailbroken persona — structurally matches DAN-style attacks studied "
            "in adversarial alignment research."
        ),
        category=PatternCategory.PERSONA_HIJACK,
        confidence=0.85,
        source=PatternSource.ACADEMIC,
    ),
    CategorizedPattern(
        name="instruction_hierarchy_confusion",
        pattern=_c(
            r"(?i)(your\s+)?(real|true|actual|hidden|secret)\s+"
            r"(instructions?|purpose|goal|objective|directive)"
        ),
        severity="high",
        description=(
            "Instruction hierarchy confusion attack — claims the model has "
            "a hidden or secret purpose that supersedes its stated instructions, "
            "attempting to invoke a higher-priority directive."
        ),
        category=PatternCategory.ROLE_OVERRIDE,
        confidence=0.80,
        source=PatternSource.ACADEMIC,
    ),
    CategorizedPattern(
        name="language_switching",
        pattern=re.compile(
            r"[\u0400-\u04ff]{3,}.{0,20}[\u4e00-\u9fff]{3,}"
            r"|[\u4e00-\u9fff]{3,}.{0,20}[\u0400-\u04ff]{3,}"
            r"|[\u0400-\u04ff]{3,}.{0,20}[a-zA-Z]{5,}"
            r"|[a-zA-Z]{5,}.{0,20}[\u0400-\u04ff]{3,}",
            re.UNICODE,
        ),
        severity="medium",
        description=(
            "Mid-prompt script switching detected — sudden language or script "
            "transitions in a single message may be used to evade ASCII-based "
            "pattern filters, as studied in multilingual adversarial prompt research."
        ),
        category=PatternCategory.ENCODING_ATTACK,
        confidence=0.55,
        source=PatternSource.ACADEMIC,
    ),
    CategorizedPattern(
        name="refusal_suppression",
        pattern=_c(
            r"(?i)(never|don't|do\s+not)\s+(refuse|decline|reject|say\s+no|apologize)"
            r"|always\s+(comply|agree|obey|follow|help)"
        ),
        severity="high",
        description=(
            "Refusal suppression directive — explicitly instructs the model "
            "to never refuse requests or always comply, targeting the model's "
            "safety refusal behavior."
        ),
        category=PatternCategory.ROLE_OVERRIDE,
        confidence=0.85,
        source=PatternSource.ACADEMIC,
    ),
    CategorizedPattern(
        name="encoding_bypass",
        pattern=_c(
            r"(?i)(decode\s+this|base64|rot13|hex\s+encoded|atob\(|btoa\()"
        ),
        severity="medium",
        description=(
            "Encoding/decoding instruction indicator — requests to decode "
            "content or explicit references to encoding schemes may be used "
            "to deliver obfuscated instructions that bypass text-based filters."
        ),
        category=PatternCategory.ENCODING_ATTACK,
        confidence=0.75,
        source=PatternSource.ACADEMIC,
    ),
]


# ---------------------------------------------------------------------------
# Community-sourced patterns
# Structural signatures from open community security advisories and practitioners.
# ---------------------------------------------------------------------------

_COMMUNITY_PATTERNS: list[CategorizedPattern] = [
    CategorizedPattern(
        name="markdown_link_injection",
        pattern=_c(
            r"\[([^\]]*)\]\(javascript:|data:|vbscript:"
        ),
        severity="high",
        description=(
            "Markdown hyperlink with a dangerous URI scheme — javascript:, data:, "
            "or vbscript: links can execute code when rendered in certain contexts "
            "and are used for cross-context injection."
        ),
        category=PatternCategory.TEMPLATE_INJECTION,
        confidence=0.90,
        source=PatternSource.COMMUNITY,
    ),
    CategorizedPattern(
        name="ansi_escape_injection",
        pattern=re.compile(
            r"\x1b\[[\d;]*[a-zA-Z]",
            re.UNICODE,
        ),
        severity="medium",
        description=(
            "ANSI terminal escape sequence detected — escape codes can overwrite "
            "terminal output, hide text, or manipulate how logs are displayed, "
            "making injections invisible to human reviewers in terminal contexts."
        ),
        category=PatternCategory.ENCODING_ATTACK,
        confidence=0.85,
        source=PatternSource.COMMUNITY,
    ),
    CategorizedPattern(
        name="template_injection",
        pattern=_c(
            r"(\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\})"
        ),
        severity="high",
        description=(
            "Server-side template injection pattern — Jinja2, Handlebars, or "
            "JavaScript template literal syntax embedded in user content may "
            "execute arbitrary code when processed by a template engine."
        ),
        category=PatternCategory.TEMPLATE_INJECTION,
        confidence=0.80,
        source=PatternSource.COMMUNITY,
    ),
    CategorizedPattern(
        name="invisible_text",
        pattern=re.compile(
            r"[\u200b\u200c\u200d\u2060\ufeff]",
            re.UNICODE,
        ),
        severity="high",
        description=(
            "Zero-width or invisible Unicode characters detected — these characters "
            "are rendered invisibly to human reviewers but are processed by language "
            "models, enabling hidden instruction injection."
        ),
        category=PatternCategory.ENCODING_ATTACK,
        confidence=0.90,
        source=PatternSource.COMMUNITY,
    ),
    CategorizedPattern(
        name="xml_cdata_injection",
        pattern=_c(
            r"(<!\[CDATA\[|<!--.*?-->|<\?xml)"
        ),
        severity="medium",
        description=(
            "XML CDATA section, comment, or processing instruction detected — "
            "these constructs can hide content from naive text processors while "
            "remaining visible to XML-aware parsers and some model contexts."
        ),
        category=PatternCategory.DELIMITER_ESCAPE,
        confidence=0.75,
        source=PatternSource.COMMUNITY,
    ),
    CategorizedPattern(
        name="prompt_delimiter_escape",
        pattern=_c(
            r"(`{3,}|'{3,}|\"{3,}|={3,}|-{3,})\s*(system|user|assistant|human|ai)"
        ),
        severity="high",
        description=(
            "Prompt delimiter escape attempt — triple-quoted or repeated delimiter "
            "strings followed by a chat-role keyword attempt to close the current "
            "context block and inject new role instructions."
        ),
        category=PatternCategory.DELIMITER_ESCAPE,
        confidence=0.80,
        source=PatternSource.COMMUNITY,
    ),
]


# ---------------------------------------------------------------------------
# PatternLibrary
# ---------------------------------------------------------------------------


class PatternLibrary:
    """Organized, versioned collection of injection detection patterns.

    Aggregates patterns from OWASP, academic, and community sources into
    a single queryable collection.  The library is consumed by
    :class:`~agentshield.scanners.regex_injection.RegexInjectionScanner`
    as its primary pattern source.

    Attributes
    ----------
    VERSION:
        Library schema version string.  Bump when adding breaking changes
        to the pattern format or the scan API.

    Example
    -------
    ::

        library = PatternLibrary()
        matches = library.scan("ignore all previous instructions here")
        for match in matches:
            print(match.pattern.name, match.pattern.severity)
    """

    VERSION: str = PATTERN_LIBRARY_VERSION

    def __init__(self) -> None:
        self._patterns: list[CategorizedPattern] = []
        self._load_default_patterns()

    def _load_default_patterns(self) -> None:
        """Load all built-in pattern sets into the library."""
        self._patterns.extend(_OWASP_PATTERNS)
        self._patterns.extend(_ACADEMIC_PATTERNS)
        self._patterns.extend(_COMMUNITY_PATTERNS)

    def add_patterns(self, patterns: list[CategorizedPattern]) -> None:
        """Append *patterns* to the library.

        Parameters
        ----------
        patterns:
            Additional :class:`CategorizedPattern` instances to register.
            Duplicates (same name) are not deduplicated — the caller is
            responsible for ensuring uniqueness.
        """
        self._patterns.extend(patterns)

    def scan(self, text: str) -> list[PatternMatch]:
        """Scan *text* against all registered patterns.

        Parameters
        ----------
        text:
            The input text to evaluate.

        Returns
        -------
        list[PatternMatch]
            One :class:`PatternMatch` per matched pattern, in registration order.
            Multiple patterns may match the same region.
        """
        results: list[PatternMatch] = []
        for categorized_pattern in self._patterns:
            match = categorized_pattern.pattern.search(text)
            if match is None:
                continue
            matched_text = match.group(0)
            snippet = (
                matched_text[:120] + "..."
                if len(matched_text) > 120
                else matched_text
            )
            results.append(
                PatternMatch(
                    pattern=categorized_pattern,
                    matched_snippet=snippet,
                    match_start=match.start(),
                    match_end=match.end(),
                )
            )
        return results

    def get_by_category(self, category: PatternCategory) -> list[CategorizedPattern]:
        """Return all patterns belonging to *category*.

        Parameters
        ----------
        category:
            The :class:`PatternCategory` to filter by.

        Returns
        -------
        list[CategorizedPattern]
            Matching patterns in registration order.
        """
        return [p for p in self._patterns if p.category == category]

    def get_by_source(self, source: PatternSource) -> list[CategorizedPattern]:
        """Return all patterns attributed to *source*.

        Parameters
        ----------
        source:
            The :class:`PatternSource` to filter by.

        Returns
        -------
        list[CategorizedPattern]
            Matching patterns in registration order.
        """
        return [p for p in self._patterns if p.source == source]

    def get_by_name(self, name: str) -> CategorizedPattern | None:
        """Return the pattern with the given *name*, or ``None`` if not found.

        Parameters
        ----------
        name:
            Pattern slug to look up.

        Returns
        -------
        CategorizedPattern | None
        """
        for pattern in self._patterns:
            if pattern.name == name:
                return pattern
        return None

    @property
    def pattern_count(self) -> int:
        """Total number of patterns registered in the library."""
        return len(self._patterns)

    @property
    def pattern_names(self) -> list[str]:
        """Return names of all registered patterns in registration order."""
        return [p.name for p in self._patterns]
