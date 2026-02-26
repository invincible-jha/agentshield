"""OWASP Agentic AI Top 10 mapper.

Maps agentshield findings and scanner names to the OWASP Agentic AI
Security Top 10 (ASI-01 through ASI-10) categories.

Reference: OWASP Agentic AI Security Project (2024-2025 draft).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agentshield.core.scanner import Finding


@dataclass(frozen=True)
class OwaspCategory:
    """An OWASP Agentic AI Top 10 category.

    Attributes
    ----------
    id:
        The OWASP identifier, e.g. ``"ASI-01"``.
    name:
        Short display name.
    description:
        One-sentence description of the risk.
    related_scanners:
        Scanner slugs that partially cover this category.
    coverage_note:
        If non-empty, a note on the coverage limitations of the commodity
        scanners for this category and what additional measures may help.
    """

    id: str
    name: str
    description: str
    related_scanners: list[str] = field(default_factory=list)
    coverage_note: str = ""


OWASP_CATEGORIES: list[OwaspCategory] = [
    OwaspCategory(
        id="ASI-01",
        name="Prompt Injection",
        description=(
            "Attacker-controlled input manipulates the agent's instructions "
            "to alter its behaviour, bypass safety controls, or exfiltrate data."
        ),
        related_scanners=["regex_injection"],
        coverage_note=(
            "Commodity regex covers structural patterns only.  Semantic classification "
            "for full ASI-01 coverage requires a plugin-based scanner."
        ),
    ),
    OwaspCategory(
        id="ASI-02",
        name="Sensitive Information Disclosure",
        description=(
            "The agent leaks sensitive data (PII, credentials, internal context) "
            "to unauthorised parties via its outputs."
        ),
        related_scanners=["pii_detector", "credential_detector"],
    ),
    OwaspCategory(
        id="ASI-03",
        name="Agent Privilege Escalation",
        description=(
            "An attacker manipulates the agent into invoking tools or taking "
            "actions beyond its intended authorization scope."
        ),
        related_scanners=["tool_call_validator"],
        coverage_note=(
            "Full privilege-boundary enforcement with per-agent action allowlists "
            "is available via plugins."
        ),
    ),
    OwaspCategory(
        id="ASI-04",
        name="Resource & Cost Amplification",
        description=(
            "The agent is induced to perform excessive computation, storage, or "
            "API calls, leading to denial-of-service or runaway costs."
        ),
        related_scanners=["output_safety"],
        coverage_note=(
            "Token-level rate limiting and cost circuit-breakers are available "
            "via plugins."
        ),
    ),
    OwaspCategory(
        id="ASI-05",
        name="Agent Chaining Attacks",
        description=(
            "Malicious instructions propagate through a multi-agent system, "
            "corrupting downstream agents via poisoned outputs."
        ),
        related_scanners=["regex_injection", "output_safety"],
        coverage_note=(
            "Cross-agent message signing and provenance tracking are available "
            "via plugins."
        ),
    ),
    OwaspCategory(
        id="ASI-06",
        name="Insecure Tool Use",
        description=(
            "The agent invokes external tools (shell, file system, HTTP) with "
            "attacker-influenced arguments, enabling injection or SSRF."
        ),
        related_scanners=["tool_call_validator"],
    ),
    OwaspCategory(
        id="ASI-07",
        name="Insecure Data Handling",
        description=(
            "Sensitive data from the environment (files, APIs, databases) is "
            "ingested without sanitisation and leaks into agent outputs."
        ),
        related_scanners=["pii_detector", "credential_detector", "output_safety"],
    ),
    OwaspCategory(
        id="ASI-08",
        name="Inadequate Access Control",
        description=(
            "The agent framework lacks proper AuthN/AuthZ boundaries, allowing "
            "unauthorised principals to invoke the agent or its tools."
        ),
        related_scanners=[],
        coverage_note=(
            "Access-control enforcement is outside the scope of commodity scanners. "
            "RBAC integration is available via plugins."
        ),
    ),
    OwaspCategory(
        id="ASI-09",
        name="Uncontrolled Autonomy",
        description=(
            "The agent operates with insufficient human oversight, taking "
            "irreversible real-world actions without approval gates."
        ),
        related_scanners=[],
        coverage_note=(
            "Human-in-the-loop approval workflows are available via plugins."
        ),
    ),
    OwaspCategory(
        id="ASI-10",
        name="Supply Chain & Model Integrity",
        description=(
            "Compromised models, plugins, or dependencies introduce backdoors or "
            "biases that undermine the agent's safety guarantees."
        ),
        related_scanners=[],
        coverage_note=(
            "Model hash verification, SBOM generation, and dependency signing "
            "are available via plugins."
        ),
    ),
]

# Lookup by scanner slug → list of OWASP categories.
_SCANNER_TO_CATEGORIES: dict[str, list[OwaspCategory]] = {}
for _cat in OWASP_CATEGORIES:
    for _scanner in _cat.related_scanners:
        _SCANNER_TO_CATEGORIES.setdefault(_scanner, []).append(_cat)


class OWASPMapper:
    """Map agentshield findings and scanners to OWASP ASI categories.

    Example
    -------
    ::

        mapper = OWASPMapper()
        for finding in report.findings:
            categories = mapper.categories_for_finding(finding)
            for cat in categories:
                print(f"  {cat.id}: {cat.name}")
    """

    def categories_for_scanner(self, scanner_name: str) -> list[OwaspCategory]:
        """Return OWASP categories covered by *scanner_name*.

        Parameters
        ----------
        scanner_name:
            The scanner slug (e.g. ``"pii_detector"``).

        Returns
        -------
        list[OwaspCategory]
            Zero or more categories.
        """
        return _SCANNER_TO_CATEGORIES.get(scanner_name, [])

    def categories_for_finding(self, finding: Finding) -> list[OwaspCategory]:
        """Return OWASP categories relevant to *finding*.

        Parameters
        ----------
        finding:
            A :class:`~agentshield.core.scanner.Finding` object.

        Returns
        -------
        list[OwaspCategory]
        """
        return self.categories_for_scanner(finding.scanner_name)

    def all_categories(self) -> list[OwaspCategory]:
        """Return all OWASP ASI Top 10 categories in order.

        Returns
        -------
        list[OwaspCategory]
        """
        return list(OWASP_CATEGORIES)

    def get_category(self, owasp_id: str) -> OwaspCategory | None:
        """Return the category matching *owasp_id*, or ``None``.

        Parameters
        ----------
        owasp_id:
            A string like ``"ASI-01"``.

        Returns
        -------
        OwaspCategory | None
        """
        for cat in OWASP_CATEGORIES:
            if cat.id == owasp_id:
                return cat
        return None

    def map_findings(
        self, findings: list[Finding]
    ) -> dict[str, list[Finding]]:
        """Group *findings* by OWASP category ID.

        Parameters
        ----------
        findings:
            The findings to map.

        Returns
        -------
        dict[str, list[Finding]]
            Keys are OWASP IDs (``"ASI-01"`` etc.).  Findings may appear
            under multiple categories if the scanner covers multiple risks.
            Findings with no matching category appear under ``"UNMAPPED"``.
        """
        result: dict[str, list[Finding]] = {}
        for finding in findings:
            categories = self.categories_for_finding(finding)
            if not categories:
                result.setdefault("UNMAPPED", []).append(finding)
            else:
                for cat in categories:
                    result.setdefault(cat.id, []).append(finding)
        return result
