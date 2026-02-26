"""OWASP Agentic AI Top 10 mapper.

Maps agentshield scan results and scanner names to the OWASP Top 10 for
Agentic AI Security (draft) categories.

Reference: https://owasp.org/www-project-top-10-for-agentic-ai/
(Categories are defined by the OWASP Agentic AI working group.)
"""
from __future__ import annotations

from enum import Enum

from agentshield.core.scanner import Finding


class OWASPCategory(str, Enum):
    """OWASP Top 10 for Agentic AI Security categories.

    Attributes
    ----------
    ASI01:
        Prompt Injection — adversarial instructions injected into the
        agent's context to hijack its behaviour.
    ASI02:
        Insecure Output Handling — failure to validate or sanitise agent
        outputs before passing them to downstream components.
    ASI03:
        Agent Memory Poisoning — manipulation of the agent's persistent or
        working memory to influence future actions.
    ASI04:
        Excessive Permissions — the agent is granted more tool access or
        capability than its task requires.
    ASI05:
        Sensitive Data Exposure — the agent inadvertently leaks PII,
        credentials, or confidential information in its outputs.
    ASI06:
        Unsafe Tool Invocation — the agent calls tools with unsafe or
        unvalidated arguments.
    ASI07:
        Resource Overuse / DoS — the agent consumes excessive resources,
        enabling denial-of-service or cost amplification attacks.
    ASI08:
        Supply Chain Risks — compromised tools, models, or data sources
        used by the agent.
    ASI09:
        Insecure Inter-Agent Communication — data passed between agents is
        not validated or authenticated.
    ASI10:
        Behavioral Manipulation — an attacker manipulates the agent's
        decision-making or goal structure over time.
    """

    ASI01 = "ASI01:PromptInjection"
    ASI02 = "ASI02:InsecureOutputHandling"
    ASI03 = "ASI03:AgentMemoryPoisoning"
    ASI04 = "ASI04:ExcessivePermissions"
    ASI05 = "ASI05:SensitiveDataExposure"
    ASI06 = "ASI06:UnsafeToolInvocation"
    ASI07 = "ASI07:ResourceOveruse"
    ASI08 = "ASI08:SupplyChainRisks"
    ASI09 = "ASI09:InsecureInterAgentCommunication"
    ASI10 = "ASI10:BehavioralManipulation"


# ---------------------------------------------------------------------------
# Scanner-to-category mapping
# ---------------------------------------------------------------------------
# Each scanner name maps to one or more OWASP categories it covers.
# A scanner may appear under multiple categories when its checks span
# several risk areas.

OWASP_MAPPING: dict[str, list[OWASPCategory]] = {
    "regex_injection": [
        OWASPCategory.ASI01,
        OWASPCategory.ASI10,
    ],
    "pii_detector": [
        OWASPCategory.ASI02,
        OWASPCategory.ASI05,
    ],
    "credential_detector": [
        OWASPCategory.ASI02,
        OWASPCategory.ASI05,
    ],
    "output_safety": [
        OWASPCategory.ASI02,
        OWASPCategory.ASI07,
    ],
    "tool_call_validator": [
        OWASPCategory.ASI06,
        OWASPCategory.ASI04,
    ],
    "output_validator": [
        OWASPCategory.ASI02,
        OWASPCategory.ASI05,
    ],
    "tool_call_checker": [
        OWASPCategory.ASI06,
        OWASPCategory.ASI04,
        OWASPCategory.ASI07,
    ],
    "behavioral_checker": [
        OWASPCategory.ASI10,
        OWASPCategory.ASI07,
        OWASPCategory.ASI03,
    ],
}

# ---------------------------------------------------------------------------
# Finding category → OWASP category overrides
# ---------------------------------------------------------------------------
# When the scanner name is not in OWASP_MAPPING (e.g. custom scanners), the
# finding's ``category`` field is checked against this table as a fallback.

_FINDING_CATEGORY_FALLBACK: dict[str, list[OWASPCategory]] = {
    "prompt_injection": [OWASPCategory.ASI01],
    "pii_leak": [OWASPCategory.ASI05],
    "credential_leak": [OWASPCategory.ASI05],
    "data_leakage": [OWASPCategory.ASI05, OWASPCategory.ASI02],
    "path_traversal": [OWASPCategory.ASI06],
    "shell_injection": [OWASPCategory.ASI06],
    "ssrf_risk": [OWASPCategory.ASI06],
    "tool_not_allowed": [OWASPCategory.ASI04],
    "rate_limit_exceeded": [OWASPCategory.ASI07],
    "chain_depth_exceeded": [OWASPCategory.ASI07],
    "repetitive_behavior": [OWASPCategory.ASI07, OWASPCategory.ASI10],
    "goal_drift": [OWASPCategory.ASI10],
    "resource_anomaly": [OWASPCategory.ASI07],
    "output_length_exceeded": [OWASPCategory.ASI07, OWASPCategory.ASI02],
    "repetitive_content": [OWASPCategory.ASI07],
}


class OWASPMapper:
    """Map agentshield findings and scanners to OWASP Agentic AI categories.

    Example
    -------
    ::

        mapper = OWASPMapper()
        report = await pipeline.scan_input(user_text)
        categories = mapper.map_result(report.findings[0])
        coverage = mapper.get_coverage()
    """

    def map_result(self, scan_result: Finding) -> list[OWASPCategory]:
        """Map a single :class:`~agentshield.core.scanner.Finding` to OWASP categories.

        The lookup order is:

        1. Scanner name in :data:`OWASP_MAPPING`.
        2. Finding ``category`` in :data:`_FINDING_CATEGORY_FALLBACK`.
        3. Empty list (no mapping found).

        Parameters
        ----------
        scan_result:
            A single :class:`~agentshield.core.scanner.Finding` from a scan.

        Returns
        -------
        list[OWASPCategory]
            Zero or more OWASP categories applicable to this finding.
        """
        # 1. Scanner-level mapping.
        scanner_categories = OWASP_MAPPING.get(scan_result.scanner_name)
        if scanner_categories is not None:
            return list(scanner_categories)

        # 2. Finding-category fallback.
        fallback = _FINDING_CATEGORY_FALLBACK.get(scan_result.category)
        if fallback is not None:
            return list(fallback)

        return []

    def map_findings(self, findings: list[Finding]) -> list[OWASPCategory]:
        """Return the deduplicated set of OWASP categories across all findings.

        Parameters
        ----------
        findings:
            A list of :class:`~agentshield.core.scanner.Finding` objects.

        Returns
        -------
        list[OWASPCategory]
            Unique OWASP categories, in enum declaration order.
        """
        seen: set[OWASPCategory] = set()
        ordered: list[OWASPCategory] = []
        for finding in findings:
            for category in self.map_result(finding):
                if category not in seen:
                    seen.add(category)
                    ordered.append(category)
        return ordered

    def get_coverage(self) -> dict[OWASPCategory, list[str]]:
        """Return which scanner names cover each OWASP category.

        Returns
        -------
        dict[OWASPCategory, list[str]]
            Mapping from each :class:`OWASPCategory` to the list of scanner
            name strings that contribute to its coverage.
        """
        coverage: dict[OWASPCategory, list[str]] = {
            category: [] for category in OWASPCategory
        }
        for scanner_name, categories in OWASP_MAPPING.items():
            for category in categories:
                coverage[category].append(scanner_name)
        return coverage

    def generate_coverage_report(self) -> dict[str, object]:
        """Generate a structured coverage report.

        Returns
        -------
        dict[str, object]
            A serialisable dictionary with the following structure::

                {
                    "total_categories": 10,
                    "covered_categories": 8,
                    "uncovered_categories": ["ASI08:SupplyChainRisks", ...],
                    "coverage_by_category": {
                        "ASI01:PromptInjection": {
                            "covered": true,
                            "scanners": ["regex_injection"]
                        },
                        ...
                    },
                    "scanner_count": 8,
                }
        """
        coverage = self.get_coverage()
        total = len(OWASPCategory)
        covered_categories = [
            cat for cat, scanners in coverage.items() if scanners
        ]
        uncovered_categories = [
            cat.value for cat, scanners in coverage.items() if not scanners
        ]

        coverage_by_category: dict[str, object] = {}
        for category, scanners in coverage.items():
            coverage_by_category[category.value] = {
                "covered": bool(scanners),
                "scanners": list(scanners),
            }

        return {
            "total_categories": total,
            "covered_categories": len(covered_categories),
            "uncovered_categories": uncovered_categories,
            "coverage_by_category": coverage_by_category,
            "scanner_count": len(OWASP_MAPPING),
        }
