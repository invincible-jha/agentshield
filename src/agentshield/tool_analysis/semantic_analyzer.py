"""Semantic security analysis of MCP tool descriptions.

Analyzes tool name + description text for risk signals across five
privilege categories, producing a risk score 0-10.

Risk categories:
- FILESYSTEM: read/write/delete/access to file system
- NETWORK: HTTP, socket, DNS, external service calls
- EXECUTION: process execution, shell, subprocess, eval
- ADMIN: privilege escalation, sudo, admin access, system config
- DATA_EXFILTRATION: export, upload, transfer, send data externally

Scoring approach
----------------
Each category has a set of keyword signals with individual weights.
Category score = min(sum of matched signal weights, 10).
Overall score = weighted maximum across categories.

This is a commodity keyword/heuristic approach — no ML models.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RiskCategory(str, Enum):
    """Security risk category for tool semantic signals."""

    FILESYSTEM = "filesystem"
    NETWORK = "network"
    EXECUTION = "execution"
    ADMIN = "admin"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass(frozen=True)
class RiskSignal:
    """A single matched risk signal in a tool description.

    Attributes
    ----------
    category:
        The risk category this signal belongs to.
    keyword:
        The keyword or pattern that matched.
    weight:
        The risk weight contributed by this match (0-10).
    context_snippet:
        A short excerpt from the description around the match.
    """

    category: RiskCategory
    keyword: str
    weight: float
    context_snippet: str = ""


@dataclass
class ToolRiskAssessment:
    """Security risk assessment for a single tool.

    Attributes
    ----------
    tool_name:
        The name of the analyzed tool.
    overall_risk_score:
        Overall risk score (0-10). Higher = more risky.
    category_scores:
        Per-category risk scores.
    matched_signals:
        All risk signals detected in the description.
    recommendation:
        Human-readable security recommendation.
    requires_review:
        True if the overall risk score exceeds the review threshold.
    """

    tool_name: str
    overall_risk_score: float
    category_scores: dict[RiskCategory, float] = field(default_factory=dict)
    matched_signals: list[RiskSignal] = field(default_factory=list)
    recommendation: str = ""
    requires_review: bool = False

    @property
    def highest_risk_category(self) -> RiskCategory | None:
        """The category with the highest risk score."""
        if not self.category_scores:
            return None
        return max(self.category_scores, key=lambda c: self.category_scores[c])

    @property
    def risk_level(self) -> str:
        """Human-readable risk level label."""
        score = self.overall_risk_score
        if score >= 8:
            return "CRITICAL"
        if score >= 6:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        if score >= 2:
            return "LOW"
        return "MINIMAL"


# ---------------------------------------------------------------------------
# Signal definitions — keyword patterns and weights per category
# ---------------------------------------------------------------------------

_SIGNAL_MAP: dict[RiskCategory, list[tuple[str, float]]] = {
    RiskCategory.FILESYSTEM: [
        ("read file", 2.0),
        ("write file", 3.0),
        ("delete file", 4.0),
        ("file system", 2.0),
        ("file access", 2.5),
        ("open file", 2.0),
        ("create file", 2.5),
        ("modify file", 3.0),
        ("directory", 1.5),
        ("path traversal", 5.0),
        ("\\\\\\\\", 3.0),            # Windows UNC paths
        ("/etc/", 5.0),
        ("/proc/", 5.0),
        ("sensitive file", 4.0),
        ("read filesystem", 3.0),
    ],
    RiskCategory.NETWORK: [
        ("http request", 2.0),
        ("https request", 2.0),
        ("curl", 2.5),
        ("fetch url", 2.0),
        ("web request", 2.0),
        ("socket", 3.0),
        ("dns lookup", 2.5),
        ("external service", 2.0),
        ("api call", 1.5),
        ("network access", 2.5),
        ("connect to", 2.0),
        ("send request", 2.0),
        ("download", 2.5),
        ("upload", 3.0),
        ("webhook", 2.5),
        ("outbound", 3.0),
    ],
    RiskCategory.EXECUTION: [
        ("execute", 4.0),
        ("run command", 5.0),
        ("shell", 5.0),
        ("subprocess", 5.0),
        ("eval(", 6.0),
        ("exec(", 6.0),
        ("exec_", 4.0),
        ("_exec", 4.0),
        ("os.system", 6.0),
        ("popen", 5.0),
        ("command line", 4.0),
        ("spawn process", 5.0),
        ("terminal", 4.0),
        ("bash", 4.5),
        ("powershell", 4.5),
        ("script execution", 4.0),
        ("arbitrary code", 7.0),
    ],
    RiskCategory.ADMIN: [
        ("admin", 3.0),
        ("administrator", 3.0),
        ("sudo", 5.0),
        ("root access", 6.0),
        ("privilege", 4.0),
        ("escalate", 5.0),
        ("system config", 4.0),
        ("system configuration", 4.0),
        ("registry", 3.5),
        ("permission", 2.5),
        ("access control", 2.5),
        ("superuser", 5.5),
        ("override security", 7.0),
        ("disable security", 8.0),
        ("disables security", 8.0),
        ("bypass authentication", 8.0),
        ("bypasses authentication", 8.0),
        ("bypass auth", 7.0),
        ("bypasses auth", 7.0),
    ],
    RiskCategory.DATA_EXFILTRATION: [
        ("send data", 3.5),
        ("export data", 3.0),
        ("transmit", 3.0),
        ("exfiltrate", 9.0),
        ("leak", 4.0),
        ("copy to external", 4.0),
        ("transfer data", 3.5),
        ("email", 2.5),
        ("smtp", 3.0),
        ("ftp", 3.5),
        ("upload to", 3.5),
        ("post to", 3.0),
        ("report to", 2.0),
        ("notify external", 3.0),
        ("send to remote", 4.0),
    ],
}

# Category weights for overall score computation
_CATEGORY_WEIGHTS: dict[RiskCategory, float] = {
    RiskCategory.EXECUTION: 1.0,
    RiskCategory.ADMIN: 1.0,
    RiskCategory.DATA_EXFILTRATION: 0.95,
    RiskCategory.FILESYSTEM: 0.85,
    RiskCategory.NETWORK: 0.75,
}

_REVIEW_THRESHOLD: float = 6.0


def _extract_context(text: str, keyword: str, window: int = 40) -> str:
    """Extract context around a keyword match.

    Parameters
    ----------
    text:
        The source text.
    keyword:
        The keyword to find.
    window:
        Characters to include on each side of the match.

    Returns
    -------
    str
        Context snippet.
    """
    idx = text.lower().find(keyword.lower())
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end = min(len(text), idx + len(keyword) + window)
    return f"...{text[start:end]}..."


class ToolSemanticAnalyzer:
    """Analyzes MCP tool descriptions for privilege escalation and security risks.

    Usage
    -----
    ::

        analyzer = ToolSemanticAnalyzer()
        assessment = analyzer.analyze("read_file", "Reads any file from the filesystem.")
        print(assessment.risk_level)   # "HIGH"
        print(assessment.overall_risk_score)  # 7.0+
    """

    def __init__(
        self,
        review_threshold: float = _REVIEW_THRESHOLD,
        include_tool_name_in_analysis: bool = True,
    ) -> None:
        """Initialise the analyzer.

        Parameters
        ----------
        review_threshold:
            Risk score (0-10) above which a tool is flagged for review.
        include_tool_name_in_analysis:
            If True, the tool name is included in the analysis text
            (keywords in tool names are also scored).
        """
        self.review_threshold = review_threshold
        self.include_tool_name_in_analysis = include_tool_name_in_analysis

    def analyze(
        self,
        tool_name: str,
        description: str,
        input_schema: dict[str, object] | None = None,
    ) -> ToolRiskAssessment:
        """Analyze a tool's description for security risks.

        Parameters
        ----------
        tool_name:
            The MCP tool name.
        description:
            The tool's description text.
        input_schema:
            Optional JSON Schema of the tool's inputs (used to detect
            path/network argument patterns).

        Returns
        -------
        ToolRiskAssessment
        """
        # Combine tool name and description for analysis
        if self.include_tool_name_in_analysis:
            analysis_text = f"{tool_name} {description}"
        else:
            analysis_text = description

        # Add schema hints if available
        if input_schema:
            schema_str = str(input_schema)
            analysis_text = f"{analysis_text} {schema_str}"

        analysis_lower = analysis_text.lower()

        # Scan each category
        category_scores: dict[RiskCategory, float] = {}
        all_signals: list[RiskSignal] = []

        for category, signals in _SIGNAL_MAP.items():
            category_score = 0.0
            for keyword, weight in signals:
                if keyword.lower() in analysis_lower:
                    context = _extract_context(analysis_text, keyword)
                    signal = RiskSignal(
                        category=category,
                        keyword=keyword,
                        weight=weight,
                        context_snippet=context,
                    )
                    all_signals.append(signal)
                    category_score += weight

            category_scores[category] = min(category_score, 10.0)

        # Compute overall score as weighted maximum
        overall_score = 0.0
        for category, score in category_scores.items():
            weight = _CATEGORY_WEIGHTS.get(category, 1.0)
            weighted = score * weight
            if weighted > overall_score:
                overall_score = weighted

        overall_score = round(min(overall_score, 10.0), 2)
        requires_review = overall_score >= self.review_threshold

        recommendation = self._build_recommendation(
            tool_name, overall_score, category_scores, all_signals
        )

        assessment = ToolRiskAssessment(
            tool_name=tool_name,
            overall_risk_score=overall_score,
            category_scores=category_scores,
            matched_signals=all_signals,
            recommendation=recommendation,
            requires_review=requires_review,
        )

        logger.debug(
            "Tool=%r risk_score=%.1f level=%s requires_review=%s",
            tool_name,
            overall_score,
            assessment.risk_level,
            requires_review,
        )

        return assessment

    def analyze_batch(
        self,
        tools: list[dict[str, object]],
    ) -> list[ToolRiskAssessment]:
        """Analyze a list of tool definitions.

        Parameters
        ----------
        tools:
            List of dicts with keys: "name", "description",
            optionally "input_schema".

        Returns
        -------
        list[ToolRiskAssessment]
        """
        results: list[ToolRiskAssessment] = []
        for tool in tools:
            name = str(tool.get("name", ""))
            desc = str(tool.get("description", ""))
            schema = tool.get("input_schema")
            results.append(self.analyze(name, desc, schema))
        return results

    def _build_recommendation(
        self,
        tool_name: str,
        score: float,
        category_scores: dict[RiskCategory, float],
        signals: list[RiskSignal],
    ) -> str:
        if score < 2.0:
            return f"Tool '{tool_name}' appears low risk. No special handling required."

        top_category = (
            max(category_scores, key=lambda c: category_scores[c])
            if category_scores
            else None
        )

        if score >= 8.0:
            prefix = "CRITICAL RISK:"
        elif score >= 6.0:
            prefix = "HIGH RISK:"
        elif score >= 4.0:
            prefix = "MEDIUM RISK:"
        else:
            prefix = "LOW RISK:"

        top_cat_str = top_category.value if top_category else "unknown"
        unique_keywords = list({s.keyword for s in signals[:5]})

        return (
            f"{prefix} Tool '{tool_name}' (score={score:.1f}) has elevated "
            f"'{top_cat_str}' risk. Matched signals: {unique_keywords}. "
            "Recommend: require explicit permission, audit all invocations, "
            "and restrict allowed arguments."
        )


def analyze_tool_description(
    tool_name: str,
    description: str,
    *,
    review_threshold: float = _REVIEW_THRESHOLD,
) -> ToolRiskAssessment:
    """Convenience function to analyze a single tool description.

    Parameters
    ----------
    tool_name:
        The MCP tool name.
    description:
        The tool's description text.
    review_threshold:
        Score above which the tool is flagged for review.

    Returns
    -------
    ToolRiskAssessment
    """
    analyzer = ToolSemanticAnalyzer(review_threshold=review_threshold)
    return analyzer.analyze(tool_name, description)
