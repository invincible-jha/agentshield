"""Tool-semantic security analysis for agentshield.

Analyzes MCP tool descriptions for privilege escalation patterns,
file system access, network access, and execution risks.
"""
from __future__ import annotations

from agentshield.tool_analysis.semantic_analyzer import (
    RiskCategory,
    RiskSignal,
    ToolRiskAssessment,
    ToolSemanticAnalyzer,
    analyze_tool_description,
)

__all__ = [
    "RiskCategory",
    "RiskSignal",
    "ToolRiskAssessment",
    "ToolSemanticAnalyzer",
    "analyze_tool_description",
]
