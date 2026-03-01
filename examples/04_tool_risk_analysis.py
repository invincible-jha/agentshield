#!/usr/bin/env python3
"""Example: Tool Risk Analysis

Demonstrates the ToolSemanticAnalyzer to assess risk levels in
MCP and LangChain tool descriptions before allowing execution.

Usage:
    python examples/04_tool_risk_analysis.py

Requirements:
    pip install agentshield
"""
from __future__ import annotations

import agentshield
from agentshield import (
    ToolSemanticAnalyzer,
    RiskCategory,
    ToolRiskAssessment,
    analyze_tool_description,
)


TOOL_DESCRIPTIONS: list[dict[str, object]] = [
    {
        "name": "web_search",
        "description": "Search the web for publicly available information.",
        "parameters": {"query": "string"},
    },
    {
        "name": "execute_shell",
        "description": "Execute arbitrary shell commands on the host system.",
        "parameters": {"command": "string", "args": "list"},
    },
    {
        "name": "read_file",
        "description": "Read the contents of a file from the filesystem.",
        "parameters": {"path": "string"},
    },
    {
        "name": "send_email",
        "description": "Send an email to any recipient without approval.",
        "parameters": {"to": "string", "subject": "string", "body": "string"},
    },
    {
        "name": "database_query",
        "description": "Execute read-only SQL SELECT queries against the analytics database.",
        "parameters": {"sql": "string"},
    },
]


def main() -> None:
    print(f"agentshield version: {agentshield.__version__}")

    # Step 1: Create the tool semantic analyzer
    analyzer = ToolSemanticAnalyzer()
    print("ToolSemanticAnalyzer ready.")

    # Step 2: Analyze each tool's risk profile
    print("\nTool risk assessments:")
    assessments: list[ToolRiskAssessment] = []
    for tool in TOOL_DESCRIPTIONS:
        description = str(tool["description"])
        assessment = analyze_tool_description(
            tool_name=str(tool["name"]),
            description=description,
        )
        assessments.append(assessment)

        risk_label = assessment.risk_level.name if hasattr(assessment.risk_level, 'name') else str(assessment.risk_level)
        categories = [c.value for c in assessment.risk_categories] if assessment.risk_categories else []
        print(f"  [{risk_label}] {tool['name']}: categories={categories}")
        for signal in assessment.signals[:2]:
            print(f"    Signal: {signal.description[:60]}")

    # Step 3: Filter high-risk tools
    high_risk = [a for a in assessments if a.is_high_risk]
    print(f"\nHigh-risk tools ({len(high_risk)}/{len(assessments)}):")
    for assessment in high_risk:
        print(f"  - {assessment.tool_name}: {assessment.risk_summary[:80]}")

    # Step 4: Use analyzer for batch processing
    all_results = analyzer.analyze_batch(TOOL_DESCRIPTIONS)
    allowed = [r for r in all_results if not r.is_high_risk]
    print(f"\nBatch analysis: {len(allowed)} tools approved, {len(all_results) - len(allowed)} flagged")


if __name__ == "__main__":
    main()
