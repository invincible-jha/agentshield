"""Core domain logic.

Place foundational models, protocols, and business logic here.
Submodules in core/ should not import from plugins/ or cli/.
"""
from __future__ import annotations

from agentshield.core.config import OnFindingAction, PipelineConfig, ScannerConfig
from agentshield.core.context import ScanContext
from agentshield.core.exceptions import AgentShieldError, ConfigError, SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner

__all__ = [
    "AgentShieldError",
    "ConfigError",
    "Finding",
    "FindingSeverity",
    "OnFindingAction",
    "PipelineConfig",
    "ScanContext",
    "ScanPhase",
    "ScannerConfig",
    "Scanner",
    "SecurityBlockError",
    "SecurityPipeline",
    "SecurityReport",
]
