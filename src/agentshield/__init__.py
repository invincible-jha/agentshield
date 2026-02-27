"""agentshield — Multi-layer agent defense framework for AI security.

Public API
----------
The stable public surface is everything exported from this module.
Anything inside submodules not re-exported here is considered private
and may change without notice.

Example
-------
::

    import agentshield

    pipeline = agentshield.SecurityPipeline.default()
    report   = pipeline.scan_input_sync("Hello, I need help.")
    print(report.summary)
    print(agentshield.__version__)
"""
from __future__ import annotations

__version__: str = "0.1.0"

from agentshield.convenience import Shield

# Core
from agentshield.core.config import PipelineConfig, ScannerConfig
from agentshield.core.context import ScanContext
from agentshield.core.exceptions import AgentShieldError, ConfigError, SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner

# Scanners — commodity layer
from agentshield.scanners.behavioral_checker import BehavioralChecker
from agentshield.scanners.credential_detector import CredentialDetectorScanner
from agentshield.scanners.output_safety import OutputSafetyScanner
from agentshield.scanners.output_validator import OutputValidator
from agentshield.scanners.pii_detector import PiiDetectorScanner
from agentshield.scanners.regex_injection import RegexInjectionScanner
from agentshield.scanners.tool_call_checker import ToolCallChecker
from agentshield.scanners.tool_call_validator import ToolCallValidatorScanner

# OWASP mapping
from agentshield.owasp.mapper import OWASPCategory, OWASPMapper

# Reporting
from agentshield.reporting.html_reporter import HTMLReporter
from agentshield.reporting.json_reporter import JSONReporter
from agentshield.reporting.summary import SecuritySummary

# Middleware
from agentshield.middleware.wrapper import AgentWrapper

# Plugins
from agentshield.plugins.registry import ScannerRegistry, scanner_registry

# Multi-layer defense (Phase 5)
from agentshield.multilayer import (
    DefenseChain,
    DefenseDecision,
    DefenseLayer,
    DefenseOutcome,
    FeedbackLoop,
    FeedbackSignal,
    LayerResult,
    SensitivityLevel,
)

# Tool semantic analysis (Phase 6)
from agentshield.tool_analysis import (
    RiskCategory,
    RiskSignal,
    ToolRiskAssessment,
    ToolSemanticAnalyzer,
    analyze_tool_description,
)

# Structured output validators
from agentshield.validators import (
    OutputValidator as StructuredOutputValidator,
    OutputValidatorError,
    ValidationResult as StructuredValidationResult,
)

__all__ = [
    "__version__",
    "Shield",
    # Core types
    "AgentShieldError",
    "ConfigError",
    "Finding",
    "FindingSeverity",
    "PipelineConfig",
    "ScanContext",
    "ScanPhase",
    "ScannerConfig",
    "Scanner",
    "SecurityBlockError",
    "SecurityPipeline",
    "SecurityReport",
    # Scanners
    "BehavioralChecker",
    "CredentialDetectorScanner",
    "OutputSafetyScanner",
    "OutputValidator",
    "PiiDetectorScanner",
    "RegexInjectionScanner",
    "ToolCallChecker",
    "ToolCallValidatorScanner",
    # OWASP
    "OWASPCategory",
    "OWASPMapper",
    # Reporting
    "HTMLReporter",
    "JSONReporter",
    "SecuritySummary",
    # Middleware
    "AgentWrapper",
    # Plugins
    "ScannerRegistry",
    "scanner_registry",
    # Structured output validators
    "StructuredOutputValidator",
    "OutputValidatorError",
    "StructuredValidationResult",
    # Multi-layer defense
    "DefenseChain",
    "DefenseDecision",
    "DefenseLayer",
    "DefenseOutcome",
    "FeedbackLoop",
    "FeedbackSignal",
    "LayerResult",
    "SensitivityLevel",
    # Tool semantic analysis
    "RiskCategory",
    "RiskSignal",
    "ToolRiskAssessment",
    "ToolSemanticAnalyzer",
    "analyze_tool_description",
]
