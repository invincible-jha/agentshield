"""Built-in commodity scanner implementations.

All scanners are re-exported here for convenience.  They are also
registered into :data:`~agentshield.plugins.registry.scanner_registry`
by calling :func:`~agentshield.plugins.registry.register_builtin_scanners`.

The five canonical commodity scanners are:

* :class:`RegexInjectionScanner` — INPUT phase prompt-injection detection
* :class:`PiiDetectorScanner` — OUTPUT phase PII detection
* :class:`CredentialDetectorScanner` — OUTPUT phase credential detection
* :class:`OutputSafetyScanner` — OUTPUT phase structural safety checks
* :class:`ToolCallValidatorScanner` — TOOL_CALL phase argument validation

Additional scanners bundled with the framework:

* :class:`BehavioralChecker` — INPUT/OUTPUT behavioral drift detection
* :class:`OutputValidator` — OUTPUT forbidden-pattern validation
* :class:`ToolCallChecker` — TOOL_CALL allowlist and rate limiting
"""
from __future__ import annotations

from agentshield.scanners.behavioral_checker import BehavioralChecker
from agentshield.scanners.credential_detector import CredentialDetectorScanner
from agentshield.scanners.output_safety import OutputSafetyScanner
from agentshield.scanners.output_validator import OutputValidator
from agentshield.scanners.pii_detector import PiiDetectorScanner
from agentshield.scanners.regex_injection import RegexInjectionScanner
from agentshield.scanners.tool_call_checker import ToolCallChecker
from agentshield.scanners.tool_call_validator import ToolCallValidatorScanner

__all__ = [
    "BehavioralChecker",
    "CredentialDetectorScanner",
    "OutputSafetyScanner",
    "OutputValidator",
    "PiiDetectorScanner",
    "RegexInjectionScanner",
    "ToolCallChecker",
    "ToolCallValidatorScanner",
]
