"""Custom exceptions for agentshield.

All public exceptions are exported from this module.  Application code
should catch these types rather than inspecting generic ``Exception``
instances so that future refactors can change internal implementation
details without breaking callers.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentshield.core.result import SecurityReport


class AgentShieldError(Exception):
    """Base class for all agentshield exceptions."""


class SecurityBlockError(AgentShieldError):
    """Raised when a critical or high-severity finding blocks execution.

    Attributes
    ----------
    report:
        The :class:`~agentshield.core.result.SecurityReport` that triggered
        the block.  Always present when raised by the pipeline.
    message:
        Human-readable explanation of why execution was blocked.

    Example
    -------
    ::

        try:
            result = await pipeline.scan_input(user_text)
        except SecurityBlockError as exc:
            logger.error("Blocked: %s", exc.message)
            return {"error": "Request blocked by security policy."}
    """

    def __init__(self, message: str, report: SecurityReport | None = None) -> None:
        super().__init__(message)
        self.message: str = message
        self.report: SecurityReport | None = report

    def __repr__(self) -> str:
        return f"SecurityBlockError(message={self.message!r})"


class ConfigError(AgentShieldError):
    """Raised when pipeline configuration is invalid or cannot be loaded.

    Attributes
    ----------
    path:
        Optional filesystem path that was being loaded when the error
        occurred.
    reason:
        A short description of why the config is invalid.

    Example
    -------
    ::

        try:
            pipeline = SecurityPipeline.from_config("shield.yaml")
        except ConfigError as exc:
            print(f"Configuration error in {exc.path}: {exc.reason}")
    """

    def __init__(self, reason: str, path: str | None = None) -> None:
        self.reason: str = reason
        self.path: str | None = path
        location = f" (path={path!r})" if path else ""
        super().__init__(f"Configuration error{location}: {reason}")

    def __repr__(self) -> str:
        return f"ConfigError(reason={self.reason!r}, path={self.path!r})"
