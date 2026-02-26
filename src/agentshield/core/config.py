"""Pydantic v2 configuration models for the security pipeline.

Configuration may be supplied as:

* A ``shield.yaml`` file loaded via :meth:`~agentshield.core.pipeline.SecurityPipeline.from_config`.
* Programmatic construction using the Pydantic model classes here.

The configuration schema is intentionally flat and human-friendly so that
YAML files remain readable without deep nesting.
"""
from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


class OnFindingAction(str, Enum):
    """What the pipeline should do when a finding meets the severity threshold.

    Attributes
    ----------
    BLOCK:
        Raise :class:`~agentshield.core.exceptions.SecurityBlockError` and
        halt agent execution.
    WARN:
        Log a structured warning and return the report; execution continues.
    LOG:
        Silently record the finding; execution continues.
    """

    BLOCK = "block"
    WARN = "warn"
    LOG = "log"


class ScannerConfig(BaseModel):
    """Per-scanner configuration entry.

    Attributes
    ----------
    name:
        The scanner's registered slug (e.g. ``"regex_injection"``).
    enabled:
        Whether this scanner is active.  Defaults to ``True``.
    config:
        Arbitrary scanner-specific settings passed to the scanner at
        construction time.
    """

    model_config = {"extra": "forbid"}

    name: str
    enabled: bool = True
    config: dict[str, object] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def name_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Scanner name must not be empty or whitespace.")
        return value.strip()


class PipelineConfig(BaseModel):
    """Top-level pipeline configuration.

    Attributes
    ----------
    scanners:
        Ordered list of :class:`ScannerConfig` entries.  Scanners run in
        declaration order within each phase.
    severity_threshold:
        Minimum :class:`~agentshield.core.scanner.FindingSeverity` value
        that triggers :attr:`on_finding`.  Findings below this level are
        still recorded but do not trigger an action.
    on_finding:
        Action to take when a finding meets or exceeds
        :attr:`severity_threshold`.  Defaults to ``"warn"``.
    agent_id:
        Optional default agent identifier embedded in every
        :class:`~agentshield.core.context.ScanContext`.

    Example
    -------
    ::

        config = PipelineConfig(
            scanners=[
                ScannerConfig(name="regex_injection"),
                ScannerConfig(name="pii_detector"),
            ],
            severity_threshold="high",
            on_finding="block",
        )
    """

    model_config = {"extra": "forbid"}

    scanners: list[ScannerConfig] = Field(default_factory=list)
    severity_threshold: Annotated[
        str,
        Field(
            default="medium",
            description=(
                "Minimum severity that triggers the on_finding action. "
                "Allowed: info, low, medium, high, critical."
            ),
        ),
    ] = "medium"
    on_finding: OnFindingAction = OnFindingAction.WARN
    agent_id: str = "default"

    @field_validator("severity_threshold")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        allowed = {"info", "low", "medium", "high", "critical"}
        normalised = value.lower().strip()
        if normalised not in allowed:
            raise ValueError(
                f"severity_threshold must be one of {sorted(allowed)}, got {value!r}."
            )
        return normalised

    @property
    def enabled_scanners(self) -> list[ScannerConfig]:
        """Return only scanners where :attr:`ScannerConfig.enabled` is ``True``."""
        return [s for s in self.scanners if s.enabled]
