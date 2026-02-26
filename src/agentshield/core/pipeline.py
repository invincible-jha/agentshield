"""SecurityPipeline — the central orchestrator.

The pipeline wires together an ordered chain of :class:`~agentshield.core.scanner.Scanner`
instances and exposes three async scanning entry-points plus a report
generator.  Sync wrappers are provided for callers that cannot use
``await``.

Usage
-----
::

    import asyncio
    from agentshield import SecurityPipeline

    pipeline = SecurityPipeline.from_config("shield.yaml")

    # Async usage
    report = asyncio.run(pipeline.scan_input("Hello, assistant!"))
    print(report.summary)

    # Sync usage (thin wrapper around asyncio.run)
    report = pipeline.scan_input_sync("Hello, assistant!")
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from agentshield.core.config import OnFindingAction, PipelineConfig, ScannerConfig
from agentshield.core.context import ScanContext
from agentshield.core.exceptions import ConfigError, SecurityBlockError
from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Default scanner slugs mapped to their import paths so that the pipeline
# can auto-instantiate them from a config file without requiring callers to
# import every scanner class explicitly.
_BUILTIN_SCANNER_MAP: dict[str, str] = {
    "regex_injection": "agentshield.scanners.regex_injection:RegexInjectionScanner",
    "pii_detector": "agentshield.scanners.pii_detector:PiiDetectorScanner",
    "credential_detector": "agentshield.scanners.credential_detector:CredentialDetectorScanner",
    "output_safety": "agentshield.scanners.output_safety:OutputSafetyScanner",
    "tool_call_validator": "agentshield.scanners.tool_call_validator:ToolCallValidatorScanner",
    "behavioral_checker": "agentshield.scanners.behavioral_checker:BehavioralChecker",
    "output_validator": "agentshield.scanners.output_validator:OutputValidator",
    "tool_call_checker": "agentshield.scanners.tool_call_checker:ToolCallChecker",
}


def _load_scanner_class(dotted_path: str) -> type[Scanner]:
    """Import and return a scanner class from a ``module:ClassName`` path.

    Parameters
    ----------
    dotted_path:
        A string of the form ``"package.module:ClassName"``.

    Returns
    -------
    type[Scanner]
        The resolved class.

    Raises
    ------
    ConfigError
        If the module cannot be imported or the attribute does not exist.
    """
    if ":" not in dotted_path:
        raise ConfigError(
            f"Scanner path {dotted_path!r} must use 'module:ClassName' format."
        )
    module_path, class_name = dotted_path.rsplit(":", 1)
    try:
        import importlib

        module = importlib.import_module(module_path)
    except ImportError as exc:
        raise ConfigError(
            f"Cannot import scanner module {module_path!r}: {exc}"
        ) from exc
    try:
        cls = getattr(module, class_name)
    except AttributeError as exc:
        raise ConfigError(
            f"Module {module_path!r} has no attribute {class_name!r}."
        ) from exc
    if not (isinstance(cls, type) and issubclass(cls, Scanner)):
        raise ConfigError(
            f"{dotted_path!r} does not resolve to a Scanner subclass."
        )
    return cls


def _instantiate_scanner(scanner_cfg: ScannerConfig) -> Scanner:
    """Create a scanner instance from its config entry.

    Parameters
    ----------
    scanner_cfg:
        The per-scanner config.  :attr:`~ScannerConfig.name` is looked up
        in :data:`_BUILTIN_SCANNER_MAP` first; if absent it is treated as a
        full ``module:ClassName`` path.

    Returns
    -------
    Scanner
        A ready-to-use scanner instance.
    """
    dotted = _BUILTIN_SCANNER_MAP.get(scanner_cfg.name, scanner_cfg.name)
    cls = _load_scanner_class(dotted)
    if scanner_cfg.config:
        instance: Scanner = cls(**scanner_cfg.config)  # type: ignore[call-arg]
    else:
        instance = cls()
    return instance


class SecurityPipeline:
    """Ordered chain of scanners that protects an agent at every phase.

    Attributes
    ----------
    config:
        The validated :class:`~agentshield.core.config.PipelineConfig`
        backing this pipeline.
    scanners:
        The ordered list of active :class:`~agentshield.core.scanner.Scanner`
        instances.

    Example
    -------
    ::

        pipeline = SecurityPipeline.from_config("shield.yaml")
        report   = await pipeline.scan_input(user_message)
        if report.has_critical:
            raise SecurityBlockError("Blocked", report=report)
    """

    def __init__(
        self,
        scanners: list[Scanner],
        config: PipelineConfig | None = None,
    ) -> None:
        self.scanners: list[Scanner] = scanners
        self.config: PipelineConfig = config or PipelineConfig()
        self._cumulative_findings: list[Finding] = []

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, path: str | Path) -> SecurityPipeline:
        """Load a pipeline from a YAML configuration file.

        Parameters
        ----------
        path:
            Filesystem path to ``shield.yaml`` (or any ``.yaml`` / ``.yml``
            file following the :class:`~agentshield.core.config.PipelineConfig`
            schema).

        Returns
        -------
        SecurityPipeline
            A fully initialised pipeline with all enabled scanners loaded.

        Raises
        ------
        ConfigError
            If the file does not exist, cannot be parsed as YAML, or fails
            Pydantic validation.
        """
        file_path = Path(path)
        if not file_path.exists():
            raise ConfigError(f"Config file not found.", path=str(file_path))
        try:
            raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigError(f"YAML parse error: {exc}", path=str(file_path)) from exc
        if not isinstance(raw, dict):
            raise ConfigError(
                "Top-level YAML value must be a mapping.", path=str(file_path)
            )
        try:
            pipeline_config = PipelineConfig.model_validate(raw)
        except Exception as exc:
            raise ConfigError(str(exc), path=str(file_path)) from exc
        return cls.from_pipeline_config(pipeline_config)

    @classmethod
    def from_pipeline_config(cls, config: PipelineConfig) -> SecurityPipeline:
        """Construct a pipeline from an already-validated :class:`PipelineConfig`.

        Parameters
        ----------
        config:
            Validated configuration.

        Returns
        -------
        SecurityPipeline
        """
        scanners: list[Scanner] = []
        for scanner_cfg in config.enabled_scanners:
            try:
                scanners.append(_instantiate_scanner(scanner_cfg))
            except ConfigError:
                raise
            except Exception as exc:
                raise ConfigError(
                    f"Failed to instantiate scanner {scanner_cfg.name!r}: {exc}"
                ) from exc
        return cls(scanners=scanners, config=config)

    @classmethod
    def default(cls) -> SecurityPipeline:
        """Return a pipeline with all built-in scanners enabled at MEDIUM threshold.

        Returns
        -------
        SecurityPipeline
        """
        config = PipelineConfig(
            scanners=[ScannerConfig(name=name) for name in _BUILTIN_SCANNER_MAP],
            severity_threshold="medium",
            on_finding=OnFindingAction.WARN,
        )
        return cls.from_pipeline_config(config)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_context(
        self,
        phase: ScanPhase,
        tool_name: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> ScanContext:
        return ScanContext(
            phase=phase,
            agent_id=self.config.agent_id,
            session_id=session_id or str(uuid.uuid4()),
            tool_name=tool_name,
            metadata=metadata or {},
        )

    def _threshold_severity(self) -> FindingSeverity:
        return FindingSeverity(self.config.severity_threshold)

    async def _run_scanners(
        self, content: str, context: ScanContext
    ) -> list[Finding]:
        """Run all scanners whose phases include the context's current phase."""
        all_findings: list[Finding] = []
        for scanner in self.scanners:
            if context.phase not in scanner.phases:
                continue
            try:
                findings = await scanner.scan(content, context)
            except Exception:
                logger.exception(
                    "Scanner %r raised an exception; skipping.", scanner.name
                )
                continue
            all_findings.extend(findings)
            context.add_findings(findings)
        return all_findings

    def _apply_threshold(
        self, findings: list[Finding], report: SecurityReport
    ) -> None:
        """Raise SecurityBlockError or log according to the configured action."""
        threshold = self._threshold_severity()
        triggered = [f for f in findings if f.severity >= threshold]
        if not triggered:
            return
        action = self.config.on_finding
        if action == OnFindingAction.BLOCK:
            raise SecurityBlockError(
                f"Pipeline blocked execution: {report.summary}", report=report
            )
        if action == OnFindingAction.WARN:
            logger.warning(
                "agentshield [%s] %s | session=%s",
                report.phase,
                report.summary,
                report.session_id,
            )
        else:
            logger.debug(
                "agentshield [%s] %s | session=%s",
                report.phase,
                report.summary,
                report.session_id,
            )

    def _build_report(
        self,
        findings: list[Finding],
        context: ScanContext,
        duration_ms: float,
    ) -> SecurityReport:
        report = SecurityReport(
            findings=findings,
            scan_duration_ms=duration_ms,
            agent_id=context.agent_id,
            session_id=context.session_id,
            phase=context.phase.value,
        )
        self._cumulative_findings.extend(findings)
        return report

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def scan_input(
        self,
        text: str,
        *,
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Scan agent input text for security issues.

        Parameters
        ----------
        text:
            The raw input text arriving from the user or environment.
        session_id:
            Optional stable identifier for the current session.
        metadata:
            Arbitrary key-value pairs forwarded to scanners.

        Returns
        -------
        SecurityReport
            Summary of findings produced during this scan.

        Raises
        ------
        SecurityBlockError
            When :attr:`~PipelineConfig.on_finding` is ``"block"`` and a
            finding meets the severity threshold.
        """
        context = self._make_context(
            ScanPhase.INPUT, session_id=session_id, metadata=metadata
        )
        start = time.monotonic()
        findings = await self._run_scanners(text, context)
        duration = (time.monotonic() - start) * 1000
        report = self._build_report(findings, context, duration)
        self._apply_threshold(findings, report)
        return report

    async def scan_output(
        self,
        text: str,
        *,
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Scan agent output text for PII and credential leaks.

        Parameters
        ----------
        text:
            The text the agent is about to emit.
        session_id:
            Optional stable identifier for the current session.
        metadata:
            Arbitrary key-value pairs forwarded to scanners.

        Returns
        -------
        SecurityReport

        Raises
        ------
        SecurityBlockError
            When configured to block on findings above the threshold.
        """
        context = self._make_context(
            ScanPhase.OUTPUT, session_id=session_id, metadata=metadata
        )
        start = time.monotonic()
        findings = await self._run_scanners(text, context)
        duration = (time.monotonic() - start) * 1000
        report = self._build_report(findings, context, duration)
        self._apply_threshold(findings, report)
        return report

    async def scan_tool_call(
        self,
        tool_name: str,
        args: dict[str, object],
        *,
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Scan a tool invocation before it is dispatched.

        The *args* dictionary is serialised to a JSON string and passed to
        scanners as ``content`` so that all scanner implementations can
        operate on a plain string.

        Parameters
        ----------
        tool_name:
            The name of the tool being called.
        args:
            The tool's argument dictionary.
        session_id:
            Optional stable identifier for the current session.
        metadata:
            Arbitrary key-value pairs forwarded to scanners.

        Returns
        -------
        SecurityReport

        Raises
        ------
        SecurityBlockError
            When configured to block on findings above the threshold.
        """
        context = self._make_context(
            ScanPhase.TOOL_CALL,
            tool_name=tool_name,
            session_id=session_id,
            metadata=metadata,
        )
        content = json.dumps(args, ensure_ascii=False)
        start = time.monotonic()
        findings = await self._run_scanners(content, context)
        duration = (time.monotonic() - start) * 1000
        report = self._build_report(findings, context, duration)
        self._apply_threshold(findings, report)
        return report

    # ------------------------------------------------------------------
    # Sync wrappers
    # ------------------------------------------------------------------

    def scan_input_sync(
        self,
        text: str,
        *,
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Synchronous wrapper around :meth:`scan_input`."""
        return asyncio.run(
            self.scan_input(text, session_id=session_id, metadata=metadata)
        )

    def scan_output_sync(
        self,
        text: str,
        *,
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Synchronous wrapper around :meth:`scan_output`."""
        return asyncio.run(
            self.scan_output(text, session_id=session_id, metadata=metadata)
        )

    def scan_tool_call_sync(
        self,
        tool_name: str,
        args: dict[str, object],
        *,
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SecurityReport:
        """Synchronous wrapper around :meth:`scan_tool_call`."""
        return asyncio.run(
            self.scan_tool_call(
                tool_name, args, session_id=session_id, metadata=metadata
            )
        )

    # ------------------------------------------------------------------
    # Cumulative reporting
    # ------------------------------------------------------------------

    def generate_report(self, format: str = "json") -> str:
        """Generate a cumulative report over all scans run so far.

        Parameters
        ----------
        format:
            Output format — ``"json"``, ``"markdown"``, or ``"html"``.

        Returns
        -------
        str
            The formatted report.

        Raises
        ------
        ValueError
            If *format* is not one of the supported values.
        """
        from agentshield.reporting.report import SecurityReportGenerator

        generator = SecurityReportGenerator()
        if format == "json":
            return generator.generate_json(self._cumulative_findings)
        if format == "markdown":
            return generator.generate_markdown(self._cumulative_findings)
        if format == "html":
            return generator.generate_html(self._cumulative_findings)
        raise ValueError(
            f"Unsupported report format {format!r}. "
            "Choose one of: 'json', 'markdown', 'html'."
        )

    def clear_cumulative_findings(self) -> None:
        """Reset the accumulated findings list.

        Useful when reusing a pipeline instance across logically separate
        conversations or test runs.
        """
        self._cumulative_findings.clear()

    def __repr__(self) -> str:
        return (
            f"SecurityPipeline("
            f"scanners={[s.name for s in self.scanners]!r}, "
            f"threshold={self.config.severity_threshold!r}, "
            f"on_finding={self.config.on_finding.value!r})"
        )
