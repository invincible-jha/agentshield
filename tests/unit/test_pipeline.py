"""Unit tests for agentshield.core.pipeline.SecurityPipeline."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agentshield.core.config import OnFindingAction, PipelineConfig, ScannerConfig
from agentshield.core.context import ScanContext
from agentshield.core.exceptions import ConfigError, SecurityBlockError
from agentshield.core.pipeline import SecurityPipeline, _load_scanner_class
from agentshield.core.result import SecurityReport
from agentshield.core.scanner import Finding, FindingSeverity, ScanPhase, Scanner


# ---------------------------------------------------------------------------
# Minimal scanner stubs
# ---------------------------------------------------------------------------


class _CleanScanner(Scanner):
    """Always returns no findings."""

    name: str = "clean_scanner"
    phases: list[ScanPhase] = [ScanPhase.INPUT, ScanPhase.OUTPUT, ScanPhase.TOOL_CALL]

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        return []


class _FlaggingScanner(Scanner):
    """Always returns one CRITICAL finding."""

    name: str = "flagging_scanner"
    phases: list[ScanPhase] = [ScanPhase.INPUT, ScanPhase.OUTPUT, ScanPhase.TOOL_CALL]

    def __init__(self, severity: FindingSeverity = FindingSeverity.CRITICAL) -> None:
        self._severity = severity

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        return [
            Finding(
                scanner_name=self.name,
                severity=self._severity,
                category="test_category",
                message="Test finding",
            )
        ]


class _InputOnlyScanner(Scanner):
    """Only runs during INPUT phase."""

    name: str = "input_only"
    phases: list[ScanPhase] = [ScanPhase.INPUT]

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        return [
            Finding(
                scanner_name=self.name,
                severity=FindingSeverity.LOW,
                category="test",
                message="input only hit",
            )
        ]


class _ErrorScanner(Scanner):
    """Raises an exception during scan."""

    name: str = "error_scanner"
    phases: list[ScanPhase] = [ScanPhase.INPUT]

    async def scan(self, content: str, context: ScanContext) -> list[Finding]:
        raise RuntimeError("Scanner failed!")


# ---------------------------------------------------------------------------
# _load_scanner_class helper
# ---------------------------------------------------------------------------


class TestLoadScannerClass:
    def test_loads_builtin_scanner(self) -> None:
        cls = _load_scanner_class(
            "agentshield.scanners.regex_injection:RegexInjectionScanner"
        )
        from agentshield.scanners.regex_injection import RegexInjectionScanner

        assert cls is RegexInjectionScanner

    def test_missing_colon_raises_config_error(self) -> None:
        with pytest.raises(ConfigError, match="module:ClassName"):
            _load_scanner_class("agentshield.scanners.regex_injection")

    def test_nonexistent_module_raises_config_error(self) -> None:
        with pytest.raises(ConfigError):
            _load_scanner_class("agentshield.nonexistent_module:SomeClass")

    def test_nonexistent_class_raises_config_error(self) -> None:
        with pytest.raises(ConfigError):
            _load_scanner_class("agentshield.scanners.regex_injection:NonExistentClass")

    def test_non_scanner_class_raises_config_error(self) -> None:
        with pytest.raises(ConfigError, match="Scanner subclass"):
            _load_scanner_class("agentshield.core.config:PipelineConfig")


# ---------------------------------------------------------------------------
# SecurityPipeline construction
# ---------------------------------------------------------------------------


class TestSecurityPipelineConstruction:
    def test_instantiate_with_empty_scanners(self) -> None:
        pipeline = SecurityPipeline(scanners=[])
        assert pipeline.scanners == []

    def test_instantiate_with_scanners(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner(), _FlaggingScanner()])
        assert len(pipeline.scanners) == 2

    def test_default_config_applied_when_none(self) -> None:
        pipeline = SecurityPipeline(scanners=[])
        assert pipeline.config.severity_threshold == "medium"

    def test_custom_config_applied(self) -> None:
        config = PipelineConfig(severity_threshold="critical")
        pipeline = SecurityPipeline(scanners=[], config=config)
        assert pipeline.config.severity_threshold == "critical"

    def test_default_factory_creates_all_builtin_scanners(self) -> None:
        pipeline = SecurityPipeline.default()
        scanner_names = [s.name for s in pipeline.scanners]
        assert "regex_injection" in scanner_names
        assert "pii_detector" in scanner_names

    def test_repr_contains_scanner_names(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        assert "clean_scanner" in repr(pipeline)

    def test_from_pipeline_config_creates_pipeline(self) -> None:
        config = PipelineConfig(
            scanners=[ScannerConfig(name="regex_injection")],
            severity_threshold="high",
        )
        pipeline = SecurityPipeline.from_pipeline_config(config)
        assert len(pipeline.scanners) == 1
        assert pipeline.scanners[0].name == "regex_injection"

    def test_disabled_scanner_not_loaded(self) -> None:
        config = PipelineConfig(
            scanners=[
                ScannerConfig(name="regex_injection", enabled=True),
                ScannerConfig(name="pii_detector", enabled=False),
            ]
        )
        pipeline = SecurityPipeline.from_pipeline_config(config)
        scanner_names = [s.name for s in pipeline.scanners]
        assert "regex_injection" in scanner_names
        assert "pii_detector" not in scanner_names


# ---------------------------------------------------------------------------
# from_config (YAML loading)
# ---------------------------------------------------------------------------


class TestFromConfig:
    def test_missing_file_raises_config_error(self) -> None:
        with pytest.raises(ConfigError, match="not found"):
            SecurityPipeline.from_config("/nonexistent/path/shield.yaml")

    def test_valid_yaml_creates_pipeline(self, tmp_path: Path) -> None:
        yaml_content = """
scanners:
  - name: regex_injection
severity_threshold: medium
on_finding: warn
"""
        config_file = tmp_path / "shield.yaml"
        config_file.write_text(yaml_content)
        pipeline = SecurityPipeline.from_config(config_file)
        assert len(pipeline.scanners) == 1

    def test_invalid_yaml_raises_config_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "shield.yaml"
        config_file.write_text(":\tinvalid:\n  yaml:\n  {")
        with pytest.raises(ConfigError):
            SecurityPipeline.from_config(config_file)

    def test_non_mapping_yaml_raises_config_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "shield.yaml"
        config_file.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigError, match="mapping"):
            SecurityPipeline.from_config(config_file)

    def test_invalid_severity_threshold_in_yaml(self, tmp_path: Path) -> None:
        yaml_content = """
scanners: []
severity_threshold: extreme
"""
        config_file = tmp_path / "shield.yaml"
        config_file.write_text(yaml_content)
        with pytest.raises(ConfigError):
            SecurityPipeline.from_config(config_file)


# ---------------------------------------------------------------------------
# scan_input
# ---------------------------------------------------------------------------


class TestScanInput:
    async def test_clean_input_returns_clean_report(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = await pipeline.scan_input("hello world")
        assert report.is_clean

    async def test_phase_in_report_is_input(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = await pipeline.scan_input("hello")
        assert report.phase == "input"

    async def test_findings_propagated_to_report(self) -> None:
        pipeline = SecurityPipeline(scanners=[_FlaggingScanner()])
        report = await pipeline.scan_input("any content")
        assert len(report.findings) == 1
        assert report.findings[0].scanner_name == "flagging_scanner"

    async def test_session_id_forwarded(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = await pipeline.scan_input("text", session_id="custom-session")
        assert report.session_id == "custom-session"

    async def test_metadata_forwarded(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = await pipeline.scan_input("text", metadata={"env": "test"})
        assert report.is_clean

    async def test_scanner_exception_is_swallowed(self) -> None:
        pipeline = SecurityPipeline(scanners=[_ErrorScanner()])
        report = await pipeline.scan_input("any text")
        assert report.is_clean

    async def test_block_action_raises_on_critical(self) -> None:
        config = PipelineConfig(
            on_finding=OnFindingAction.BLOCK, severity_threshold="critical"
        )
        pipeline = SecurityPipeline(
            scanners=[_FlaggingScanner(FindingSeverity.CRITICAL)], config=config
        )
        with pytest.raises(SecurityBlockError):
            await pipeline.scan_input("trigger content")

    async def test_warn_action_does_not_raise(self) -> None:
        config = PipelineConfig(
            on_finding=OnFindingAction.WARN, severity_threshold="medium"
        )
        pipeline = SecurityPipeline(
            scanners=[_FlaggingScanner(FindingSeverity.HIGH)], config=config
        )
        report = await pipeline.scan_input("trigger")
        assert not report.is_clean

    async def test_log_action_does_not_raise(self) -> None:
        config = PipelineConfig(
            on_finding=OnFindingAction.LOG, severity_threshold="info"
        )
        pipeline = SecurityPipeline(
            scanners=[_FlaggingScanner(FindingSeverity.INFO)], config=config
        )
        report = await pipeline.scan_input("trigger")
        assert not report.is_clean

    async def test_below_threshold_does_not_trigger_block(self) -> None:
        config = PipelineConfig(
            on_finding=OnFindingAction.BLOCK, severity_threshold="critical"
        )
        pipeline = SecurityPipeline(
            scanners=[_FlaggingScanner(FindingSeverity.LOW)], config=config
        )
        # Should NOT raise because LOW < CRITICAL threshold.
        report = await pipeline.scan_input("trigger")
        assert not report.is_clean

    async def test_scanner_skipped_for_wrong_phase(self) -> None:
        pipeline = SecurityPipeline(scanners=[_InputOnlyScanner()])
        # Calling scan_output should not invoke the INPUT-only scanner.
        report = await pipeline.scan_output("output text")
        assert report.is_clean


# ---------------------------------------------------------------------------
# scan_output
# ---------------------------------------------------------------------------


class TestScanOutput:
    async def test_phase_is_output(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = await pipeline.scan_output("clean output")
        assert report.phase == "output"

    async def test_clean_output_returns_clean_report(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = await pipeline.scan_output("safe content")
        assert report.is_clean


# ---------------------------------------------------------------------------
# scan_tool_call
# ---------------------------------------------------------------------------


class TestScanToolCall:
    async def test_phase_is_tool_call(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = await pipeline.scan_tool_call("my_tool", {"arg": "value"})
        assert report.phase == "tool_call"

    async def test_args_serialised_to_json(self) -> None:
        captured_content: list[str] = []

        class _CapturingScanner(Scanner):
            name: str = "capturing"
            phases: list[ScanPhase] = [ScanPhase.TOOL_CALL]

            async def scan(self, content: str, ctx: ScanContext) -> list[Finding]:
                captured_content.append(content)
                return []

        pipeline = SecurityPipeline(scanners=[_CapturingScanner()])
        await pipeline.scan_tool_call("some_tool", {"key": "value", "count": 42})
        assert len(captured_content) == 1
        parsed = json.loads(captured_content[0])
        assert parsed["key"] == "value"
        assert parsed["count"] == 42

    async def test_clean_tool_call_returns_clean_report(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = await pipeline.scan_tool_call("safe_tool", {"param": "safe"})
        assert report.is_clean


# ---------------------------------------------------------------------------
# Sync wrappers
# ---------------------------------------------------------------------------


class TestSyncWrappers:
    def test_scan_input_sync(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = pipeline.scan_input_sync("hello")
        assert report.is_clean

    def test_scan_output_sync(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = pipeline.scan_output_sync("output")
        assert report.is_clean

    def test_scan_tool_call_sync(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report = pipeline.scan_tool_call_sync("tool", {"arg": "value"})
        assert report.is_clean


# ---------------------------------------------------------------------------
# Cumulative findings and generate_report
# ---------------------------------------------------------------------------


class TestCumulativeFindings:
    async def test_cumulative_findings_accumulate_across_scans(self) -> None:
        pipeline = SecurityPipeline(
            scanners=[_FlaggingScanner()],
            config=PipelineConfig(on_finding=OnFindingAction.LOG, severity_threshold="info"),
        )
        await pipeline.scan_input("text 1")
        await pipeline.scan_input("text 2")
        assert len(pipeline._cumulative_findings) == 2

    async def test_clear_cumulative_findings(self) -> None:
        pipeline = SecurityPipeline(
            scanners=[_FlaggingScanner()],
            config=PipelineConfig(on_finding=OnFindingAction.LOG, severity_threshold="info"),
        )
        await pipeline.scan_input("trigger")
        pipeline.clear_cumulative_findings()
        assert len(pipeline._cumulative_findings) == 0

    def test_generate_report_json_format(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report_str = pipeline.generate_report(format="json")
        parsed = json.loads(report_str)
        assert "findings" in parsed

    def test_generate_report_markdown_format(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report_str = pipeline.generate_report(format="markdown")
        assert "agentshield Security Report" in report_str

    def test_generate_report_html_format(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        report_str = pipeline.generate_report(format="html")
        assert "<!DOCTYPE html>" in report_str

    def test_generate_report_invalid_format_raises(self) -> None:
        pipeline = SecurityPipeline(scanners=[_CleanScanner()])
        with pytest.raises(ValueError, match="Unsupported"):
            pipeline.generate_report(format="csv")
