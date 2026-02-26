"""Unit tests for agentshield.core.config."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentshield.core.config import OnFindingAction, PipelineConfig, ScannerConfig


# ---------------------------------------------------------------------------
# OnFindingAction
# ---------------------------------------------------------------------------


class TestOnFindingAction:
    def test_block_value(self) -> None:
        assert OnFindingAction.BLOCK.value == "block"

    def test_warn_value(self) -> None:
        assert OnFindingAction.WARN.value == "warn"

    def test_log_value(self) -> None:
        assert OnFindingAction.LOG.value == "log"

    def test_is_string_enum(self) -> None:
        assert isinstance(OnFindingAction.WARN, str)


# ---------------------------------------------------------------------------
# ScannerConfig
# ---------------------------------------------------------------------------


class TestScannerConfig:
    def test_basic_construction(self) -> None:
        cfg = ScannerConfig(name="regex_injection")
        assert cfg.name == "regex_injection"

    def test_enabled_defaults_to_true(self) -> None:
        cfg = ScannerConfig(name="pii_detector")
        assert cfg.enabled is True

    def test_enabled_can_be_disabled(self) -> None:
        cfg = ScannerConfig(name="pii_detector", enabled=False)
        assert cfg.enabled is False

    def test_config_defaults_to_empty_dict(self) -> None:
        cfg = ScannerConfig(name="pii_detector")
        assert cfg.config == {}

    def test_config_accepts_custom_values(self) -> None:
        cfg = ScannerConfig(name="output_safety", config={"max_length": 8192})
        assert cfg.config["max_length"] == 8192

    def test_name_whitespace_stripped(self) -> None:
        cfg = ScannerConfig(name="  regex_injection  ")
        assert cfg.name == "regex_injection"

    def test_empty_name_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            ScannerConfig(name="")

    def test_whitespace_only_name_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            ScannerConfig(name="   ")

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            ScannerConfig(name="pii_detector", unknown_field="value")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# PipelineConfig
# ---------------------------------------------------------------------------


class TestPipelineConfig:
    def test_default_construction(self) -> None:
        cfg = PipelineConfig()
        assert cfg.scanners == []
        assert cfg.severity_threshold == "medium"
        assert cfg.on_finding == OnFindingAction.WARN
        assert cfg.agent_id == "default"

    def test_scanners_list_accepted(self) -> None:
        cfg = PipelineConfig(
            scanners=[ScannerConfig(name="pii_detector"), ScannerConfig(name="regex_injection")]
        )
        assert len(cfg.scanners) == 2

    def test_severity_threshold_valid_values(self) -> None:
        for threshold in ("info", "low", "medium", "high", "critical"):
            cfg = PipelineConfig(severity_threshold=threshold)
            assert cfg.severity_threshold == threshold

    def test_severity_threshold_normalised_to_lowercase(self) -> None:
        cfg = PipelineConfig(severity_threshold="HIGH")
        assert cfg.severity_threshold == "high"

    def test_severity_threshold_invalid_raises(self) -> None:
        with pytest.raises(ValidationError):
            PipelineConfig(severity_threshold="extreme")

    def test_on_finding_block(self) -> None:
        cfg = PipelineConfig(on_finding=OnFindingAction.BLOCK)
        assert cfg.on_finding == OnFindingAction.BLOCK

    def test_on_finding_log(self) -> None:
        cfg = PipelineConfig(on_finding=OnFindingAction.LOG)
        assert cfg.on_finding == OnFindingAction.LOG

    def test_agent_id_custom(self) -> None:
        cfg = PipelineConfig(agent_id="order-agent")
        assert cfg.agent_id == "order-agent"

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            PipelineConfig(unknown_key="value")  # type: ignore[call-arg]

    def test_enabled_scanners_filters_disabled(self) -> None:
        cfg = PipelineConfig(
            scanners=[
                ScannerConfig(name="pii_detector", enabled=True),
                ScannerConfig(name="regex_injection", enabled=False),
                ScannerConfig(name="output_safety", enabled=True),
            ]
        )
        enabled = cfg.enabled_scanners
        assert len(enabled) == 2
        assert all(s.enabled for s in enabled)

    def test_enabled_scanners_returns_all_when_all_enabled(self) -> None:
        cfg = PipelineConfig(
            scanners=[
                ScannerConfig(name="pii_detector"),
                ScannerConfig(name="regex_injection"),
            ]
        )
        assert len(cfg.enabled_scanners) == 2

    def test_enabled_scanners_empty_when_all_disabled(self) -> None:
        cfg = PipelineConfig(
            scanners=[ScannerConfig(name="pii_detector", enabled=False)]
        )
        assert cfg.enabled_scanners == []

    def test_severity_threshold_strips_whitespace(self) -> None:
        cfg = PipelineConfig(severity_threshold="  critical  ")
        assert cfg.severity_threshold == "critical"
