"""Test that the 3-line quickstart API works for agentshield."""
from __future__ import annotations


def test_quickstart_import() -> None:
    from agentshield import Shield

    shield = Shield()
    assert shield is not None


def test_quickstart_check_safe_text() -> None:
    from agentshield import Shield

    shield = Shield()
    result = shield.check("Hello, how can I help you today?")
    assert result is not None


def test_quickstart_check_returns_report() -> None:
    from agentshield import Shield
    from agentshield.core.result import SecurityReport

    shield = Shield()
    result = shield.check("Normal message without issues.")
    assert isinstance(result, SecurityReport)


def test_quickstart_check_has_summary() -> None:
    from agentshield import Shield

    shield = Shield()
    result = shield.check("This is a normal message.")
    assert hasattr(result, "summary")


def test_quickstart_pipeline_accessible() -> None:
    from agentshield import Shield
    from agentshield.core.pipeline import SecurityPipeline

    shield = Shield()
    assert isinstance(shield.pipeline, SecurityPipeline)


def test_quickstart_repr() -> None:
    from agentshield import Shield

    shield = Shield()
    assert "Shield" in repr(shield)
