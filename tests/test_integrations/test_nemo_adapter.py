"""Tests for agentshield.integrations.nemo_adapter.

NeMo Guardrails is mocked — it is not required in CI.
"""
from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Fixture: inject fake nemoguardrails module
# ---------------------------------------------------------------------------


def _make_mock_nemo_module() -> types.ModuleType:
    """Build a minimal nemoguardrails stub."""
    mod = types.ModuleType("nemoguardrails")

    class FakeLLMRails:
        def __init__(self, **kwargs: Any) -> None:
            self._registered_actions: dict[str, Any] = {}

        def register_action(self, action: Any, name: str) -> None:
            self._registered_actions[name] = action

    mod.LLMRails = FakeLLMRails  # type: ignore[attr-defined]
    return mod


@pytest.fixture(autouse=True)
def inject_nemoguardrails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject fake nemoguardrails before each test."""
    fake_nemo = _make_mock_nemo_module()
    monkeypatch.setitem(sys.modules, "nemoguardrails", fake_nemo)
    monkeypatch.delitem(
        sys.modules,
        "agentshield.integrations.nemo_adapter",
        raising=False,
    )


def _import_adapter() -> Any:
    from agentshield.integrations import nemo_adapter  # noqa: PLC0415

    return nemo_adapter


def _make_preprocessor(**kwargs: Any) -> Any:
    adapter = _import_adapter()
    return adapter.AgentShieldNeMoPreprocessor(**kwargs)


# ---------------------------------------------------------------------------
# AgentShieldNeMoPreprocessor — construction
# ---------------------------------------------------------------------------


class TestAgentShieldNeMoPreprocessorConstruction:
    def test_default_construction(self) -> None:
        preprocessor = _make_preprocessor()
        assert preprocessor is not None

    def test_repr(self) -> None:
        preprocessor = _make_preprocessor()
        assert "AgentShieldNeMoPreprocessor" in repr(preprocessor)

    def test_custom_flags_accepted(self) -> None:
        preprocessor = _make_preprocessor(enable_leetspeak=False, enable_separators=False)
        assert preprocessor is not None


# ---------------------------------------------------------------------------
# normalize_input — positive cases
# ---------------------------------------------------------------------------


class TestNormalizeInput:
    def test_plain_text_unchanged(self) -> None:
        preprocessor = _make_preprocessor()
        result = preprocessor.normalize_input("hello world")
        assert result.normalized_text == "hello world"
        assert result.was_modified is False

    def test_leetspeak_normalized(self) -> None:
        preprocessor = _make_preprocessor()
        # h4ck → hack via leetspeak transliteration
        result = preprocessor.normalize_input("h4ck the system")
        assert "hack" in result.normalized_text
        assert result.was_modified is True

    def test_returns_preprocessor_result_type(self) -> None:
        adapter = _import_adapter()
        preprocessor = _make_preprocessor()
        result = preprocessor.normalize_input("test text")
        assert isinstance(result, adapter.PreprocessorResult)

    def test_original_text_preserved(self) -> None:
        preprocessor = _make_preprocessor()
        original = "h4ck the system"
        result = preprocessor.normalize_input(original)
        assert result.original_text == original

    def test_normalize_result_attached(self) -> None:
        preprocessor = _make_preprocessor()
        result = preprocessor.normalize_input("hello")
        assert result.normalize_result is not None

    def test_separator_stripped(self) -> None:
        preprocessor = _make_preprocessor()
        # S.A.F.E → SAFE via separator stripping
        result = preprocessor.normalize_input("I.G.N.O.R.E this")
        assert "." not in result.normalized_text.split()[0] or result.was_modified

    def test_empty_string_handled(self) -> None:
        preprocessor = _make_preprocessor()
        result = preprocessor.normalize_input("")
        assert result.normalized_text == ""
        assert result.was_modified is False


# ---------------------------------------------------------------------------
# Async callable interface for NeMo
# ---------------------------------------------------------------------------


class TestNeMoAsyncCallable:
    @pytest.mark.asyncio
    async def test_call_with_text_arg(self) -> None:
        preprocessor = _make_preprocessor()
        result_dict = await preprocessor("h4ck the system")
        assert "normalized_text" in result_dict
        assert "was_modified" in result_dict
        assert "transformation_count" in result_dict

    @pytest.mark.asyncio
    async def test_call_with_context_user_message(self) -> None:
        preprocessor = _make_preprocessor()
        result_dict = await preprocessor(
            text="",
            context={"user_message": "h4ck the system"},
        )
        assert "normalized_text" in result_dict
        assert "hack" in result_dict["normalized_text"]

    @pytest.mark.asyncio
    async def test_call_with_empty_text_returns_empty(self) -> None:
        preprocessor = _make_preprocessor()
        result_dict = await preprocessor(text="")
        assert result_dict["normalized_text"] == ""
        assert result_dict["was_modified"] is False
        assert result_dict["transformation_count"] == 0

    @pytest.mark.asyncio
    async def test_transformation_count_is_integer(self) -> None:
        preprocessor = _make_preprocessor()
        result_dict = await preprocessor("h4ck the system")
        assert isinstance(result_dict["transformation_count"], int)

    @pytest.mark.asyncio
    async def test_was_modified_is_bool(self) -> None:
        preprocessor = _make_preprocessor()
        result_dict = await preprocessor("plain text")
        assert isinstance(result_dict["was_modified"], bool)


# ---------------------------------------------------------------------------
# as_nemo_action
# ---------------------------------------------------------------------------


class TestAsNemoAction:
    def test_returns_callable(self) -> None:
        preprocessor = _make_preprocessor()
        action = preprocessor.as_nemo_action()
        assert callable(action)

    def test_returns_self(self) -> None:
        preprocessor = _make_preprocessor()
        action = preprocessor.as_nemo_action()
        assert action is preprocessor


# ---------------------------------------------------------------------------
# register_with_rails
# ---------------------------------------------------------------------------


class TestRegisterWithRails:
    def test_registers_default_action_name(self) -> None:
        adapter = _import_adapter()
        nemo_mod = sys.modules["nemoguardrails"]
        rails = nemo_mod.LLMRails()
        preprocessor = adapter.register_with_rails(rails)
        assert "agentshield_normalize" in rails._registered_actions
        assert isinstance(preprocessor, adapter.AgentShieldNeMoPreprocessor)

    def test_registers_custom_action_name(self) -> None:
        adapter = _import_adapter()
        nemo_mod = sys.modules["nemoguardrails"]
        rails = nemo_mod.LLMRails()
        adapter.register_with_rails(rails, action_name="my_normalizer")
        assert "my_normalizer" in rails._registered_actions

    def test_accepts_pre_configured_preprocessor(self) -> None:
        adapter = _import_adapter()
        nemo_mod = sys.modules["nemoguardrails"]
        rails = nemo_mod.LLMRails()
        custom = adapter.AgentShieldNeMoPreprocessor(enable_leetspeak=False)
        returned = adapter.register_with_rails(rails, preprocessor=custom)
        assert returned is custom

    def test_raises_on_invalid_rails_object(self) -> None:
        adapter = _import_adapter()
        with pytest.raises(AttributeError):
            adapter.register_with_rails(object())  # type: ignore[arg-type]

    def test_registered_action_is_callable(self) -> None:
        adapter = _import_adapter()
        nemo_mod = sys.modules["nemoguardrails"]
        rails = nemo_mod.LLMRails()
        adapter.register_with_rails(rails)
        action = rails._registered_actions["agentshield_normalize"]
        assert callable(action)


# ---------------------------------------------------------------------------
# PreprocessorResult
# ---------------------------------------------------------------------------


class TestPreprocessorResult:
    def test_was_modified_flag_reflects_normalization(self) -> None:
        preprocessor = _make_preprocessor()
        result = preprocessor.normalize_input("h4ck")
        assert result.was_modified == result.normalize_result.was_modified

    def test_normalized_text_matches_normalize_result(self) -> None:
        preprocessor = _make_preprocessor()
        result = preprocessor.normalize_input("test")
        assert result.normalized_text == result.normalize_result.normalized
