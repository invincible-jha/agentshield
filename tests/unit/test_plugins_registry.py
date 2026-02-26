"""Tests for agentshield.plugins.registry — PluginRegistry, ScannerRegistry."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from unittest.mock import MagicMock, patch

import pytest

from agentshield.plugins.registry import (
    PluginAlreadyRegisteredError,
    PluginNotFoundError,
    PluginRegistry,
    ScannerRegistry,
    register_builtin_scanners,
    scanner_registry,
)


# ---------------------------------------------------------------------------
# Helpers — a tiny in-test ABC and subclasses so we can make independent
# PluginRegistry instances without contaminating global state.
# ---------------------------------------------------------------------------


class _FakeBase(ABC):
    @abstractmethod
    def do(self) -> str: ...


class _FakePlugin(_FakeBase):
    def do(self) -> str:
        return "fake"


class _FakePlugin2(_FakeBase):
    def do(self) -> str:
        return "fake2"


def _fresh_registry() -> PluginRegistry[_FakeBase]:
    return PluginRegistry(_FakeBase, "test-registry")


# ---------------------------------------------------------------------------
# PluginNotFoundError
# ---------------------------------------------------------------------------


class TestPluginNotFoundError:
    def test_message_contains_plugin_name(self) -> None:
        err = PluginNotFoundError("my-plugin", "my-registry")
        assert "my-plugin" in str(err)

    def test_attributes_set(self) -> None:
        err = PluginNotFoundError("p", "r")
        assert err.plugin_name == "p"
        assert err.registry_name == "r"

    def test_is_key_error(self) -> None:
        assert isinstance(PluginNotFoundError("p", "r"), KeyError)


class TestPluginAlreadyRegisteredError:
    def test_message_contains_plugin_name(self) -> None:
        err = PluginAlreadyRegisteredError("my-plugin", "my-registry")
        assert "my-plugin" in str(err)

    def test_attributes_set(self) -> None:
        err = PluginAlreadyRegisteredError("p", "r")
        assert err.plugin_name == "p"
        assert err.registry_name == "r"

    def test_is_value_error(self) -> None:
        assert isinstance(PluginAlreadyRegisteredError("p", "r"), ValueError)


# ---------------------------------------------------------------------------
# PluginRegistry — registration
# ---------------------------------------------------------------------------


class TestPluginRegistryRegisterDecorator:
    def test_register_decorator_returns_class_unchanged(self) -> None:
        registry = _fresh_registry()
        cls = registry.register("myplugin")(_FakePlugin)
        assert cls is _FakePlugin

    def test_register_makes_plugin_discoverable(self) -> None:
        registry = _fresh_registry()
        registry.register("myplugin")(_FakePlugin)
        assert "myplugin" in registry

    def test_register_duplicate_raises(self) -> None:
        registry = _fresh_registry()
        registry.register("dup")(_FakePlugin)
        with pytest.raises(PluginAlreadyRegisteredError):
            registry.register("dup")(_FakePlugin)

    def test_register_non_subclass_raises_type_error(self) -> None:
        registry = _fresh_registry()

        class NotASubclass:
            pass

        with pytest.raises(TypeError):
            registry.register("bad")(NotASubclass)  # type: ignore[arg-type]

    def test_registered_class_instantiable(self) -> None:
        registry = _fresh_registry()
        registry.register("inst")(_FakePlugin)
        cls = registry.get("inst")
        instance = cls()
        assert instance.do() == "fake"


class TestPluginRegistryRegisterClass:
    def test_register_class_works(self) -> None:
        registry = _fresh_registry()
        registry.register_class("direct", _FakePlugin)
        assert "direct" in registry

    def test_register_class_duplicate_raises(self) -> None:
        registry = _fresh_registry()
        registry.register_class("dup", _FakePlugin)
        with pytest.raises(PluginAlreadyRegisteredError):
            registry.register_class("dup", _FakePlugin2)

    def test_register_class_non_subclass_raises(self) -> None:
        registry = _fresh_registry()

        class Stranger:
            pass

        with pytest.raises(TypeError):
            registry.register_class("bad", Stranger)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# PluginRegistry — lookup
# ---------------------------------------------------------------------------


class TestPluginRegistryGet:
    def test_get_registered_class(self) -> None:
        registry = _fresh_registry()
        registry.register_class("p", _FakePlugin)
        assert registry.get("p") is _FakePlugin

    def test_get_missing_raises_plugin_not_found(self) -> None:
        registry = _fresh_registry()
        with pytest.raises(PluginNotFoundError):
            registry.get("nonexistent")

    def test_list_plugins_empty_registry(self) -> None:
        registry = _fresh_registry()
        assert registry.list_plugins() == []

    def test_list_plugins_sorted(self) -> None:
        registry = _fresh_registry()
        registry.register_class("c", _FakePlugin)
        registry.register_class("a", _FakePlugin2)
        registry.register_class("b", _FakePlugin)
        assert registry.list_plugins() == ["a", "b", "c"]

    def test_contains_true_for_registered(self) -> None:
        registry = _fresh_registry()
        registry.register_class("exists", _FakePlugin)
        assert "exists" in registry

    def test_contains_false_for_missing(self) -> None:
        registry = _fresh_registry()
        assert "nope" not in registry

    def test_len_zero_initially(self) -> None:
        registry = _fresh_registry()
        assert len(registry) == 0

    def test_len_increases_on_register(self) -> None:
        registry = _fresh_registry()
        registry.register_class("a", _FakePlugin)
        registry.register_class("b", _FakePlugin2)
        assert len(registry) == 2

    def test_repr_contains_registry_name(self) -> None:
        registry = _fresh_registry()
        assert "test-registry" in repr(registry)


class TestPluginRegistryDeregister:
    def test_deregister_removes_plugin(self) -> None:
        registry = _fresh_registry()
        registry.register_class("to-remove", _FakePlugin)
        registry.deregister("to-remove")
        assert "to-remove" not in registry

    def test_deregister_missing_raises(self) -> None:
        registry = _fresh_registry()
        with pytest.raises(PluginNotFoundError):
            registry.deregister("nonexistent")


# ---------------------------------------------------------------------------
# PluginRegistry — load_entrypoints
# ---------------------------------------------------------------------------


class TestLoadEntrypoints:
    def test_already_registered_skipped(self) -> None:
        registry = _fresh_registry()
        registry.register_class("existing", _FakePlugin)

        mock_ep = MagicMock()
        mock_ep.name = "existing"
        mock_ep.load.return_value = _FakePlugin2

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("test.group")

        # Should still be the original plugin
        assert registry.get("existing") is _FakePlugin

    def test_load_error_is_skipped(self) -> None:
        registry = _fresh_registry()

        mock_ep = MagicMock()
        mock_ep.name = "broken"
        mock_ep.load.side_effect = ImportError("module not found")

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("test.group")

        assert "broken" not in registry

    def test_type_error_on_load_is_skipped(self) -> None:
        registry = _fresh_registry()

        class NotASubclass:
            pass

        mock_ep = MagicMock()
        mock_ep.name = "wrong-type"
        mock_ep.load.return_value = NotASubclass

        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("test.group")

        assert "wrong-type" not in registry


# ---------------------------------------------------------------------------
# ScannerRegistry
# ---------------------------------------------------------------------------


class TestScannerRegistry:
    def test_register_builtin_scanners_runs_without_error(self) -> None:
        register_builtin_scanners()

    def test_builtin_scanners_registered(self) -> None:
        register_builtin_scanners()
        expected = {
            "regex_injection",
            "pii_detector",
            "credential_detector",
            "output_safety",
            "tool_call_validator",
            "behavioral_checker",
            "output_validator",
            "tool_call_checker",
        }
        for slug in expected:
            assert slug in scanner_registry, f"{slug!r} not in scanner_registry"

    def test_register_builtin_scanners_is_idempotent(self) -> None:
        register_builtin_scanners()
        register_builtin_scanners()  # Second call should not raise

    def test_fresh_scanner_registry_starts_empty(self) -> None:
        fresh = ScannerRegistry()
        assert len(fresh) == 0

    def test_register_scanner(self) -> None:
        # Registering a non-Scanner subclass must raise TypeError.
        fresh = ScannerRegistry()
        with pytest.raises(TypeError):
            fresh.register_scanner("my_scanner", _FakePlugin)  # type: ignore[arg-type]

        # Registering a real Scanner subclass must succeed.
        from agentshield.scanners.output_safety import OutputSafetyScanner
        fresh2 = ScannerRegistry()
        fresh2.register_scanner("output_safety_test", OutputSafetyScanner)
        assert "output_safety_test" in fresh2

    def test_get_scanner_returns_class(self) -> None:
        fresh = ScannerRegistry()
        from agentshield.scanners.output_safety import OutputSafetyScanner
        fresh.register_scanner("output_safety_v2", OutputSafetyScanner)
        cls = fresh.get_scanner("output_safety_v2")
        assert cls is OutputSafetyScanner

    def test_get_scanner_missing_raises(self) -> None:
        fresh = ScannerRegistry()
        with pytest.raises(PluginNotFoundError):
            fresh.get_scanner("nonexistent")

    def test_list_scanners_sorted(self) -> None:
        fresh = ScannerRegistry()
        from agentshield.scanners.output_safety import OutputSafetyScanner
        from agentshield.scanners.output_validator import OutputValidator
        fresh.register_scanner("z_scanner", OutputSafetyScanner)
        fresh.register_scanner("a_scanner", OutputValidator)
        slugs = fresh.list_scanners()
        assert slugs == sorted(slugs)

    def test_contains_check(self) -> None:
        fresh = ScannerRegistry()
        from agentshield.scanners.output_safety import OutputSafetyScanner
        fresh.register_scanner("test_scanner", OutputSafetyScanner)
        assert "test_scanner" in fresh
        assert "nope" not in fresh

    def test_len(self) -> None:
        fresh = ScannerRegistry()
        assert len(fresh) == 0
        from agentshield.scanners.output_safety import OutputSafetyScanner
        fresh.register_scanner("s1", OutputSafetyScanner)
        assert len(fresh) == 1

    def test_repr_contains_scanners(self) -> None:
        fresh = ScannerRegistry()
        assert "ScannerRegistry" in repr(fresh)
