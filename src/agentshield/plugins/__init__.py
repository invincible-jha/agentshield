"""Plugin system for agentshield.

Provides the scanner registry and entry-point loading machinery.
Third-party implementations register scanners via this system using
``importlib.metadata`` entry-points under the "agentshield.scanners"
group.

Example
-------
Declare a scanner plugin in pyproject.toml:

.. code-block:: toml

    [project.entry-points."agentshield.scanners"]
    my_scanner = "my_package.scanners:MyScanner"
"""
from __future__ import annotations

from agentshield.plugins.registry import (
    PluginAlreadyRegisteredError,
    PluginNotFoundError,
    PluginRegistry,
    ScannerRegistry,
    register_builtin_scanners,
    scanner_registry,
)

__all__ = [
    "PluginAlreadyRegisteredError",
    "PluginNotFoundError",
    "PluginRegistry",
    "ScannerRegistry",
    "register_builtin_scanners",
    "scanner_registry",
]
