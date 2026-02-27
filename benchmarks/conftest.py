"""Shared bootstrap for agentshield benchmarks."""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent
_SRC = _REPO_ROOT / "src"
_BENCHMARKS = _REPO_ROOT / "benchmarks"

for _path in [str(_SRC), str(_BENCHMARKS)]:
    if _path not in sys.path:
        sys.path.insert(0, _path)

from agentshield.core.context import ScanContext
from agentshield.core.scanner import ScanPhase
from agentshield.scanners.regex_injection import RegexInjectionScanner

__all__ = ["ScanContext", "ScanPhase", "RegexInjectionScanner"]
