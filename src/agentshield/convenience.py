"""Convenience API for agentshield — 3-line quickstart.

Example
-------
::

    from agentshield import Shield
    shield = Shield()
    result = shield.check("Hello, how can I help you today?")
    print(result.safe)

"""
from __future__ import annotations

from typing import Any


class Shield:
    """Zero-config security shield for the 80% use case.

    Wraps SecurityPipeline.default() so you can scan text input and
    agent output with a single method call.

    Example
    -------
    ::

        from agentshield import Shield
        shield = Shield()
        result = shield.check("Hello, I need help with Python.")
        print(result.safe)       # True
        print(result.summary)    # brief text summary
    """

    def __init__(self) -> None:
        from agentshield.core.pipeline import SecurityPipeline

        self._pipeline = SecurityPipeline.default()

    def check(self, text: str) -> Any:
        """Scan text through the default security pipeline.

        Parameters
        ----------
        text:
            Text to scan (user input or agent output).

        Returns
        -------
        SecurityReport
            Report with ``.safe`` bool, ``.summary`` string, and
            ``.findings`` list.

        Example
        -------
        ::

            shield = Shield()
            report = shield.check("Normal user message")
            assert report.safe
        """
        return self._pipeline.scan_input_sync(text)

    def check_output(self, text: str) -> Any:
        """Scan agent output through the security pipeline.

        Parameters
        ----------
        text:
            Agent-generated text to scan for safety issues.

        Returns
        -------
        SecurityReport
            Security scan report.
        """
        return self._pipeline.scan_output_sync(text)

    @property
    def pipeline(self) -> Any:
        """The underlying SecurityPipeline instance."""
        return self._pipeline

    def __repr__(self) -> str:
        return "Shield(pipeline=SecurityPipeline.default())"
