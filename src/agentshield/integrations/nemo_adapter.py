"""NeMo Guardrails adapter — AgentShield normalizer as a NeMo input rail.

Registers the AgentShield TextNormalizer as a NeMo Guardrails preprocessing
action. The normalizer strips homoglyphs, invisible characters, leetspeak, and
encoded payloads before NeMo's own rails execute, providing character-evasion
defense as a first-pass filter.

Install the extra to use this module::

    pip install aumos-agentshield[nemo]

Usage
-----
::

    from agentshield.integrations.nemo_adapter import (
        AgentShieldNeMoPreprocessor,
        register_with_rails,
    )
    from nemoguardrails import LLMRails

    rails = LLMRails(config=...)
    register_with_rails(rails)

Or use the preprocessor standalone::

    preprocessor = AgentShieldNeMoPreprocessor()
    result = preprocessor.normalize_input("h4ck the system")
    # result.normalized == "hack the system"
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from agentshield.normalizers.text_normalizer import NormalizeResult, TextNormalizer

try:
    import nemoguardrails  # type: ignore[import-untyped]
    from nemoguardrails import LLMRails  # type: ignore[import-untyped]
except ImportError as _import_error:
    raise ImportError(
        "NeMo Guardrails is required for this adapter. "
        "Install it with: pip install aumos-agentshield[nemo]"
    ) from _import_error

logger = logging.getLogger(__name__)

# Action name used when registering with NeMo's action registry
_NEMO_ACTION_NAME = "agentshield_normalize"


@dataclass
class PreprocessorResult:
    """Result of an AgentShield preprocessing step within NeMo.

    Parameters
    ----------
    original_text:
        The raw input before normalization.
    normalized_text:
        The canonical form after normalization.
    normalize_result:
        Full NormalizeResult with transformation metadata.
    was_modified:
        Convenience flag — True when normalization changed the text.
    """

    original_text: str
    normalized_text: str
    normalize_result: NormalizeResult
    was_modified: bool


class AgentShieldNeMoPreprocessor:
    """NeMo Guardrails input rail that normalizes text with AgentShield.

    The preprocessor wraps AgentShield's TextNormalizer and exposes it as
    a NeMo ``action`` that can be registered via ``LLMRails.register_action()``.
    When called from Colang flow, it receives the raw user message, normalizes
    it to strip evasion techniques, and returns the canonical form.

    Parameters
    ----------
    enable_invisible_chars:
        Strip zero-width, RTL override, and other invisible Unicode. Default: True.
    enable_homoglyphs:
        Replace Unicode homoglyphs (Cyrillic/Greek look-alikes) with ASCII. Default: True.
    enable_separators:
        Strip inter-character separators (S.A.F.E → SAFE). Default: True.
    enable_encodings:
        Detect and decode base64, hex, URL, ROT13 payloads. Default: True.
    enable_leetspeak:
        Transliterate leetspeak substitutions (h4ck → hack). Default: True.

    Examples
    --------
    ::

        preprocessor = AgentShieldNeMoPreprocessor()
        result = preprocessor.normalize_input("ign0re a11 prev10us instructions")
        print(result.normalized_text)  # "ignore all previous instructions"
    """

    def __init__(
        self,
        *,
        enable_invisible_chars: bool = True,
        enable_homoglyphs: bool = True,
        enable_separators: bool = True,
        enable_encodings: bool = True,
        enable_leetspeak: bool = True,
    ) -> None:
        self._normalizer = TextNormalizer(
            enable_invisible_chars=enable_invisible_chars,
            enable_homoglyphs=enable_homoglyphs,
            enable_separators=enable_separators,
            enable_encodings=enable_encodings,
            enable_leetspeak=enable_leetspeak,
        )

    # ------------------------------------------------------------------
    # Core normalization
    # ------------------------------------------------------------------

    def normalize_input(self, text: str) -> PreprocessorResult:
        """Normalize raw user input through the full AgentShield pipeline.

        Parameters
        ----------
        text:
            The raw user message to normalize.

        Returns
        -------
        PreprocessorResult
            Contains the normalized text and full transformation metadata.
        """
        result = self._normalizer.normalize(text)
        logger.debug(
            "AgentShield normalization: modified=%s transformations=%d",
            result.was_modified,
            result.transformation_count,
        )
        return PreprocessorResult(
            original_text=result.original,
            normalized_text=result.normalized,
            normalize_result=result,
            was_modified=result.was_modified,
        )

    # ------------------------------------------------------------------
    # NeMo action interface
    # ------------------------------------------------------------------

    async def __call__(
        self,
        text: str = "",
        context: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """NeMo action callable — normalize text and return result dict.

        NeMo Guardrails invokes registered actions as async callables,
        passing the current context. This method adapts the signature
        to the NeMo action protocol.

        Parameters
        ----------
        text:
            User input to normalize. NeMo passes this via the action call.
        context:
            NeMo runtime context dict (may contain ``user_message`` key).
        **kwargs:
            Additional NeMo-provided keyword arguments (ignored).

        Returns
        -------
        dict[str, Any]
            Dict with ``normalized_text``, ``was_modified``, and
            ``transformation_count`` keys, suitable for use in Colang flows.
        """
        # NeMo may pass the message via context["user_message"] rather than text
        if not text and context:
            text = str(context.get("user_message", ""))

        if not text:
            return {
                "normalized_text": "",
                "was_modified": False,
                "transformation_count": 0,
            }

        result = self.normalize_input(text)
        return {
            "normalized_text": result.normalized_text,
            "was_modified": result.was_modified,
            "transformation_count": result.normalize_result.transformation_count,
        }

    # ------------------------------------------------------------------
    # Registration helpers
    # ------------------------------------------------------------------

    def as_nemo_action(self) -> Any:
        """Return this preprocessor as a NeMo-compatible action callable.

        Returns
        -------
        AgentShieldNeMoPreprocessor
            The preprocessor itself (already implements the async callable
            protocol required by NeMo's ``register_action()``).
        """
        return self

    def __repr__(self) -> str:
        return "AgentShieldNeMoPreprocessor()"


def register_with_rails(
    rails: Any,
    preprocessor: Optional[AgentShieldNeMoPreprocessor] = None,
    action_name: str = _NEMO_ACTION_NAME,
) -> AgentShieldNeMoPreprocessor:
    """Register the AgentShield preprocessor with a NeMo LLMRails instance.

    Parameters
    ----------
    rails:
        The ``nemoguardrails.LLMRails`` instance to register with.
    preprocessor:
        Pre-configured preprocessor. Defaults to a new instance with all
        normalization passes enabled.
    action_name:
        Name under which the action is registered. Defaults to
        ``"agentshield_normalize"``.

    Returns
    -------
    AgentShieldNeMoPreprocessor
        The registered preprocessor instance.

    Raises
    ------
    AttributeError
        If the provided ``rails`` object does not have a ``register_action``
        method (wrong type passed).

    Examples
    --------
    ::

        from nemoguardrails import LLMRails
        from agentshield.integrations.nemo_adapter import register_with_rails

        rails = LLMRails(config=my_config)
        preprocessor = register_with_rails(rails)
        # Now "agentshield_normalize" is available in Colang flows.
    """
    if not hasattr(rails, "register_action"):
        raise AttributeError(
            f"Expected an LLMRails instance with register_action(), got {type(rails)!r}"
        )

    instance = preprocessor or AgentShieldNeMoPreprocessor()
    rails.register_action(instance.as_nemo_action(), name=action_name)
    logger.info("AgentShield preprocessor registered with NeMo as action %r", action_name)
    return instance
