"""Master text normalization pipeline for evasion defense.

TextNormalizer chains multiple normalization passes to produce a canonical
form of the input text. Downstream scanners should always operate on the
normalized form to avoid evasion via character substitution or encoding.

The pipeline is:
  1. Invisible character stripping (zero-width spaces, RTL overrides, etc.)
  2. Homoglyph normalization (Cyrillic/Greek/full-width → ASCII)
  3. Separator stripping (S.A.F.E.T.Y → SAFETY)
  4. Encoding detection and decoding (base64, hex, ROT13, URL)
  5. Leetspeak transliteration (h4ck → hack)

Each normalizer can also be used independently.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum

from agentshield.normalizers.encoding_detector import (
    EncodingType,
    decode_all_encodings,
)
from agentshield.normalizers.homoglyph_map import (
    has_homoglyphs,
    normalize_homoglyphs,
)
from agentshield.normalizers.invisible_chars import (
    has_invisible_chars,
    strip_invisible,
)
from agentshield.normalizers.leetspeak import has_leetspeak, transliterate_leet
from agentshield.normalizers.separator_strip import (
    has_char_separators,
    strip_separators,
)


class TransformationType(str, Enum):
    """The type of normalization transformation applied to text."""

    INVISIBLE_CHARS_STRIPPED = "invisible_chars_stripped"
    HOMOGLYPHS_NORMALIZED = "homoglyphs_normalized"
    SEPARATORS_STRIPPED = "separators_stripped"
    ENCODING_DECODED = "encoding_decoded"
    LEETSPEAK_TRANSLITERATED = "leetspeak_transliterated"


@dataclass(frozen=True)
class TransformationRecord:
    """Record of a single normalization transformation applied to text.

    Parameters
    ----------
    transformation_type:
        Which normalization was applied.
    detail:
        Additional context about what was transformed.
    """

    transformation_type: TransformationType
    detail: str = ""


@dataclass(frozen=True)
class NormalizeResult:
    """The result of running the normalization pipeline on a text input.

    Parameters
    ----------
    original:
        The original, unmodified input text.
    normalized:
        The fully normalized output text.
    transformations:
        Ordered list of transformations that were applied.
    encoding_types:
        Encoding schemes that were detected and decoded.
    """

    original: str
    normalized: str
    transformations: list[TransformationRecord] = field(default_factory=list)
    encoding_types: list[EncodingType] = field(default_factory=list)

    @property
    def was_modified(self) -> bool:
        """True if any normalization changed the text."""
        return self.original != self.normalized

    @property
    def transformation_count(self) -> int:
        """Number of distinct normalization passes that applied."""
        return len(self.transformations)

    def to_dict(self) -> dict[str, object]:
        """Convert this result to a plain dictionary.

        Returns
        -------
        dict[str, object]
        """
        return {
            "original": self.original,
            "normalized": self.normalized,
            "was_modified": self.was_modified,
            "transformations": [
                {
                    "type": t.transformation_type.value,
                    "detail": t.detail,
                }
                for t in self.transformations
            ],
            "encoding_types": [e.value for e in self.encoding_types],
        }


class TextNormalizer:
    """Composable pipeline for normalizing evasion-obfuscated text.

    The normalizer chains all available normalization passes in a safe
    sequence. Each pass is applied only when its corresponding detector
    indicates the pass would modify the text.

    The pipeline is idempotent: ``normalize(normalize(x)) == normalize(x)``.

    Parameters
    ----------
    enable_invisible_chars:
        Whether to strip invisible/format Unicode characters. Default: True.
    enable_homoglyphs:
        Whether to normalize Unicode homoglyphs to ASCII. Default: True.
    enable_separators:
        Whether to strip inter-character separators. Default: True.
    enable_encodings:
        Whether to detect and decode encoded content. Default: True.
    enable_leetspeak:
        Whether to transliterate leetspeak tokens. Default: True.

    Example
    -------
    ::

        normalizer = TextNormalizer()
        result = normalizer.normalize("S.A.F.E.T.Y")
        print(result.normalized)     # "SAFETY"
        print(result.was_modified)   # True
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
        self._enable_invisible = enable_invisible_chars
        self._enable_homoglyphs = enable_homoglyphs
        self._enable_separators = enable_separators
        self._enable_encodings = enable_encodings
        self._enable_leet = enable_leetspeak

    def normalize(self, text: str) -> NormalizeResult:
        """Apply the full normalization pipeline to the input text.

        Passes are applied in order. Each pass operates on the output
        of the previous pass, so normalizations are composable.

        Parameters
        ----------
        text:
            The raw input text to normalize.

        Returns
        -------
        NormalizeResult
            The normalized text plus metadata about what was applied.
        """
        original = text
        current = text
        transformations: list[TransformationRecord] = []
        encoding_types: list[EncodingType] = []

        # Pass 1: Strip invisible/format characters
        if self._enable_invisible and has_invisible_chars(current):
            after = strip_invisible(current)
            if after != current:
                transformations.append(
                    TransformationRecord(
                        transformation_type=TransformationType.INVISIBLE_CHARS_STRIPPED,
                        detail="Removed zero-width, RTL override, and format characters.",
                    )
                )
                current = after

        # Pass 2: Normalize homoglyphs (Cyrillic/Greek/full-width → ASCII)
        if self._enable_homoglyphs and has_homoglyphs(current):
            after = normalize_homoglyphs(current)
            if after != current:
                transformations.append(
                    TransformationRecord(
                        transformation_type=TransformationType.HOMOGLYPHS_NORMALIZED,
                        detail="Replaced Unicode homoglyphs with ASCII equivalents.",
                    )
                )
                current = after

        # Pass 3: Strip inter-character separators (S.A.F.E → SAFE)
        if self._enable_separators and has_char_separators(current):
            after = strip_separators(current)
            if after != current:
                transformations.append(
                    TransformationRecord(
                        transformation_type=TransformationType.SEPARATORS_STRIPPED,
                        detail="Removed inter-character separators from obfuscated tokens.",
                    )
                )
                current = after

        # Pass 4: Detect and decode encodings (hex, URL, ROT13, base64)
        if self._enable_encodings:
            after, detected = decode_all_encodings(current)
            if detected:
                encoding_types.extend(detected)
                transformations.append(
                    TransformationRecord(
                        transformation_type=TransformationType.ENCODING_DECODED,
                        detail=f"Decoded: {', '.join(e.value for e in detected)}.",
                    )
                )
                current = after

        # Pass 5: Transliterate leetspeak (h4ck → hack)
        if self._enable_leet and has_leetspeak(current):
            after = transliterate_leet(current)
            if after != current:
                transformations.append(
                    TransformationRecord(
                        transformation_type=TransformationType.LEETSPEAK_TRANSLITERATED,
                        detail="Transliterated leetspeak character substitutions.",
                    )
                )
                current = after

        return NormalizeResult(
            original=original,
            normalized=current,
            transformations=transformations,
            encoding_types=encoding_types,
        )


def normalize(text: str) -> NormalizeResult:
    """Convenience function: normalize text using the default pipeline.

    Equivalent to ``TextNormalizer().normalize(text)``.

    Parameters
    ----------
    text:
        The raw input text to normalize.

    Returns
    -------
    NormalizeResult
        The normalized text plus metadata about what was applied.
    """
    return TextNormalizer().normalize(text)
