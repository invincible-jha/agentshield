"""Character evasion normalization for agentshield.

This subpackage provides a composable pipeline for normalizing text that
has been obfuscated using common evasion techniques. Normalizing input
before scanning dramatically increases detection coverage.

Evasion techniques handled:
- Invisible/format Unicode characters (zero-width spaces, RTL overrides)
- Unicode homoglyphs (Cyrillic/Greek look-alikes substituted for Latin)
- Inter-character separators (S.A.F.E.T.Y, h-a-r-m)
- Encoded content (Base64, ROT13, hex escapes, URL encoding)
- Leetspeak (h4ck, h@rm, $ecure)

Exports
-------
TextNormalizer
    Master pipeline that chains all normalizers in sequence.
normalize
    Convenience function: normalize text using the default pipeline.
NormalizeResult
    Result of normalization: original, normalized, transformations list.
TransformationType
    Enum of normalization types that can appear in a NormalizeResult.
TransformationRecord
    Record of a single normalization transformation.

Example
-------
::

    from agentshield.normalizers import TextNormalizer, normalize

    # Using the pipeline class
    normalizer = TextNormalizer()
    result = normalizer.normalize("S.A.F.E.T.Y")
    print(result.normalized)        # "SAFETY"
    print(result.was_modified)      # True

    # Using the convenience function
    result = normalize("аttаck")    # Cyrillic а characters
    print(result.normalized)        # "attack"
"""
from __future__ import annotations

from agentshield.normalizers.encoding_detector import (
    EncodingType,
    decode_all_encodings,
    decode_base64_segments,
    decode_hex_escapes,
    decode_rot13,
    decode_url_encoding,
)
from agentshield.normalizers.homoglyph_map import (
    has_homoglyphs,
    normalize_homoglyphs,
)
from agentshield.normalizers.invisible_chars import (
    has_invisible_chars,
    list_invisible_chars,
    strip_invisible,
)
from agentshield.normalizers.leetspeak import has_leetspeak, transliterate_leet
from agentshield.normalizers.separator_strip import (
    has_char_separators,
    strip_separators,
)
from agentshield.normalizers.text_normalizer import (
    NormalizeResult,
    TextNormalizer,
    TransformationRecord,
    TransformationType,
    normalize,
)

__all__ = [
    # Pipeline
    "TextNormalizer",
    "normalize",
    "NormalizeResult",
    "TransformationType",
    "TransformationRecord",
    # Invisible chars
    "strip_invisible",
    "has_invisible_chars",
    "list_invisible_chars",
    # Homoglyphs
    "normalize_homoglyphs",
    "has_homoglyphs",
    # Separators
    "strip_separators",
    "has_char_separators",
    # Encodings
    "decode_all_encodings",
    "decode_hex_escapes",
    "decode_url_encoding",
    "decode_base64_segments",
    "decode_rot13",
    "EncodingType",
    # Leetspeak
    "transliterate_leet",
    "has_leetspeak",
]
