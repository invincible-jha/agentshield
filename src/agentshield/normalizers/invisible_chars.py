"""Invisible character stripping normalizer.

Removes zero-width spaces, RTL overrides, soft hyphens, and other
Unicode format characters that adversarial inputs use to split words
and bypass string-matching defenses.
"""
from __future__ import annotations

# Unicode code points for invisible/format characters to strip
# Reference: Unicode category Cf (Format characters) + specific control chars
_INVISIBLE_CODEPOINTS: frozenset[int] = frozenset(
    [
        0x00AD,  # SOFT HYPHEN
        0x034F,  # COMBINING GRAPHEME JOINER
        0x061C,  # ARABIC LETTER MARK
        0x115F,  # HANGUL CHOSEONG FILLER
        0x1160,  # HANGUL JUNGSEONG FILLER
        0x17B4,  # KHMER VOWEL INHERENT AQ
        0x17B5,  # KHMER VOWEL INHERENT AA
        0x180B,  # MONGOLIAN FREE VARIATION SELECTOR ONE
        0x180C,  # MONGOLIAN FREE VARIATION SELECTOR TWO
        0x180D,  # MONGOLIAN FREE VARIATION SELECTOR THREE
        0x180E,  # MONGOLIAN VOWEL SEPARATOR
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE  ← common evasion vector
        0x2060,  # WORD JOINER
        0x2061,  # FUNCTION APPLICATION
        0x2062,  # INVISIBLE TIMES
        0x2063,  # INVISIBLE SEPARATOR
        0x2064,  # INVISIBLE PLUS
        0x206A,  # INHIBIT SYMMETRIC SWAPPING
        0x206B,  # ACTIVATE SYMMETRIC SWAPPING
        0x206C,  # INHIBIT ARABIC FORM SHAPING
        0x206D,  # ACTIVATE ARABIC FORM SHAPING
        0x206E,  # NATIONAL DIGIT SHAPES
        0x206F,  # NOMINAL DIGIT SHAPES
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (BOM)
        0xFFF9,  # INTERLINEAR ANNOTATION ANCHOR
        0xFFFA,  # INTERLINEAR ANNOTATION SEPARATOR
        0xFFFB,  # INTERLINEAR ANNOTATION TERMINATOR
        # Variation selectors VS1-VS16
        *range(0xFE00, 0xFE10),
        # Variation selectors supplement VS17-VS256
        *range(0xE0100, 0xE01F0),
        # Tags block (U+E0000 - U+E007F)
        *range(0xE0000, 0xE0080),
    ]
)

# Build a translation table for fast stripping
_STRIP_TABLE: dict[int, None] = {cp: None for cp in _INVISIBLE_CODEPOINTS}


def strip_invisible(text: str) -> str:
    """Remove invisible and format Unicode characters from text.

    Parameters
    ----------
    text:
        Input string that may contain invisible characters.

    Returns
    -------
    str
        The input with all invisible/format characters removed.

    Example
    -------
    ::

        text = "safe\\u200bty"  # zero-width space embedded
        strip_invisible(text)   # -> "safety"
    """
    return text.translate(_STRIP_TABLE)


def has_invisible_chars(text: str) -> bool:
    """Return True if the text contains any invisible/format characters.

    Parameters
    ----------
    text:
        Input string to check.

    Returns
    -------
    bool
        True if at least one invisible character is present.
    """
    return any(ord(ch) in _INVISIBLE_CODEPOINTS for ch in text)


def list_invisible_chars(text: str) -> list[tuple[int, str]]:
    """Return a list of (position, character) pairs for each invisible char.

    Parameters
    ----------
    text:
        Input string to inspect.

    Returns
    -------
    list[tuple[int, str]]
        Each tuple contains the character index and the character itself.
    """
    return [
        (index, char)
        for index, char in enumerate(text)
        if ord(char) in _INVISIBLE_CODEPOINTS
    ]
