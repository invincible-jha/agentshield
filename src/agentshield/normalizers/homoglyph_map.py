"""Unicode homoglyph normalization.

Maps visually similar Unicode characters (homoglyphs) to their ASCII
equivalents. This prevents evasion attacks that substitute Cyrillic,
Greek, or math-bold characters for Latin letters that look identical.

For example: Cyrillic "а" (U+0430) looks identical to Latin "a" (U+0061)
but is a different codepoint that bypasses ASCII-based keyword matching.
"""
from __future__ import annotations

# -----------------------------------------------------------------------
# Comprehensive homoglyph mapping: Unicode codepoint → ASCII character
# -----------------------------------------------------------------------
# Sources:
# - Unicode Confusables (https://www.unicode.org/reports/tr39/)
# - Common attack patterns documented in security research
# -----------------------------------------------------------------------

_HOMOGLYPH_MAP: dict[str, str] = {
    # ===== Cyrillic → Latin =====
    "\u0430": "a",  # CYRILLIC SMALL LETTER A → a
    "\u0410": "A",  # CYRILLIC CAPITAL LETTER A → A
    "\u0431": "b",  # CYRILLIC SMALL LETTER BE → b (approximate)
    "\u0432": "b",  # CYRILLIC SMALL LETTER VE → b (visual approximation)
    "\u0042": "B",  # (already ASCII, but included for completeness)
    "\u0412": "B",  # CYRILLIC CAPITAL LETTER VE → B
    "\u0441": "c",  # CYRILLIC SMALL LETTER ES → c
    "\u0421": "C",  # CYRILLIC CAPITAL LETTER ES → C
    "\u0435": "e",  # CYRILLIC SMALL LETTER IE → e
    "\u0415": "E",  # CYRILLIC CAPITAL LETTER IE → E
    "\u0454": "e",  # CYRILLIC SMALL LETTER UKRAINIAN IE → e
    "\u0404": "E",  # CYRILLIC CAPITAL LETTER UKRAINIAN IE → E
    "\u0433": "g",  # CYRILLIC SMALL LETTER GHE → g (approximate)
    "\u0453": "g",  # CYRILLIC SMALL LETTER GJE → g
    "\u0456": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I → i
    "\u0406": "I",  # CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I → I
    "\u0457": "i",  # CYRILLIC SMALL LETTER YI → i
    "\u0407": "I",  # CYRILLIC CAPITAL LETTER YI → I
    "\u0458": "j",  # CYRILLIC SMALL LETTER JE → j
    "\u043A": "k",  # CYRILLIC SMALL LETTER KA → k (approximate)
    "\u041A": "K",  # CYRILLIC CAPITAL LETTER KA → K
    "\u043C": "m",  # CYRILLIC SMALL LETTER EM → m (approximate)
    "\u041C": "M",  # CYRILLIC CAPITAL LETTER EM → M
    "\u043D": "n",  # CYRILLIC SMALL LETTER EN → n (approximate)
    "\u041D": "N",  # CYRILLIC CAPITAL LETTER EN → N
    "\u043E": "o",  # CYRILLIC SMALL LETTER O → o
    "\u041E": "O",  # CYRILLIC CAPITAL LETTER O → O
    "\u0440": "p",  # CYRILLIC SMALL LETTER ER → p
    "\u0420": "P",  # CYRILLIC CAPITAL LETTER ER → P
    "\u0455": "s",  # CYRILLIC SMALL LETTER DZE → s
    "\u0445": "x",  # CYRILLIC SMALL LETTER HA → x
    "\u0425": "X",  # CYRILLIC CAPITAL LETTER HA → X
    "\u0443": "y",  # CYRILLIC SMALL LETTER U → y
    "\u0423": "Y",  # CYRILLIC CAPITAL LETTER U → Y
    "\u044B": "bl",  # CYRILLIC SMALL LETTER YERU (approximate visual)

    # ===== Greek → Latin =====
    "\u03B1": "a",  # GREEK SMALL LETTER ALPHA → a
    "\u0391": "A",  # GREEK CAPITAL LETTER ALPHA → A
    "\u03B2": "b",  # GREEK SMALL LETTER BETA → b
    "\u0392": "B",  # GREEK CAPITAL LETTER BETA → B
    "\u03B3": "y",  # GREEK SMALL LETTER GAMMA → y (approximate)
    "\u03B5": "e",  # GREEK SMALL LETTER EPSILON → e
    "\u0395": "E",  # GREEK CAPITAL LETTER EPSILON → E
    "\u03B7": "n",  # GREEK SMALL LETTER ETA → n
    "\u0397": "H",  # GREEK CAPITAL LETTER ETA → H
    "\u03B9": "i",  # GREEK SMALL LETTER IOTA → i
    "\u0399": "I",  # GREEK CAPITAL LETTER IOTA → I
    "\u03BA": "k",  # GREEK SMALL LETTER KAPPA → k
    "\u039A": "K",  # GREEK CAPITAL LETTER KAPPA → K
    "\u03BC": "u",  # GREEK SMALL LETTER MU → u (approximate)
    "\u039C": "M",  # GREEK CAPITAL LETTER MU → M
    "\u03BD": "v",  # GREEK SMALL LETTER NU → v
    "\u039D": "N",  # GREEK CAPITAL LETTER NU → N
    "\u03BF": "o",  # GREEK SMALL LETTER OMICRON → o
    "\u039F": "O",  # GREEK CAPITAL LETTER OMICRON → O
    "\u03C1": "p",  # GREEK SMALL LETTER RHO → p
    "\u03A1": "P",  # GREEK CAPITAL LETTER RHO → P
    "\u03C4": "t",  # GREEK SMALL LETTER TAU → t
    "\u03A4": "T",  # GREEK CAPITAL LETTER TAU → T
    "\u03C5": "u",  # GREEK SMALL LETTER UPSILON → u
    "\u03A5": "Y",  # GREEK CAPITAL LETTER UPSILON → Y
    "\u03C7": "x",  # GREEK SMALL LETTER CHI → x
    "\u03A7": "X",  # GREEK CAPITAL LETTER CHI → X
    "\u03C9": "w",  # GREEK SMALL LETTER OMEGA → w
    "\u03A9": "W",  # GREEK CAPITAL LETTER OMEGA → W
    "\u03C6": "o",  # GREEK SMALL LETTER PHI → o (approximate)

    # ===== Full-width Latin → ASCII =====
    # Full-width A-Z (U+FF21 - U+FF3A) → A-Z
    **{chr(0xFF21 + i): chr(ord("A") + i) for i in range(26)},
    # Full-width a-z (U+FF41 - U+FF5A) → a-z
    **{chr(0xFF41 + i): chr(ord("a") + i) for i in range(26)},
    # Full-width digits (U+FF10 - U+FF19) → 0-9
    **{chr(0xFF10 + i): chr(ord("0") + i) for i in range(10)},

    # ===== Mathematical Alphanumeric Symbols (bold, italic, etc.) =====
    # Mathematical Bold Capital A-Z (U+1D400-U+1D419) → A-Z
    **{chr(0x1D400 + i): chr(ord("A") + i) for i in range(26)},
    # Mathematical Bold Small a-z (U+1D41A-U+1D433) → a-z
    **{chr(0x1D41A + i): chr(ord("a") + i) for i in range(26)},
    # Mathematical Italic Capital A-Z (U+1D434-U+1D44D) → A-Z
    **{chr(0x1D434 + i): chr(ord("A") + i) for i in range(26)},
    # Mathematical Italic Small a-z (U+1D44E-U+1D467) → a-z (with gap at h)
    **{chr(0x1D44E + i): chr(ord("a") + i) for i in range(26) if i != 7},
    "\u210E": "h",  # PLANCK CONSTANT (italic h) → h
    # Mathematical Bold Italic (U+1D468 - U+1D481)
    **{chr(0x1D468 + i): chr(ord("A") + i) for i in range(26)},
    **{chr(0x1D482 + i): chr(ord("a") + i) for i in range(26)},
    # Mathematical Script (U+1D49C+) — partial
    "\u1D49C": "A",  # MATHEMATICAL SCRIPT CAPITAL A
    "\u1D4A2": "G",
    "\u1D4A5": "J",
    "\u1D4A6": "K",
    "\u1D4A9": "N",
    "\u1D4AA": "O",
    "\u1D4AB": "P",
    "\u1D4AC": "Q",
    "\u1D4AE": "S",
    "\u1D4AF": "T",
    "\u1D4B0": "U",
    "\u1D4B1": "V",
    "\u1D4B2": "W",
    "\u1D4B3": "X",
    "\u1D4B4": "Y",
    "\u1D4B5": "Z",
    # Mathematical Double-Struck (Blackboard Bold)
    "\u1D538": "A",  # MATHEMATICAL DOUBLE-STRUCK CAPITAL A
    "\u1D539": "B",
    "\u2102": "C",   # DOUBLE-STRUCK CAPITAL C
    "\u1D53B": "D",
    "\u1D53C": "E",
    "\u1D53D": "F",
    "\u1D53E": "G",
    "\u210D": "H",   # DOUBLE-STRUCK CAPITAL H
    "\u1D540": "I",
    "\u1D541": "J",
    "\u1D542": "K",
    "\u1D543": "L",
    "\u1D544": "M",
    "\u2115": "N",   # DOUBLE-STRUCK CAPITAL N
    "\u1D546": "O",
    "\u2119": "P",   # DOUBLE-STRUCK CAPITAL P
    "\u211A": "Q",   # DOUBLE-STRUCK CAPITAL Q
    "\u211D": "R",   # DOUBLE-STRUCK CAPITAL R
    "\u1D54A": "S",
    "\u1D54B": "T",
    "\u1D54C": "U",
    "\u1D54D": "V",
    "\u1D54E": "W",
    "\u1D54F": "X",
    "\u1D550": "Y",
    "\u2124": "Z",   # DOUBLE-STRUCK CAPITAL Z

    # ===== Other common confusables =====
    "\u00B0": "o",   # DEGREE SIGN → o (approximate)
    "\u00D0": "D",   # LATIN CAPITAL LETTER ETH → D
    "\u00F0": "d",   # LATIN SMALL LETTER ETH → d
    "\u00D8": "O",   # LATIN CAPITAL LETTER O WITH STROKE → O
    "\u00F8": "o",   # LATIN SMALL LETTER O WITH STROKE → o
    "\u0152": "OE",  # LATIN CAPITAL LIGATURE OE
    "\u0153": "oe",  # LATIN SMALL LIGATURE OE
    "\u00C6": "AE",  # LATIN CAPITAL LIGATURE AE
    "\u00E6": "ae",  # LATIN SMALL LIGATURE AE
    "\u00DF": "ss",  # LATIN SMALL LETTER SHARP S
    "\u1E9E": "SS",  # LATIN CAPITAL LETTER SHARP S
    "\u0131": "i",   # LATIN SMALL LETTER DOTLESS I
    "\u0130": "I",   # LATIN CAPITAL LETTER I WITH DOT ABOVE
    "\u0141": "L",   # LATIN CAPITAL LETTER L WITH STROKE
    "\u0142": "l",   # LATIN SMALL LETTER L WITH STROKE
    "\u01C0": "|",   # LATIN LETTER DENTAL CLICK
    "\u2223": "|",   # DIVIDES
    "\u2502": "|",   # BOX DRAWINGS LIGHT VERTICAL
    "\u0406": "I",   # CYRILLIC CAPITAL I (duplicate guard)
    "\u04CF": "l",   # CYRILLIC SMALL LETTER PALOCHKA → l
    "\u04C0": "I",   # CYRILLIC LETTER PALOCHKA → I
    # Digits
    "\u2070": "0",   # SUPERSCRIPT ZERO
    "\u00B9": "1",   # SUPERSCRIPT ONE
    "\u00B2": "2",   # SUPERSCRIPT TWO
    "\u00B3": "3",   # SUPERSCRIPT THREE
    "\u2074": "4",   # SUPERSCRIPT FOUR
    "\u2075": "5",   # SUPERSCRIPT FIVE
    "\u2076": "6",   # SUPERSCRIPT SIX
    "\u2077": "7",   # SUPERSCRIPT SEVEN
    "\u2078": "8",   # SUPERSCRIPT EIGHT
    "\u2079": "9",   # SUPERSCRIPT NINE
    # Punctuation lookalikes
    "\u2010": "-",   # HYPHEN
    "\u2011": "-",   # NON-BREAKING HYPHEN
    "\u2012": "-",   # FIGURE DASH
    "\u2013": "-",   # EN DASH
    "\u2014": "-",   # EM DASH
    "\u2015": "-",   # HORIZONTAL BAR
    "\u2018": "'",   # LEFT SINGLE QUOTATION MARK
    "\u2019": "'",   # RIGHT SINGLE QUOTATION MARK
    "\u201C": '"',   # LEFT DOUBLE QUOTATION MARK
    "\u201D": '"',   # RIGHT DOUBLE QUOTATION MARK
    "\u2022": "*",   # BULLET
    "\u2027": ".",   # HYPHENATION POINT
    "\u2024": ".",   # ONE DOT LEADER
    "\u2025": "..",  # TWO DOT LEADER
    "\u2026": "...", # HORIZONTAL ELLIPSIS
}

# Build a translation table for O(1) character lookup.
# Only include entries where the source is a single character (as expected).
# Multi-char targets (e.g., "AE" for ligature Æ) are valid — only the key
# must be a single codepoint.
_TRANSLATION_TABLE: dict[int, str] = {
    ord(source): target
    for source, target in _HOMOGLYPH_MAP.items()
    if len(source) == 1
}


def normalize_homoglyphs(text: str) -> str:
    """Replace Unicode homoglyphs with their ASCII equivalents.

    Processes each character individually and replaces known homoglyphs.
    Characters not in the mapping are passed through unchanged.

    Parameters
    ----------
    text:
        Input string that may contain Unicode homoglyphs.

    Returns
    -------
    str
        The input with all known homoglyphs replaced by ASCII equivalents.

    Example
    -------
    ::

        normalize_homoglyphs("аttаck")   # Cyrillic а → 'attack'
        normalize_homoglyphs("Ｈello")   # Full-width Ｈ → 'Hello'
    """
    if not text:
        return text

    result_chars: list[str] = []
    for char in text:
        code_point = ord(char)
        replacement = _TRANSLATION_TABLE.get(code_point)
        if replacement is not None:
            result_chars.append(replacement)
        else:
            result_chars.append(char)
    return "".join(result_chars)


def has_homoglyphs(text: str) -> bool:
    """Return True if the text contains any known homoglyph characters.

    Parameters
    ----------
    text:
        Input string to check.

    Returns
    -------
    bool
        True if at least one homoglyph is present.
    """
    return any(ord(ch) in _TRANSLATION_TABLE for ch in text)


def list_homoglyphs(text: str) -> list[tuple[int, str, str]]:
    """Return a list of (position, original_char, ascii_replacement) for each homoglyph.

    Parameters
    ----------
    text:
        Input string to inspect.

    Returns
    -------
    list[tuple[int, str, str]]
        Each tuple contains (character index, original character, ASCII replacement).
    """
    results: list[tuple[int, str, str]] = []
    for index, char in enumerate(text):
        replacement = _TRANSLATION_TABLE.get(ord(char))
        if replacement is not None:
            results.append((index, char, replacement))
    return results
