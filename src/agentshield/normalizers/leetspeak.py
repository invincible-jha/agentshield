"""Leetspeak transliteration normalizer.

Converts leetspeak substitutions back to standard Latin characters.
Leetspeak (also written l33tspeak) replaces letters with visually similar
digits and symbols to bypass keyword-based content filters.

Examples: h4ck → hack, 1337 → leet, h@rm → harm, $ecure → secure.
"""
from __future__ import annotations

import re

# -----------------------------------------------------------------------
# Leetspeak substitution table: leet character → most likely Latin char
# -----------------------------------------------------------------------
# Ordered by specificity — longer replacements take precedence in a
# single-pass substitution.
# -----------------------------------------------------------------------

_LEET_MAP: dict[str, str] = {
    # Digit/symbol → letter substitutions
    "4":  "a",
    "@":  "a",
    "8":  "b",
    "(":  "c",
    "3":  "e",
    "€":  "e",
    "6":  "g",
    "9":  "g",
    "#":  "h",
    "1":  "l",   # '1' most commonly replaces 'l' in leet (l33t)
    "!":  "i",
    "|":  "l",
    "0":  "o",
    "°":  "o",
    "5":  "s",
    "$":  "s",
    "+":  "t",
    "7":  "t",
    "2":  "z",
    "%":  "x",
}

# Characters that are purely leet substitutions and almost never appear
# as literal digits/symbols in normal words
_STRONG_LEET_CHARS: frozenset[str] = frozenset("@$")

# Threshold: fraction of characters that must be leet substitutions for
# the token to be transliterated. Prevents false positives on IP addresses,
# phone numbers, etc.
# Set at 0.25 to catch patterns like h4ck (1/4 = 0.25) and h4rm (1/4 = 0.25)
_LEET_FRACTION_THRESHOLD: float = 0.25


def transliterate_leet(text: str) -> str:
    """Convert leetspeak tokens in text to standard Latin characters.

    Operates token by token. A token is deemed "leetspeak" if the fraction
    of its characters that are leet substitutions meets the threshold, OR if
    it contains a strong leet indicator character (@, $).

    Parameters
    ----------
    text:
        Input string possibly containing leetspeak tokens.

    Returns
    -------
    str
        Text with leetspeak tokens transliterated to standard characters.

    Example
    -------
    ::

        transliterate_leet("h4ck3r")   # -> "hacker"
        transliterate_leet("h@rm")     # -> "harm"
        transliterate_leet("1337")     # -> "leet"
        transliterate_leet("$ecure")   # -> "secure"
    """
    # Tokenize: split on whitespace, preserving positions
    tokens = re.split(r"(\s+)", text)
    result_parts: list[str] = []

    for token in tokens:
        if re.match(r"^\s+$", token):
            result_parts.append(token)
            continue
        result_parts.append(_maybe_transliterate_token(token))

    return "".join(result_parts)


def _maybe_transliterate_token(token: str) -> str:
    """Transliterate a single token if it appears to be leetspeak.

    Parameters
    ----------
    token:
        A whitespace-free token from the input.

    Returns
    -------
    str
        Transliterated token or original if not detected as leetspeak.
    """
    if len(token) < 2:
        return token

    # Strip punctuation from edges for evaluation, but keep for result construction
    stripped = token.strip(".,!?;:\"'()[]{}")

    if not stripped:
        return token

    # Count leet characters in the stripped token
    leet_count = sum(1 for ch in stripped if ch in _LEET_MAP)
    total_chars = len(stripped)

    # Strong leet chars → always transliterate
    has_strong = any(ch in _STRONG_LEET_CHARS for ch in stripped)

    leet_fraction = leet_count / total_chars if total_chars > 0 else 0.0

    if has_strong or leet_fraction >= _LEET_FRACTION_THRESHOLD:
        transliterated = _apply_leet_map(token)
        return transliterated

    return token


def _apply_leet_map(token: str) -> str:
    """Apply the leet substitution map to every character in a token.

    Parameters
    ----------
    token:
        A token to transliterate.

    Returns
    -------
    str
        The token with all known leet characters replaced.
    """
    result: list[str] = []
    for char in token:
        replacement = _LEET_MAP.get(char)
        if replacement is not None:
            result.append(replacement)
        else:
            result.append(char)
    return "".join(result)


def has_leetspeak(text: str) -> bool:
    """Return True if the text contains tokens that appear to be leetspeak.

    Parameters
    ----------
    text:
        Input string to check.

    Returns
    -------
    bool
        True if at least one token is classified as leetspeak.
    """
    tokens = text.split()
    for token in tokens:
        stripped = token.strip(".,!?;:\"'()[]{}")
        if not stripped or len(stripped) < 2:
            continue
        leet_count = sum(1 for ch in stripped if ch in _LEET_MAP)
        total_chars = len(stripped)
        has_strong = any(ch in _STRONG_LEET_CHARS for ch in stripped)
        leet_fraction = leet_count / total_chars if total_chars > 0 else 0.0
        if has_strong or leet_fraction >= _LEET_FRACTION_THRESHOLD:
            return True
    return False
