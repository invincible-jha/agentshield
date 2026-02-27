"""Separator stripping normalizer.

Removes separators inserted between individual characters to obfuscate words.
For example, "S.A.F.E.T.Y" -> "SAFETY" and "h-a-r-m" -> "harm".

Adversarial inputs commonly insert punctuation between letters to prevent
keyword matching while remaining readable to humans.
"""
from __future__ import annotations

import re

# Characters commonly used as inter-character separators in evasion attempts
# These are treated as separators ONLY when they appear between single characters
_SEPARATOR_CHARS: str = r"[.\-_ *\/|,;:!~]"

# Pattern: a single non-space character, followed by one or more separators,
# followed by a single non-space character. Repeat for sequences.
# This handles "S.A.F.E.T.Y" and "h-a-r-m" without collapsing legitimate words.
_SEPARATED_WORD_PATTERN: re.Pattern[str] = re.compile(
    r"(?<![^\s])(\S)" + r"(" + _SEPARATOR_CHARS + r"+" + r"(\S))+",
)

# Pattern that matches a single letter or digit, followed by a separator,
# followed by another single letter or digit (lookahead)
# We use a stateful approach: detect if ALL characters in a token are separated
_INTER_CHAR_PATTERN: re.Pattern[str] = re.compile(
    r"(\b\S)" + r"(?:" + _SEPARATOR_CHARS + r"\S)+"
)


def strip_separators(text: str) -> str:
    """Remove inter-character separators from obfuscated words.

    Detects sequences where individual characters are separated by punctuation
    (e.g., dots, hyphens, underscores) and joins them into a single token.

    Only removes separators when they appear between single non-space characters
    in a sequence of two or more such pairs. This avoids false positives on
    hyphenated words like "well-known" or domain names.

    Parameters
    ----------
    text:
        Input string that may contain separated characters.

    Returns
    -------
    str
        The input with inter-character separators removed from matching patterns.

    Example
    -------
    ::

        strip_separators("S.A.F.E.T.Y")     # -> "SAFETY"
        strip_separators("h-a-r-m")          # -> "harm"
        strip_separators("h_4_c_k")          # -> "h4ck"
        strip_separators("well-known text")  # -> "well-known text" (unchanged)
    """
    return _apply_separator_stripping(text)


def _apply_separator_stripping(text: str) -> str:
    """Internal implementation of separator stripping.

    Scans the text for runs of single-character/separator patterns and
    replaces them with the concatenated characters.

    Parameters
    ----------
    text:
        Input string.

    Returns
    -------
    str
        Text with inter-character separators removed.
    """
    # We process token by token. A token is a whitespace-delimited word.
    # For each token, check if it matches the separated-character pattern.
    tokens = text.split()
    result_tokens: list[str] = []

    for token in tokens:
        stripped = _strip_token(token)
        result_tokens.append(stripped)

    # Reconstruct with original whitespace if possible
    # Simple join for now — preserves token boundaries
    return " ".join(result_tokens)


def _strip_token(token: str) -> str:
    """Strip inter-character separators from a single whitespace-free token.

    A token is treated as an obfuscated sequence if:
    - It contains at least 3 characters
    - Every other character (at even indices when split by separator) is
      a single printable character
    - The separator characters appear between EVERY pair of letters

    Parameters
    ----------
    token:
        A single non-whitespace token.

    Returns
    -------
    str
        The token with separators removed, or the original token unchanged.
    """
    if len(token) < 3:
        return token

    # Check for the pattern: single_char SEP single_char (SEP single_char)*
    # where SEP is one of our separator characters
    separator_re = re.compile(r"^(\S)" + r"(?:[.\-_ *\/|,;:!~]+(\S))+$")
    match = separator_re.match(token)
    if match:
        # Remove all separator characters from the token
        sep_chars_re = re.compile(r"[.\-_ *\/|,;:!~]+")
        # Split by separator runs and rejoin
        parts = sep_chars_re.split(token)
        # Only collapse if all parts are single characters (true inter-char separation)
        if all(len(p) == 1 for p in parts if p):
            return "".join(parts)

    return token


def has_char_separators(text: str) -> bool:
    """Return True if the text contains inter-character separator patterns.

    Parameters
    ----------
    text:
        Input string to check.

    Returns
    -------
    bool
        True if at least one separated-character sequence is detected.
    """
    tokens = text.split()
    sep_re = re.compile(r"^(\S)(?:[.\-_ *\/|,;:!~]+(\S))+$")
    for token in tokens:
        if len(token) >= 3:
            match = sep_re.match(token)
            if match:
                sep_chars_re = re.compile(r"[.\-_ *\/|,;:!~]+")
                parts = sep_chars_re.split(token)
                if all(len(p) == 1 for p in parts if p):
                    return True
    return False
