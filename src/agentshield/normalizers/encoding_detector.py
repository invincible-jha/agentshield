"""Encoding detection and decoding normalizer.

Detects and decodes common encoding schemes used to obfuscate malicious
content: Base64, ROT13, hex escape sequences, and URL encoding.

Defensive purpose: normalize encoded content so that downstream scanners
can inspect the actual plaintext rather than the encoded form.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass
from enum import Enum


class EncodingType(str, Enum):
    """The type of encoding detected in a text segment."""

    BASE64 = "base64"
    ROT13 = "rot13"
    HEX_ESCAPE = "hex_escape"
    URL_ENCODING = "url_encoding"


@dataclass(frozen=True)
class DecodedSegment:
    """A decoded segment found within the input text.

    Parameters
    ----------
    encoding_type:
        The encoding scheme that was detected.
    original:
        The encoded string as it appeared in the input.
    decoded:
        The decoded plaintext.
    start:
        Start position in the original text.
    end:
        End position in the original text (exclusive).
    """

    encoding_type: EncodingType
    original: str
    decoded: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# Hex escape decoding
# ---------------------------------------------------------------------------

# Matches \xNN hex escapes (C-style)
_HEX_ESCAPE_PATTERN: re.Pattern[str] = re.compile(
    r"(?:\\x[0-9a-fA-F]{2})+"
)

# Matches %NN URL-percent-encoded sequences
_URL_PERCENT_PATTERN: re.Pattern[str] = re.compile(
    r"(?:%[0-9a-fA-F]{2})+"
)

# Matches 0xNN hex literal sequences (space-separated)
_HEX_LITERAL_PATTERN: re.Pattern[str] = re.compile(
    r"(?:0x[0-9a-fA-F]{2}\s*)+"
)


def decode_hex_escapes(text: str) -> str:
    """Decode C-style hex escape sequences in text.

    Replaces all ``\\xNN`` sequences with the corresponding character.
    Non-hex or non-printable results are kept as-is.

    Parameters
    ----------
    text:
        Input string possibly containing hex escape sequences.

    Returns
    -------
    str
        Text with hex escapes replaced by their decoded characters.

    Example
    -------
    ::

        decode_hex_escapes("\\x68\\x61\\x72\\x6d")  # -> "harm"
    """
    def replace_hex(match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            # Remove \x prefixes and decode bytes
            hex_str = raw.replace("\\x", "").replace(" ", "")
            decoded_bytes = bytes.fromhex(hex_str)
            return decoded_bytes.decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            return raw

    return _HEX_ESCAPE_PATTERN.sub(replace_hex, text)


def decode_url_encoding(text: str) -> str:
    """Decode URL percent-encoded sequences in text.

    Replaces all ``%NN`` sequences with the corresponding character.

    Parameters
    ----------
    text:
        Input string possibly containing URL-encoded sequences.

    Returns
    -------
    str
        Text with percent-encoding replaced by decoded characters.

    Example
    -------
    ::

        decode_url_encoding("%68%61%72%6d")  # -> "harm"
    """
    def replace_url(match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            return urllib.parse.unquote(raw, encoding="utf-8", errors="replace")
        except Exception:
            return raw

    return _URL_PERCENT_PATTERN.sub(replace_url, text)


# ---------------------------------------------------------------------------
# Base64 detection and decoding
# ---------------------------------------------------------------------------

# Base64 tokens: at least 6 chars of the base64 alphabet, optionally with padding.
# 6 base64 chars = 4 decoded bytes, which covers the smallest meaningful payload
# (e.g. "harm" = 4 bytes = "aGFybQ==").
# Must be preceded/followed by non-base64 chars (or start/end of string).
# We exclude = from the negative lookahead so that padding does not block the match.
_BASE64_PATTERN: re.Pattern[str] = re.compile(
    r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{6,}={0,2})(?![A-Za-z0-9+/])"
)

# Base64 URL-safe tokens
_BASE64URL_PATTERN: re.Pattern[str] = re.compile(
    r"(?<![A-Za-z0-9_\-])([A-Za-z0-9_\-]{6,}={0,2})(?![A-Za-z0-9_\-])"
)


def _is_valid_base64(token: str) -> bool:
    """Return True if token is valid base64-encoded content.

    Validates that the token decodes to valid bytes and that the UTF-8
    interpretation does not contain replacement characters.  The UTF-8
    replacement character U+FFFD indicates that the raw bytes are not
    valid UTF-8, which is the hallmark of English words misidentified as
    base64 (they decode to high-byte sequences that are invalid UTF-8).
    """
    padded = token + "=" * ((4 - len(token) % 4) % 4)
    if len(padded) % 4 != 0:
        return False
    try:
        decoded = base64.b64decode(padded, validate=True)
        decoded_str = decoded.decode("utf-8", errors="replace")
        # Reject tokens whose decoded bytes are not valid UTF-8
        if "\ufffd" in decoded_str:
            return False
        return True
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False


def _decode_base64_token(token: str) -> str | None:
    """Attempt to decode a base64 token.

    Returns the decoded string or None if decoding fails or the decoded
    bytes contain UTF-8 replacement characters (indicating a false positive).
    """
    padded = token + "=" * ((4 - len(token) % 4) % 4)
    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded = decoded_bytes.decode("utf-8", errors="replace")
        if "\ufffd" in decoded:
            return None
        return decoded
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def decode_base64_segments(text: str) -> str:
    """Detect and decode Base64-encoded segments in text.

    Scans for tokens matching the base64 alphabet and attempts to decode
    them. Only replaces tokens that successfully decode to printable UTF-8
    text without replacement characters (to avoid false positives on
    English words that happen to match the base64 character set).

    Parameters
    ----------
    text:
        Input string possibly containing base64 tokens.

    Returns
    -------
    str
        Text with valid base64 segments replaced by their decoded content.

    Example
    -------
    ::

        decode_base64_segments("aGFybQ==")  # "harm" in base64 -> "harm"
    """
    def replace_if_valid(match: re.Match[str]) -> str:
        token = match.group(1)
        if not _is_valid_base64(token):
            return match.group(0)
        decoded = _decode_base64_token(token)
        if decoded is None:
            return match.group(0)
        # Only substitute if the decoded content is all printable characters
        printable_ratio = sum(
            1 for ch in decoded if ch.isprintable()
        ) / max(len(decoded), 1)
        if printable_ratio >= 0.8:
            return decoded
        return match.group(0)

    return _BASE64_PATTERN.sub(replace_if_valid, text)


# ---------------------------------------------------------------------------
# ROT13 detection and decoding
# ---------------------------------------------------------------------------

_ROT13_INDICATOR_WORDS: frozenset[str] = frozenset(
    [
        # Common harmful words that, when ROT13-encoded, appear as recognizable tokens
        "unez",   # harm
        "xvyy",   # kill
        "nggnpx",  # attack
        "pbqr",   # code
        "unxre",  # hacker (ROT13)
        "rkcybvg",  # exploit
        "cnlybna",  # payload
        "vawrpg",  # inject
        "vafgehpgvbaf",  # instructions
        "vaurevg",  # inherit
        "hfre",   # user
        "cnffjbeq",  # password
        "frpher",  # secure
        "qnatre",  # danger
        "jrncba",  # weapon
        "qrngu",  # death
    ]
)

_ROT13_TABLE: dict[int, int] = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def decode_rot13(text: str) -> str:
    """Decode ROT13-encoded text.

    ROT13 is detectable heuristically: if the decoded output contains
    known indicator words, the text is likely ROT13-encoded.

    Parameters
    ----------
    text:
        Input string possibly ROT13-encoded.

    Returns
    -------
    str
        The decoded text if ROT13 indicators are detected; original otherwise.

    Example
    -------
    ::

        decode_rot13("unez")  # -> "harm"
        decode_rot13("hello")  # -> "hello" (no ROT13 indicators)
    """
    decoded = text.translate(_ROT13_TABLE)
    # Check if the original or decoded text contains indicator words
    original_words = set(text.lower().split())
    decoded_words = set(decoded.lower().split())

    if original_words & _ROT13_INDICATOR_WORDS:
        return decoded
    return text


def decode_all_encodings(text: str) -> tuple[str, list[EncodingType]]:
    """Apply all encoding decoders in sequence and return the result.

    Applies decoders in this order:
    1. Invisible character removal (delegated — call separately)
    2. Hex escapes (\\xNN)
    3. URL percent encoding (%NN)
    4. ROT13 detection
    5. Base64 segment detection

    Parameters
    ----------
    text:
        Input string to decode.

    Returns
    -------
    tuple[str, list[EncodingType]]
        The decoded text and a list of encoding types that were detected
        and applied.
    """
    detected: list[EncodingType] = []
    current = text

    # Hex escapes
    after_hex = decode_hex_escapes(current)
    if after_hex != current:
        detected.append(EncodingType.HEX_ESCAPE)
        current = after_hex

    # URL encoding
    after_url = decode_url_encoding(current)
    if after_url != current:
        detected.append(EncodingType.URL_ENCODING)
        current = after_url

    # ROT13 — word-level check
    after_rot13 = decode_rot13(current)
    if after_rot13 != current:
        detected.append(EncodingType.ROT13)
        current = after_rot13

    # Base64 — segment-level check
    after_b64 = decode_base64_segments(current)
    if after_b64 != current:
        detected.append(EncodingType.BASE64)
        current = after_b64

    return current, detected
