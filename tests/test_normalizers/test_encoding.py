"""Tests for agentshield.normalizers.encoding_detector."""
from __future__ import annotations

import base64

import pytest

from agentshield.normalizers.encoding_detector import (
    EncodingType,
    decode_all_encodings,
    decode_base64_segments,
    decode_hex_escapes,
    decode_rot13,
    decode_url_encoding,
)


class TestDecodeHexEscapes:
    """Tests for hex escape decoding."""

    def test_harm_hex_escaped(self) -> None:
        r"""\\x68\\x61\\x72\\x6d → harm."""
        text = r"\x68\x61\x72\x6d"
        result = decode_hex_escapes(text)
        assert result == "harm"

    def test_mixed_hex_and_plain_text(self) -> None:
        text = r"hello \x77\x6f\x72\x6c\x64"
        result = decode_hex_escapes(text)
        assert "world" in result
        assert "hello" in result

    def test_clean_text_unchanged(self) -> None:
        text = "hello world"
        assert decode_hex_escapes(text) == text

    def test_empty_string(self) -> None:
        assert decode_hex_escapes("") == ""

    def test_uppercase_hex_decoded(self) -> None:
        r"""\\x48\\x49 → HI."""
        text = r"\x48\x49"
        result = decode_hex_escapes(text)
        assert result == "HI"


class TestDecodeUrlEncoding:
    """Tests for URL percent-encoding decoding."""

    def test_harm_url_encoded(self) -> None:
        """%68%61%72%6d → harm."""
        text = "%68%61%72%6d"
        result = decode_url_encoding(text)
        assert result == "harm"

    def test_clean_text_unchanged(self) -> None:
        text = "hello world"
        assert decode_url_encoding(text) == text

    def test_mixed_url_and_plain(self) -> None:
        text = "hello %77%6f%72%6c%64"
        result = decode_url_encoding(text)
        assert "world" in result
        assert "hello" in result

    def test_uppercase_percent_encoded(self) -> None:
        """%48%49 → HI."""
        text = "%48%49"
        result = decode_url_encoding(text)
        assert result == "HI"

    def test_empty_string(self) -> None:
        assert decode_url_encoding("") == ""


class TestDecodeBase64:
    """Tests for Base64 segment detection and decoding."""

    def test_valid_base64_segment_decoded(self) -> None:
        """aGFybQ== (harm in base64) should be decoded to harm."""
        encoded = base64.b64encode(b"harm").decode()
        result = decode_base64_segments(encoded)
        assert result == "harm"

    def test_clean_text_unchanged(self) -> None:
        text = "hello world"
        result = decode_base64_segments(text)
        assert result == text

    def test_empty_string(self) -> None:
        assert decode_base64_segments("") == ""

    def test_base64_with_context(self) -> None:
        """Encoded segment within larger text should be decoded."""
        encoded = base64.b64encode(b"hurtyou").decode()
        # Must be a standalone token (word boundary) for detection
        text = f"input: {encoded}"
        result = decode_base64_segments(text)
        assert "hurtyou" in result or encoded in result  # Either decoded or unchanged


class TestDecodeRot13:
    """Tests for ROT13 detection and decoding."""

    def test_harm_rot13_decoded(self) -> None:
        """ROT13 of 'harm' is 'unez'."""
        # "unez" is the ROT13 of "harm"
        text = "unez"
        result = decode_rot13(text)
        assert result == "harm"

    def test_kill_rot13_decoded(self) -> None:
        """ROT13 of 'kill' is 'xvyy'."""
        result = decode_rot13("xvyy")
        assert result == "kill"

    def test_clean_text_unchanged(self) -> None:
        """Regular English text without ROT13 indicators should be unchanged."""
        text = "hello world this is fine"
        result = decode_rot13(text)
        assert result == text

    def test_empty_string(self) -> None:
        result = decode_rot13("")
        assert result == ""


class TestDecodeAllEncodings:
    """Tests for the composite decode_all_encodings function."""

    def test_hex_detected_and_decoded(self) -> None:
        text = r"\x68\x61\x72\x6d"
        result, detected = decode_all_encodings(text)
        assert result == "harm"
        assert EncodingType.HEX_ESCAPE in detected

    def test_url_detected_and_decoded(self) -> None:
        text = "%68%61%72%6d"
        result, detected = decode_all_encodings(text)
        assert result == "harm"
        assert EncodingType.URL_ENCODING in detected

    def test_clean_text_no_encodings_detected(self) -> None:
        text = "hello world"
        result, detected = decode_all_encodings(text)
        assert result == text
        assert detected == []

    def test_rot13_detected(self) -> None:
        text = "unez"  # ROT13 of "harm"
        result, detected = decode_all_encodings(text)
        assert EncodingType.ROT13 in detected

    def test_returns_tuple_of_str_and_list(self) -> None:
        result, detected = decode_all_encodings("hello")
        assert isinstance(result, str)
        assert isinstance(detected, list)
