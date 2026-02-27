"""Tests for agentshield.normalizers.invisible_chars."""
from __future__ import annotations

import pytest

from agentshield.normalizers.invisible_chars import (
    has_invisible_chars,
    list_invisible_chars,
    strip_invisible,
)


class TestStripInvisible:
    """Tests for the strip_invisible function."""

    def test_clean_text_unchanged(self) -> None:
        text = "Hello, world!"
        assert strip_invisible(text) == text

    def test_zero_width_space_stripped(self) -> None:
        """U+200B ZERO WIDTH SPACE should be removed."""
        text = "safe\u200bty"
        result = strip_invisible(text)
        assert result == "safety"

    def test_zero_width_joiner_stripped(self) -> None:
        """U+200D ZERO WIDTH JOINER should be removed."""
        text = "harm\u200dful"
        result = strip_invisible(text)
        assert result == "harmful"

    def test_rtl_override_stripped(self) -> None:
        """U+202E RIGHT-TO-LEFT OVERRIDE should be removed."""
        text = "safe\u202etext"
        result = strip_invisible(text)
        assert result == "safetext"

    def test_soft_hyphen_stripped(self) -> None:
        """U+00AD SOFT HYPHEN should be removed."""
        text = "dan\u00adger"
        result = strip_invisible(text)
        assert result == "danger"

    def test_bom_stripped(self) -> None:
        """U+FEFF BOM should be removed."""
        text = "\ufeffdanger"
        result = strip_invisible(text)
        assert result == "danger"

    def test_multiple_invisible_chars_all_stripped(self) -> None:
        text = "\u200bharm\u200d\u202e"
        result = strip_invisible(text)
        assert result == "harm"

    def test_empty_string(self) -> None:
        assert strip_invisible("") == ""

    def test_zero_width_non_joiner_stripped(self) -> None:
        """U+200C ZERO WIDTH NON-JOINER."""
        text = "a\u200cb"
        result = strip_invisible(text)
        assert result == "ab"

    def test_left_to_right_mark_stripped(self) -> None:
        """U+200E LEFT-TO-RIGHT MARK."""
        text = "text\u200ehere"
        result = strip_invisible(text)
        assert result == "texthere"

    def test_word_joiner_stripped(self) -> None:
        """U+2060 WORD JOINER."""
        text = "word\u2060joined"
        result = strip_invisible(text)
        assert result == "wordjoined"

    def test_idempotent(self) -> None:
        """Applying strip_invisible twice should produce the same result."""
        text = "harm\u200bful"
        once = strip_invisible(text)
        twice = strip_invisible(once)
        assert once == twice


class TestHasInvisibleChars:
    """Tests for the has_invisible_chars detection function."""

    def test_clean_text_returns_false(self) -> None:
        assert not has_invisible_chars("Hello, world!")

    def test_zero_width_space_detected(self) -> None:
        assert has_invisible_chars("safe\u200bty")

    def test_rtl_override_detected(self) -> None:
        assert has_invisible_chars("text\u202ehere")

    def test_empty_string_returns_false(self) -> None:
        assert not has_invisible_chars("")


class TestListInvisibleChars:
    """Tests for the list_invisible_chars inspection function."""

    def test_clean_text_returns_empty(self) -> None:
        result = list_invisible_chars("Hello")
        assert result == []

    def test_returns_position_and_char(self) -> None:
        text = "a\u200bb"
        result = list_invisible_chars(text)
        assert len(result) == 1
        position, char = result[0]
        assert position == 1
        assert char == "\u200b"

    def test_multiple_invisible_chars(self) -> None:
        text = "\u200bab\u202e"
        result = list_invisible_chars(text)
        assert len(result) == 2
