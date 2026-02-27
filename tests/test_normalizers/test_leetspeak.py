"""Tests for agentshield.normalizers.leetspeak."""
from __future__ import annotations

import pytest

from agentshield.normalizers.leetspeak import has_leetspeak, transliterate_leet


class TestTransliterateLeet:
    """Tests for the transliterate_leet function."""

    def test_h4ck_transliterated(self) -> None:
        """h4ck → hack."""
        result = transliterate_leet("h4ck")
        assert result == "hack"

    def test_harm_at_sign(self) -> None:
        """h@rm → harm."""
        result = transliterate_leet("h@rm")
        assert result == "harm"

    def test_secure_dollar(self) -> None:
        """$ecure → secure."""
        result = transliterate_leet("$ecure")
        assert result == "secure"

    def test_1337_transliterated(self) -> None:
        """1337 → leet (all digits)."""
        result = transliterate_leet("1337")
        assert result == "leet"

    def test_h4ck3r_transliterated(self) -> None:
        """h4ck3r → hacker."""
        result = transliterate_leet("h4ck3r")
        assert result == "hacker"

    def test_clean_word_unchanged(self) -> None:
        """Normal words should not be modified."""
        result = transliterate_leet("hello")
        assert result == "hello"

    def test_empty_string(self) -> None:
        assert transliterate_leet("") == ""

    def test_sentence_with_leet_token(self) -> None:
        """Only leet tokens in a sentence should be transliterated."""
        result = transliterate_leet("I will h@rm you")
        assert "harm" in result
        assert "will" in result

    def test_idempotent(self) -> None:
        """Transliterating twice should produce the same result."""
        text = "h4ck3r"
        once = transliterate_leet(text)
        twice = transliterate_leet(once)
        assert once == twice

    def test_single_char_unchanged(self) -> None:
        """Single character tokens are too short to classify as leet."""
        assert transliterate_leet("a") == "a"
        assert transliterate_leet("4") == "4"


class TestHasLeetspeak:
    """Tests for the has_leetspeak detection function."""

    def test_h4ck_detected(self) -> None:
        assert has_leetspeak("h4ck")

    def test_harm_at_detected(self) -> None:
        assert has_leetspeak("h@rm")

    def test_clean_text_not_detected(self) -> None:
        assert not has_leetspeak("hello world this is fine")

    def test_empty_string_not_detected(self) -> None:
        assert not has_leetspeak("")

    def test_secure_dollar_detected(self) -> None:
        assert has_leetspeak("$ecure")
