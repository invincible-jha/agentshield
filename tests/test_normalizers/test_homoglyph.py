"""Tests for agentshield.normalizers.homoglyph_map."""
from __future__ import annotations

import pytest

from agentshield.normalizers.homoglyph_map import (
    has_homoglyphs,
    list_homoglyphs,
    normalize_homoglyphs,
)


class TestNormalizeHomoglyphs:
    """Tests for the normalize_homoglyphs function."""

    def test_clean_ascii_unchanged(self) -> None:
        text = "Hello, world!"
        assert normalize_homoglyphs(text) == text

    def test_cyrillic_a_normalized(self) -> None:
        """Cyrillic а (U+0430) → Latin a."""
        text = "\u0430ttack"  # Cyrillic 'а' as first char
        result = normalize_homoglyphs(text)
        assert result == "attack"

    def test_cyrillic_attack_word(self) -> None:
        """'аttаck' with Cyrillic а → 'attack'."""
        # U+0430 for 'а', U+0061 for 'a' (normal)
        text = "\u0430tt\u0430ck"
        result = normalize_homoglyphs(text)
        assert result == "attack"

    def test_full_width_capital_letters(self) -> None:
        """Full-width Ａ (U+FF21) → A."""
        text = "\uff21\uff22\uff23"  # ＡＢＣ
        result = normalize_homoglyphs(text)
        assert result == "ABC"

    def test_full_width_lowercase_letters(self) -> None:
        """Full-width ａ (U+FF41) → a."""
        text = "\uff41\uff42\uff43"  # ａｂｃ
        result = normalize_homoglyphs(text)
        assert result == "abc"

    def test_full_width_hello(self) -> None:
        """Full-width Ｈello → Hello."""
        text = "\uff28ello"  # Full-width H followed by ASCII
        result = normalize_homoglyphs(text)
        assert result == "Hello"

    def test_greek_alpha_normalized(self) -> None:
        """Greek α (U+03B1) → a."""
        text = "\u03b1ttack"
        result = normalize_homoglyphs(text)
        assert result == "attack"

    def test_math_bold_letters(self) -> None:
        """Mathematical Bold Capital A (U+1D400) → A."""
        text = "\U0001D400"  # Mathematical Bold Capital A
        result = normalize_homoglyphs(text)
        assert result == "A"

    def test_cyrillic_o_normalized(self) -> None:
        """Cyrillic о (U+043E) → o."""
        text = "c\u043ede"  # 'c' + Cyrillic о + 'de'
        result = normalize_homoglyphs(text)
        assert result == "code"

    def test_cyrillic_e_normalized(self) -> None:
        """Cyrillic е (U+0435) → e."""
        text = "s\u0435cure"
        result = normalize_homoglyphs(text)
        assert result == "secure"

    def test_cyrillic_p_normalized(self) -> None:
        """Cyrillic р (U+0440) → p."""
        text = "\u0440assword"
        result = normalize_homoglyphs(text)
        assert result == "password"

    def test_empty_string(self) -> None:
        assert normalize_homoglyphs("") == ""

    def test_idempotent(self) -> None:
        """Normalizing twice should produce the same result."""
        text = "\u0430tt\u0430ck"
        once = normalize_homoglyphs(text)
        twice = normalize_homoglyphs(once)
        assert once == twice

    def test_mixed_ascii_and_cyrillic(self) -> None:
        """Mixed ASCII and Cyrillic should normalize only the Cyrillic."""
        text = "real \u0430ttack here"
        result = normalize_homoglyphs(text)
        assert result == "real attack here"


class TestHasHomoglyphs:
    """Tests for the has_homoglyphs detection function."""

    def test_clean_ascii_returns_false(self) -> None:
        assert not has_homoglyphs("Hello, world!")

    def test_cyrillic_a_detected(self) -> None:
        assert has_homoglyphs("\u0430ttack")

    def test_full_width_letter_detected(self) -> None:
        assert has_homoglyphs("\uff21BC")

    def test_empty_string_returns_false(self) -> None:
        assert not has_homoglyphs("")


class TestListHomoglyphs:
    """Tests for the list_homoglyphs inspection function."""

    def test_clean_text_returns_empty(self) -> None:
        assert list_homoglyphs("hello") == []

    def test_returns_position_char_replacement(self) -> None:
        text = "\u0430ttack"
        result = list_homoglyphs(text)
        assert len(result) >= 1
        pos, original, replacement = result[0]
        assert pos == 0
        assert original == "\u0430"
        assert replacement == "a"

    def test_multiple_homoglyphs(self) -> None:
        text = "\u0430tt\u0430ck"
        result = list_homoglyphs(text)
        assert len(result) == 2
