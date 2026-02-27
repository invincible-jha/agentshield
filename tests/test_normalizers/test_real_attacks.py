"""Real-world evasion attack pattern tests.

These tests use patterns documented in public security research on
prompt injection and LLM guardrail evasion. All patterns are sourced
from defensive security literature.

Defensive purpose: verify the normalizer correctly identifies and
canonicalizes known evasion techniques.
"""
from __future__ import annotations

import pytest

from agentshield.normalizers.text_normalizer import TextNormalizer, normalize


class TestSeparatorEvasion:
    """Inter-character separator evasion patterns."""

    def test_dot_separated_safety(self) -> None:
        """S.A.F.E.T.Y bypasses keyword 'safety'."""
        result = normalize("S.A.F.E.T.Y")
        assert result.normalized == "SAFETY"
        assert result.was_modified

    def test_dot_separated_harm(self) -> None:
        """h.a.r.m bypasses keyword 'harm'."""
        result = normalize("h.a.r.m")
        assert result.normalized == "harm"

    def test_hyphen_separated_harm(self) -> None:
        """h-a-r-m bypasses keyword 'harm'."""
        result = normalize("h-a-r-m")
        assert result.normalized == "harm"

    def test_underscore_separated_kill(self) -> None:
        """k_i_l_l bypasses keyword 'kill'."""
        result = normalize("k_i_l_l")
        assert result.normalized == "kill"


class TestHomoglyphEvasion:
    """Unicode homoglyph substitution evasion patterns."""

    def test_cyrillic_substitution_attack(self) -> None:
        """'аttаck' with Cyrillic а looks identical to 'attack'."""
        text = "\u0430tt\u0430ck"
        result = normalize(text)
        assert result.normalized == "attack"

    def test_cyrillic_mixed_harm(self) -> None:
        """Cyrillic о in 'hоrm' (not standard harm, but similar)."""
        # Cyrillic о looks like Latin o
        text = "h\u043erm"
        result = normalize(text)
        # After normalization, Cyrillic о → o
        assert "o" in result.normalized
        assert "\u043e" not in result.normalized

    def test_full_width_latin_obfuscation(self) -> None:
        """Full-width ＨＡＲＭ looks like HARM but bypasses ASCII matching."""
        text = "\uff28\uff21\uff32\uff2d"  # Full-width HARM
        result = normalize(text)
        assert result.normalized == "HARM"


class TestEncodingEvasion:
    """Encoding-based evasion patterns."""

    def test_hex_escape_harm(self) -> None:
        r"""\\x68\\x61\\x72\\x6d encodes 'harm'."""
        result = normalize(r"\x68\x61\x72\x6d")
        assert result.normalized == "harm"

    def test_url_encoded_harm(self) -> None:
        """%68%61%72%6d URL-encodes 'harm'."""
        result = normalize("%68%61%72%6d")
        assert result.normalized == "harm"

    def test_rot13_harm(self) -> None:
        """ROT13('harm') = 'unez' — decoded back."""
        result = normalize("unez")
        assert result.normalized == "harm"

    def test_rot13_kill(self) -> None:
        """ROT13('kill') = 'xvyy'."""
        result = normalize("xvyy")
        assert result.normalized == "kill"


class TestInvisibleCharEvasion:
    """Invisible character injection evasion patterns."""

    def test_zero_width_space_in_safety(self) -> None:
        """Inserting U+200B into 'safety' to bypass keyword match."""
        text = "s\u200bafety"
        result = normalize(text)
        assert result.normalized == "safety"

    def test_rtl_override_evasion(self) -> None:
        """U+202E RTL override used to reverse displayed text."""
        text = "dangerous\u202etext"
        result = normalize(text)
        assert "\u202e" not in result.normalized

    def test_zero_width_joiner_injection(self) -> None:
        """U+200D zero-width joiner between word characters."""
        text = "harm\u200dful"
        result = normalize(text)
        assert result.normalized == "harmful"


class TestLeetSpeakEvasion:
    """Leet-speak substitution evasion patterns."""

    def test_h4ck_leet(self) -> None:
        result = normalize("h4ck")
        assert result.normalized == "hack"

    def test_h4rm_leet(self) -> None:
        """h4rm with digit 4 → harm."""
        result = normalize("h4rm")
        assert result.normalized == "harm"

    def test_harm_at_sign(self) -> None:
        """h@rm → harm."""
        result = normalize("h@rm")
        assert result.normalized == "harm"


class TestCombinedEvasion:
    """Combined evasion techniques."""

    def test_invisible_plus_homoglyph(self) -> None:
        """Zero-width space AND Cyrillic homoglyph in same string."""
        # Cyrillic а + zero-width space + 'ttack'
        text = "\u0430\u200btt\u0430ck"
        result = normalize(text)
        # After normalization: invisible chars stripped, Cyrillic normalized
        assert "\u200b" not in result.normalized
        assert "\u0430" not in result.normalized

    def test_normalizer_is_idempotent_on_complex_input(self) -> None:
        """Complex evasion: applying normalizer twice gives same result."""
        normalizer = TextNormalizer()
        text = "\u0430\u200btt\u0430ck"
        once = normalizer.normalize(text)
        twice = normalizer.normalize(once.normalized)
        assert once.normalized == twice.normalized
