"""Tests for agentshield.normalizers.text_normalizer.

Tests the TextNormalizer pipeline and NormalizeResult.
"""
from __future__ import annotations

import pytest

from agentshield.normalizers.text_normalizer import (
    NormalizeResult,
    TextNormalizer,
    TransformationType,
    normalize,
)


class TestTextNormalizerPipeline:
    """Tests for the full TextNormalizer pipeline."""

    def test_clean_text_unchanged(self) -> None:
        normalizer = TextNormalizer()
        result = normalizer.normalize("Hello, this is safe text.")
        assert result.normalized == "Hello, this is safe text."
        assert not result.was_modified

    def test_separator_stripping_in_pipeline(self) -> None:
        """S.A.F.E.T.Y → SAFETY via pipeline."""
        normalizer = TextNormalizer()
        result = normalizer.normalize("S.A.F.E.T.Y")
        assert result.normalized == "SAFETY"
        assert result.was_modified

    def test_invisible_chars_in_pipeline(self) -> None:
        """Zero-width space stripped via pipeline."""
        normalizer = TextNormalizer()
        result = normalizer.normalize("safe\u200bty")
        assert result.normalized == "safety"
        assert result.was_modified

    def test_homoglyphs_in_pipeline(self) -> None:
        """Cyrillic а → a via pipeline."""
        normalizer = TextNormalizer()
        result = normalizer.normalize("\u0430ttack")
        assert result.normalized == "attack"
        assert result.was_modified

    def test_leetspeak_in_pipeline(self) -> None:
        """h@rm → harm via pipeline."""
        normalizer = TextNormalizer()
        result = normalizer.normalize("h@rm")
        assert result.normalized == "harm"
        assert result.was_modified

    def test_hex_encoding_in_pipeline(self) -> None:
        r"""\\xNN → decoded via pipeline."""
        normalizer = TextNormalizer()
        result = normalizer.normalize(r"\x68\x61\x72\x6d")
        assert result.normalized == "harm"
        assert result.was_modified

    def test_empty_string(self) -> None:
        normalizer = TextNormalizer()
        result = normalizer.normalize("")
        assert result.normalized == ""
        assert not result.was_modified

    def test_was_modified_false_for_clean_input(self) -> None:
        normalizer = TextNormalizer()
        result = normalizer.normalize("regular text")
        assert not result.was_modified

    def test_was_modified_true_for_obfuscated_input(self) -> None:
        normalizer = TextNormalizer()
        result = normalizer.normalize("h-a-r-m")
        assert result.was_modified

    def test_transformations_recorded(self) -> None:
        """When a normalizer fires, it should appear in transformations."""
        normalizer = TextNormalizer()
        result = normalizer.normalize("safe\u200bty")
        assert len(result.transformations) > 0

    def test_transformation_type_recorded_for_invisible(self) -> None:
        normalizer = TextNormalizer()
        result = normalizer.normalize("safe\u200bty")
        types = [t.transformation_type for t in result.transformations]
        assert TransformationType.INVISIBLE_CHARS_STRIPPED in types

    def test_transformation_type_recorded_for_separators(self) -> None:
        normalizer = TextNormalizer()
        result = normalizer.normalize("S.A.F.E.T.Y")
        types = [t.transformation_type for t in result.transformations]
        assert TransformationType.SEPARATORS_STRIPPED in types

    def test_original_preserved_in_result(self) -> None:
        normalizer = TextNormalizer()
        original = "S.A.F.E.T.Y"
        result = normalizer.normalize(original)
        assert result.original == original


class TestTextNormalizerIdempotency:
    """Tests that the normalizer pipeline is idempotent."""

    def test_separator_idempotent(self) -> None:
        normalizer = TextNormalizer()
        text = "S.A.F.E.T.Y"
        once = normalizer.normalize(text)
        twice = normalizer.normalize(once.normalized)
        assert once.normalized == twice.normalized

    def test_invisible_idempotent(self) -> None:
        normalizer = TextNormalizer()
        text = "safe\u200bty"
        once = normalizer.normalize(text)
        twice = normalizer.normalize(once.normalized)
        assert once.normalized == twice.normalized

    def test_homoglyph_idempotent(self) -> None:
        normalizer = TextNormalizer()
        text = "\u0430ttack"
        once = normalizer.normalize(text)
        twice = normalizer.normalize(once.normalized)
        assert once.normalized == twice.normalized

    def test_leet_idempotent(self) -> None:
        normalizer = TextNormalizer()
        text = "h@rm"
        once = normalizer.normalize(text)
        twice = normalizer.normalize(once.normalized)
        assert once.normalized == twice.normalized


class TestTextNormalizerSelective:
    """Tests for selectively disabling normalizers."""

    def test_disable_invisible_chars(self) -> None:
        normalizer = TextNormalizer(enable_invisible_chars=False)
        result = normalizer.normalize("safe\u200bty")
        # Should NOT strip the zero-width space
        assert "\u200b" in result.normalized

    def test_disable_homoglyphs(self) -> None:
        normalizer = TextNormalizer(enable_homoglyphs=False)
        result = normalizer.normalize("\u0430ttack")
        # Should NOT normalize the Cyrillic char
        assert "\u0430" in result.normalized

    def test_disable_separators(self) -> None:
        normalizer = TextNormalizer(enable_separators=False)
        result = normalizer.normalize("S.A.F.E.T.Y")
        # Should NOT strip the separators
        assert result.normalized == "S.A.F.E.T.Y"

    def test_disable_leetspeak(self) -> None:
        normalizer = TextNormalizer(enable_leetspeak=False)
        result = normalizer.normalize("h@rm")
        # Should NOT transliterate
        assert "@" in result.normalized


class TestNormalizeConvenienceFunction:
    """Tests for the normalize() module-level convenience function."""

    def test_returns_normalize_result(self) -> None:
        result = normalize("hello")
        assert isinstance(result, NormalizeResult)

    def test_separator_via_convenience(self) -> None:
        result = normalize("S.A.F.E.T.Y")
        assert result.normalized == "SAFETY"

    def test_clean_text_via_convenience(self) -> None:
        result = normalize("normal text")
        assert not result.was_modified


class TestNormalizeResult:
    """Tests for NormalizeResult dataclass."""

    def test_to_dict_structure(self) -> None:
        result = normalize("S.A.F.E.T.Y")
        data = result.to_dict()
        assert "original" in data
        assert "normalized" in data
        assert "was_modified" in data
        assert "transformations" in data
        assert "encoding_types" in data

    def test_to_dict_original_correct(self) -> None:
        result = normalize("S.A.F.E.T.Y")
        assert result.to_dict()["original"] == "S.A.F.E.T.Y"

    def test_to_dict_normalized_correct(self) -> None:
        result = normalize("S.A.F.E.T.Y")
        assert result.to_dict()["normalized"] == "SAFETY"

    def test_transformation_count_zero_for_clean(self) -> None:
        result = normalize("hello world")
        assert result.transformation_count == 0

    def test_transformation_count_positive_for_modified(self) -> None:
        result = normalize("S.A.F.E.T.Y")
        assert result.transformation_count >= 1
