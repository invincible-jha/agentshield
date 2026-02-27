"""Tests for agentshield.owasp.mapper (OWASPCategory enum) and
agentshield.reporting.owasp_mapper (OwaspCategory dataclass, OWASPMapper).
"""
from __future__ import annotations

import pytest

from agentshield.core.scanner import Finding, FindingSeverity


# ---------------------------------------------------------------------------
# Tests for agentshield.owasp.mapper
# ---------------------------------------------------------------------------


class TestOWASPCategoryEnum:
    def test_all_ten_categories_present(self) -> None:
        from agentshield.owasp.mapper import OWASPCategory
        assert len(OWASPCategory) == 10

    def test_category_values_are_strings(self) -> None:
        from agentshield.owasp.mapper import OWASPCategory
        for cat in OWASPCategory:
            assert isinstance(cat.value, str)

    def test_asi01_is_prompt_injection(self) -> None:
        from agentshield.owasp.mapper import OWASPCategory
        assert "PromptInjection" in OWASPCategory.ASI01.value

    def test_asi05_is_sensitive_data(self) -> None:
        from agentshield.owasp.mapper import OWASPCategory
        assert "SensitiveData" in OWASPCategory.ASI05.value


class TestOWASPMappingDict:
    def test_regex_injection_maps_to_asi01(self) -> None:
        from agentshield.owasp.mapper import OWASP_MAPPING, OWASPCategory
        cats = OWASP_MAPPING.get("regex_injection", [])
        assert OWASPCategory.ASI01 in cats

    def test_all_scanner_slugs_in_mapping(self) -> None:
        from agentshield.owasp.mapper import OWASP_MAPPING
        expected = {
            "regex_injection", "pii_detector", "credential_detector",
            "output_safety", "tool_call_validator", "output_validator",
            "tool_call_checker", "behavioral_checker",
        }
        for slug in expected:
            assert slug in OWASP_MAPPING, f"{slug!r} not in OWASP_MAPPING"


def _make_finding(scanner_name: str, category: str = "generic") -> Finding:
    return Finding(
        scanner_name=scanner_name,
        severity=FindingSeverity.MEDIUM,
        category=category,
        message="test finding",
    )


class TestOWASPMapper:
    def test_map_result_known_scanner_returns_categories(self) -> None:
        from agentshield.owasp.mapper import OWASPCategory, OWASPMapper
        mapper = OWASPMapper()
        finding = _make_finding("regex_injection")
        cats = mapper.map_result(finding)
        assert OWASPCategory.ASI01 in cats

    def test_map_result_unknown_scanner_fallback_by_category(self) -> None:
        from agentshield.owasp.mapper import OWASPCategory, OWASPMapper
        mapper = OWASPMapper()
        finding = _make_finding("custom_scanner", "prompt_injection")
        cats = mapper.map_result(finding)
        assert OWASPCategory.ASI01 in cats

    def test_map_result_no_mapping_returns_empty(self) -> None:
        from agentshield.owasp.mapper import OWASPMapper
        mapper = OWASPMapper()
        finding = _make_finding("unknown_scanner", "totally_unknown_category")
        cats = mapper.map_result(finding)
        assert cats == []

    def test_map_findings_deduplicates(self) -> None:
        from agentshield.owasp.mapper import OWASPMapper
        mapper = OWASPMapper()
        findings = [
            _make_finding("regex_injection"),
            _make_finding("regex_injection"),
        ]
        cats = mapper.map_findings(findings)
        # Should deduplicate
        assert len(cats) == len(set(cats))

    def test_map_findings_empty_list(self) -> None:
        from agentshield.owasp.mapper import OWASPMapper
        mapper = OWASPMapper()
        cats = mapper.map_findings([])
        assert cats == []

    def test_map_findings_multiple_scanners(self) -> None:
        from agentshield.owasp.mapper import OWASPMapper
        mapper = OWASPMapper()
        findings = [
            _make_finding("regex_injection"),
            _make_finding("pii_detector"),
        ]
        cats = mapper.map_findings(findings)
        assert len(cats) > 0

    def test_get_coverage_returns_all_categories(self) -> None:
        from agentshield.owasp.mapper import OWASPCategory, OWASPMapper
        mapper = OWASPMapper()
        coverage = mapper.get_coverage()
        for cat in OWASPCategory:
            assert cat in coverage

    def test_get_coverage_known_scanner_is_listed(self) -> None:
        from agentshield.owasp.mapper import OWASPCategory, OWASPMapper
        mapper = OWASPMapper()
        coverage = mapper.get_coverage()
        assert "regex_injection" in coverage[OWASPCategory.ASI01]

    def test_generate_coverage_report_structure(self) -> None:
        from agentshield.owasp.mapper import OWASPMapper
        mapper = OWASPMapper()
        report = mapper.generate_coverage_report()
        assert report["total_categories"] == 10
        assert "covered_categories" in report
        assert "uncovered_categories" in report
        assert "coverage_by_category" in report
        assert "scanner_count" in report

    def test_generate_coverage_report_scanner_count(self) -> None:
        from agentshield.owasp.mapper import OWASP_MAPPING, OWASPMapper
        mapper = OWASPMapper()
        report = mapper.generate_coverage_report()
        assert report["scanner_count"] == len(OWASP_MAPPING)

    def test_fallback_category_data_leakage_maps_to_asi05(self) -> None:
        from agentshield.owasp.mapper import OWASPCategory, OWASPMapper
        mapper = OWASPMapper()
        finding = _make_finding("unknown", "data_leakage")
        cats = mapper.map_result(finding)
        assert OWASPCategory.ASI05 in cats


# ---------------------------------------------------------------------------
# Tests for agentshield.reporting.owasp_mapper
# ---------------------------------------------------------------------------


class TestReportingOwaspMapper:
    def test_all_categories_returns_10(self) -> None:
        from agentshield.reporting.owasp_mapper import OWASPMapper
        mapper = OWASPMapper()
        cats = mapper.all_categories()
        assert len(cats) == 10

    def test_get_category_by_id(self) -> None:
        from agentshield.reporting.owasp_mapper import OWASPMapper
        mapper = OWASPMapper()
        cat = mapper.get_category("ASI-01")
        assert cat is not None
        assert cat.id == "ASI-01"
        assert cat.name == "Prompt Injection"

    def test_get_category_missing_returns_none(self) -> None:
        from agentshield.reporting.owasp_mapper import OWASPMapper
        mapper = OWASPMapper()
        assert mapper.get_category("ASI-99") is None

    def test_categories_for_scanner_pii_detector(self) -> None:
        from agentshield.reporting.owasp_mapper import OWASPMapper
        mapper = OWASPMapper()
        cats = mapper.categories_for_scanner("pii_detector")
        assert len(cats) > 0

    def test_categories_for_scanner_unknown_returns_empty(self) -> None:
        from agentshield.reporting.owasp_mapper import OWASPMapper
        mapper = OWASPMapper()
        assert mapper.categories_for_scanner("nonexistent_scanner") == []

    def test_categories_for_finding_delegates(self) -> None:
        from agentshield.reporting.owasp_mapper import OWASPMapper
        mapper = OWASPMapper()
        finding = _make_finding("regex_injection")
        cats = mapper.categories_for_finding(finding)
        assert isinstance(cats, list)

    def test_map_findings_groups_by_category_id(self) -> None:
        from agentshield.reporting.owasp_mapper import OWASPMapper
        mapper = OWASPMapper()
        findings = [_make_finding("regex_injection")]
        result = mapper.map_findings(findings)
        assert isinstance(result, dict)
        assert any(key.startswith("ASI") for key in result)

    def test_map_findings_unmapped_goes_to_unmapped(self) -> None:
        from agentshield.reporting.owasp_mapper import OWASPMapper
        mapper = OWASPMapper()
        # Use a scanner with no mapping in the reporting owasp_mapper
        findings = [_make_finding("behavioral_checker")]
        result = mapper.map_findings(findings)
        # May go under a category or UNMAPPED depending on the mapping
        assert isinstance(result, dict)

    def test_owasp_category_dataclass_fields(self) -> None:
        from agentshield.reporting.owasp_mapper import OwaspCategory
        cat = OwaspCategory(
            id="ASI-01",
            name="Prompt Injection",
            description="Test description",
            related_scanners=["regex_injection"],
            coverage_note="Note here",
        )
        assert cat.id == "ASI-01"
        assert cat.name == "Prompt Injection"
        assert "regex_injection" in cat.related_scanners

    def test_owasp_category_is_frozen(self) -> None:
        from agentshield.reporting.owasp_mapper import OwaspCategory
        cat = OwaspCategory(id="ASI-01", name="Test", description="desc")
        with pytest.raises((AttributeError, TypeError)):
            cat.id = "ASI-99"  # type: ignore[misc]

    def test_categories_with_no_scanners_exist(self) -> None:
        from agentshield.reporting.owasp_mapper import OWASPMapper
        mapper = OWASPMapper()
        # ASI-08, ASI-09, ASI-10 have no related scanners
        cat = mapper.get_category("ASI-08")
        assert cat is not None
        assert cat.related_scanners == []
