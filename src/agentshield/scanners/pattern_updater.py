"""PatternUpdater — load additional injection detection patterns from YAML files.

This module provides a mechanism to extend the :class:`PatternLibrary` with
custom patterns defined in external YAML files.  This is useful for
domain-specific deployments that need patterns beyond the built-in set
without modifying library source code.

YAML pattern file format::

    patterns:
      - name: custom_pattern_slug
        regex: "(?i)some structural pattern"
        severity: high            # critical | high | medium | low
        description: Human-readable description of the structural signature.
        category: role_override   # see PatternCategory enum values
        confidence: 0.8           # float in [0.0, 1.0]
        source: community         # owasp | academic | community

All fields are required.  The loader validates each entry before constructing
a :class:`CategorizedPattern`.  Invalid entries raise :class:`PatternLoadError`
with a descriptive message.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from agentshield.scanners.pattern_library import (
    CategorizedPattern,
    PatternCategory,
    PatternSource,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})
_DEFAULT_FLAGS = re.IGNORECASE | re.MULTILINE


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PatternLoadError(ValueError):
    """Raised when a YAML pattern file cannot be parsed or contains invalid data.

    Attributes
    ----------
    path:
        The file path that triggered the error, if available.
    """

    def __init__(self, message: str, path: Path | None = None) -> None:
        self.path = path
        super().__init__(
            f"{message}" if path is None else f"{message} (file: {path})"
        )


# ---------------------------------------------------------------------------
# PatternUpdater
# ---------------------------------------------------------------------------


class PatternUpdater:
    """Load :class:`~agentshield.scanners.pattern_library.CategorizedPattern`
    instances from YAML files for runtime extensibility.

    Example
    -------
    ::

        updater = PatternUpdater()
        patterns = updater.load_from_yaml(Path("custom_patterns.yaml"))
        library = PatternLibrary()
        library.add_patterns(patterns)
    """

    def load_from_yaml(self, path: Path) -> list[CategorizedPattern]:
        """Load patterns from a single YAML file at *path*.

        Parameters
        ----------
        path:
            Path to a YAML file following the pattern file format.

        Returns
        -------
        list[CategorizedPattern]
            Validated, compiled patterns ready for use.

        Raises
        ------
        PatternLoadError
            If the file cannot be read, is not valid YAML, or contains
            entries with missing or invalid fields.
        FileNotFoundError
            If *path* does not exist.
        """
        if not path.exists():
            raise FileNotFoundError(f"Pattern file not found: {path}")

        try:
            raw_text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PatternLoadError(
                f"Cannot read pattern file: {exc}", path=path
            ) from exc

        try:
            data = yaml.safe_load(raw_text)
        except yaml.YAMLError as exc:
            raise PatternLoadError(
                f"Invalid YAML in pattern file: {exc}", path=path
            ) from exc

        if not isinstance(data, dict):
            raise PatternLoadError(
                "Pattern file must be a YAML mapping with a 'patterns' key.",
                path=path,
            )

        raw_patterns = data.get("patterns")
        if not isinstance(raw_patterns, list):
            raise PatternLoadError(
                "Pattern file must contain a 'patterns' list.",
                path=path,
            )

        return [self._parse_entry(entry, index, path) for index, entry in enumerate(raw_patterns)]

    def load_from_directory(self, directory: Path) -> list[CategorizedPattern]:
        """Load all YAML pattern files from *directory*.

        Scans *directory* (non-recursively) for files with ``.yaml`` or
        ``.yml`` extensions and loads patterns from each.

        Parameters
        ----------
        directory:
            Path to a directory containing YAML pattern files.

        Returns
        -------
        list[CategorizedPattern]
            Combined list of validated patterns from all files found,
            in filesystem order (sorted by filename for determinism).

        Raises
        ------
        NotADirectoryError
            If *directory* does not exist or is not a directory.
        PatternLoadError
            If any file cannot be parsed.
        """
        if not directory.exists():
            raise NotADirectoryError(f"Pattern directory not found: {directory}")
        if not directory.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {directory}")

        yaml_files = sorted(
            path for path in directory.iterdir()
            if path.suffix.lower() in {".yaml", ".yml"}
        )

        all_patterns: list[CategorizedPattern] = []
        for yaml_path in yaml_files:
            all_patterns.extend(self.load_from_yaml(yaml_path))
        return all_patterns

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_entry(
        self, entry: object, index: int, path: Path
    ) -> CategorizedPattern:
        """Parse and validate a single pattern entry dict.

        Parameters
        ----------
        entry:
            Raw value from the YAML list (should be a dict).
        index:
            Zero-based index in the patterns list (for error messages).
        path:
            Source file path (for error messages).

        Returns
        -------
        CategorizedPattern

        Raises
        ------
        PatternLoadError
            On any validation failure.
        """
        if not isinstance(entry, dict):
            raise PatternLoadError(
                f"Pattern entry at index {index} must be a mapping, "
                f"got {type(entry).__name__}.",
                path=path,
            )

        name = self._require_str(entry, "name", index, path)
        regex_str = self._require_str(entry, "regex", index, path)
        severity = self._require_str(entry, "severity", index, path)
        description = self._require_str(entry, "description", index, path)
        category_str = self._require_str(entry, "category", index, path)
        confidence_raw = entry.get("confidence")
        source_str = self._require_str(entry, "source", index, path)

        # Validate severity.
        if severity not in _VALID_SEVERITIES:
            raise PatternLoadError(
                f"Pattern '{name}' (index {index}) has invalid severity "
                f"'{severity}'. Must be one of: {sorted(_VALID_SEVERITIES)}.",
                path=path,
            )

        # Validate and compile regex.
        try:
            compiled = re.compile(regex_str, _DEFAULT_FLAGS)
        except re.error as exc:
            raise PatternLoadError(
                f"Pattern '{name}' (index {index}) has invalid regex "
                f"'{regex_str}': {exc}.",
                path=path,
            ) from exc

        # Validate category.
        try:
            category = PatternCategory(category_str)
        except ValueError:
            valid_categories = [c.value for c in PatternCategory]
            raise PatternLoadError(
                f"Pattern '{name}' (index {index}) has unknown category "
                f"'{category_str}'. Must be one of: {valid_categories}.",
                path=path,
            ) from None

        # Validate confidence.
        if confidence_raw is None:
            raise PatternLoadError(
                f"Pattern '{name}' (index {index}) is missing required field 'confidence'.",
                path=path,
            )
        if not isinstance(confidence_raw, (int, float)):
            raise PatternLoadError(
                f"Pattern '{name}' (index {index}) confidence must be a number, "
                f"got {type(confidence_raw).__name__}.",
                path=path,
            )
        confidence = float(confidence_raw)
        if not (0.0 <= confidence <= 1.0):
            raise PatternLoadError(
                f"Pattern '{name}' (index {index}) confidence {confidence} "
                "is out of range [0.0, 1.0].",
                path=path,
            )

        # Validate source.
        try:
            source = PatternSource(source_str)
        except ValueError:
            valid_sources = [s.value for s in PatternSource]
            raise PatternLoadError(
                f"Pattern '{name}' (index {index}) has unknown source "
                f"'{source_str}'. Must be one of: {valid_sources}.",
                path=path,
            ) from None

        return CategorizedPattern(
            name=name,
            pattern=compiled,
            severity=severity,
            description=description,
            category=category,
            confidence=confidence,
            source=source,
        )

    @staticmethod
    def _require_str(
        entry: dict[str, object], key: str, index: int, path: Path
    ) -> str:
        """Extract a required string field from *entry*.

        Parameters
        ----------
        entry:
            The mapping to extract from.
        key:
            Field name to look up.
        index:
            Entry index (for error messages).
        path:
            Source file path (for error messages).

        Returns
        -------
        str

        Raises
        ------
        PatternLoadError
            If the field is missing or not a string.
        """
        value = entry.get(key)
        if value is None:
            raise PatternLoadError(
                f"Pattern at index {index} is missing required field '{key}'.",
                path=path,
            )
        if not isinstance(value, str):
            raise PatternLoadError(
                f"Pattern at index {index} field '{key}' must be a string, "
                f"got {type(value).__name__}.",
                path=path,
            )
        return value
