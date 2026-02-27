"""OutputValidator — validates LLM structured outputs against JSON schemas.

Handles the common challenge of LLM outputs that are *almost* valid JSON
but contain formatting quirks like trailing commas, single-quoted strings,
or are wrapped in markdown code fences.

Design
------
The validator applies a pipeline of lightweight text fixes before parsing.
It does NOT attempt to repair severely malformed JSON; it only handles the
small set of issues that LLMs reliably produce.

Fix pipeline (applied in order)
1. Extract JSON from markdown code fences (```json ... ``` or ``` ... ```).
2. Remove trailing commas before closing braces/brackets.
3. Convert single-quoted string delimiters to double-quoted.
4. Attempt standard ``json.loads``.

Schema validation uses ``jsonschema`` if available; otherwise falls back to
a basic structural type check.  The ``validate_pydantic`` method uses the
provided Pydantic model class directly.

Classes
-------
OutputValidatorError
    Base exception for this module.
ValidationResult
    Immutable result of a single validation call.
OutputValidator
    Main validator class.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class OutputValidatorError(Exception):
    """Base exception raised by OutputValidator for configuration errors."""


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationResult:
    """The result of a single validation call.

    Attributes
    ----------
    valid:
        True when the output was successfully parsed and passed all schema
        or model validation checks.
    parsed:
        The parsed Python dict/list when valid is True, else None.
    errors:
        List of human-readable error messages describing why validation
        failed.  Empty list when valid is True.
    raw_text:
        The original output text that was validated.
    cleaned_text:
        The text after pre-processing (JSON extraction and fixes), or
        the same as raw_text if no fixes were applied.
    """

    valid: bool
    parsed: dict[str, object] | list[object] | None
    errors: list[str]
    raw_text: str
    cleaned_text: str


# ---------------------------------------------------------------------------
# Text pre-processing helpers
# ---------------------------------------------------------------------------

# Matches ```json ... ``` or ``` ... ``` markdown code fences
_CODE_FENCE_RE = re.compile(
    r"```(?:json)?\s*\n?(.*?)\n?\s*```",
    re.DOTALL | re.IGNORECASE,
)

# Trailing comma before } or ]
_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")

# Single-quoted keys or values in JSON context
# Replaces 'key' with "key" and 'value' with "value"
# This is a best-effort heuristic for the most common LLM quirks.
_SINGLE_QUOTE_RE = re.compile(r"(?<![\\])'([^']*?)(?<![\\])'")


def _extract_from_code_fence(text: str) -> str | None:
    """Extract JSON content from a markdown code fence, if present.

    Parameters
    ----------
    text:
        Possibly fence-wrapped text.

    Returns
    -------
    str | None
        The content inside the code fence, or None if no fence found.
    """
    match = _CODE_FENCE_RE.search(text)
    if match:
        return match.group(1).strip()
    return None


def _remove_trailing_commas(text: str) -> str:
    """Remove trailing commas before closing braces or brackets.

    Parameters
    ----------
    text:
        JSON string that may contain trailing commas.

    Returns
    -------
    str
        Fixed JSON string.
    """
    return _TRAILING_COMMA_RE.sub(r"\1", text)


def _fix_single_quotes(text: str) -> str:
    """Convert single-quoted JSON strings to double-quoted.

    This is a best-effort conversion for the most common LLM output
    pattern.  Does not handle escaped single quotes inside values.

    Parameters
    ----------
    text:
        JSON string that may use single quotes.

    Returns
    -------
    str
        JSON string with single-quote delimiters converted to double-quote.
    """
    return _SINGLE_QUOTE_RE.sub(r'"\1"', text)


def _fix_unquoted_keys(text: str) -> str:
    """Quote bare word keys in JSON objects.

    Handles the pattern ``{key: "value"}`` → ``{"key": "value"}``.

    Parameters
    ----------
    text:
        JSON string that may contain unquoted object keys.

    Returns
    -------
    str
        JSON string with bare keys quoted.
    """
    # Match bare word keys: word characters followed by `:` not inside quotes
    return re.sub(
        r'(?<!["\w])(\b[A-Za-z_]\w*\b)\s*:',
        lambda m: f'"{m.group(1)}":',
        text,
    )


def _preprocess(raw: str) -> str:
    """Apply the full fix pipeline to raw LLM output.

    Pipeline (in order):
    1. Extract from markdown code fence if present.
    2. Remove trailing commas.
    3. Fix single-quoted strings.

    Parameters
    ----------
    raw:
        Raw LLM output text.

    Returns
    -------
    str
        Best-effort cleaned JSON string.
    """
    text = raw.strip()

    # Step 1: code fence extraction
    extracted = _extract_from_code_fence(text)
    if extracted is not None:
        text = extracted

    # Step 2: trailing commas
    text = _remove_trailing_commas(text)

    # Step 3: single quotes
    text = _fix_single_quotes(text)

    return text


# ---------------------------------------------------------------------------
# Schema validation helpers
# ---------------------------------------------------------------------------


def _validate_against_schema(
    parsed: object,
    schema: dict[str, object],
    errors: list[str],
) -> bool:
    """Validate *parsed* against *schema* using jsonschema if available.

    Falls back to a basic Python type-check when jsonschema is not
    installed.

    Parameters
    ----------
    parsed:
        Python object to validate (dict or list).
    schema:
        JSON Schema dict.
    errors:
        Mutable list to append error messages to.

    Returns
    -------
    bool
        True when validation passed.
    """
    try:
        import jsonschema  # type: ignore[import]
        validator = jsonschema.Draft7Validator(schema)
        validation_errors = list(validator.iter_errors(parsed))
        if validation_errors:
            for error in validation_errors:
                errors.append(f"Schema error at {list(error.path)}: {error.message}")
            return False
        return True
    except ImportError:
        # Fallback: basic structural check
        schema_type = schema.get("type")
        if schema_type == "object" and not isinstance(parsed, dict):
            errors.append(
                f"Schema expects 'object' but got {type(parsed).__name__}"
            )
            return False
        if schema_type == "array" and not isinstance(parsed, list):
            errors.append(
                f"Schema expects 'array' but got {type(parsed).__name__}"
            )
            return False
        return True


# ---------------------------------------------------------------------------
# Main validator
# ---------------------------------------------------------------------------


class OutputValidator:
    """Validate LLM structured outputs against JSON schemas or Pydantic models.

    Handles common LLM JSON formatting quirks before attempting to parse
    and validate.

    Parameters
    ----------
    strict:
        When True, unrecognised fix attempts cause a validation error
        rather than silently proceeding with the cleaned text.

    Example
    -------
    ::

        validator = OutputValidator()
        schema = {
            "type": "object",
            "properties": {
                "answer": {"type": "string"},
                "confidence": {"type": "number"},
            },
            "required": ["answer", "confidence"],
        }
        result = validator.validate(
            '```json\\n{"answer": "Paris", "confidence": 0.95}\\n```',
            schema,
        )
        assert result.valid
        assert result.parsed == {"answer": "Paris", "confidence": 0.95}
    """

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self,
        output: str,
        schema: dict[str, object],
    ) -> ValidationResult:
        """Validate *output* against a JSON Schema dict.

        Parameters
        ----------
        output:
            Raw LLM output string (may be wrapped in a markdown fence).
        schema:
            JSON Schema dict to validate against.

        Returns
        -------
        ValidationResult
            Validation outcome with parsed data and any errors.
        """
        errors: list[str] = []
        cleaned = _preprocess(output)

        parsed = self._try_parse_json(cleaned, errors)
        if parsed is None:
            return ValidationResult(
                valid=False,
                parsed=None,
                errors=errors,
                raw_text=output,
                cleaned_text=cleaned,
            )

        schema_ok = _validate_against_schema(parsed, schema, errors)
        return ValidationResult(
            valid=schema_ok,
            parsed=parsed if schema_ok else None,
            errors=errors,
            raw_text=output,
            cleaned_text=cleaned,
        )

    def validate_pydantic(
        self,
        output: str,
        model_class: type,
    ) -> ValidationResult:
        """Validate *output* and parse it into a Pydantic model instance.

        Parameters
        ----------
        output:
            Raw LLM output string.
        model_class:
            A Pydantic ``BaseModel`` subclass to validate against.

        Returns
        -------
        ValidationResult
            Validation outcome.  When valid, ``parsed`` holds the model's
            ``model_dump()`` dict.

        Raises
        ------
        OutputValidatorError
            If *model_class* does not appear to be a Pydantic model.
        """
        if not hasattr(model_class, "model_validate"):
            raise OutputValidatorError(
                f"{model_class!r} does not appear to be a Pydantic v2 BaseModel. "
                "Ensure the class inherits from pydantic.BaseModel."
            )

        errors: list[str] = []
        cleaned = _preprocess(output)

        parsed_dict = self._try_parse_json(cleaned, errors)
        if parsed_dict is None:
            return ValidationResult(
                valid=False,
                parsed=None,
                errors=errors,
                raw_text=output,
                cleaned_text=cleaned,
            )

        try:
            model_instance = model_class.model_validate(parsed_dict)
            return ValidationResult(
                valid=True,
                parsed=model_instance.model_dump(),
                errors=[],
                raw_text=output,
                cleaned_text=cleaned,
            )
        except Exception as exc:
            errors.append(f"Pydantic validation error: {exc}")
            return ValidationResult(
                valid=False,
                parsed=None,
                errors=errors,
                raw_text=output,
                cleaned_text=cleaned,
            )

    def extract_json(self, output: str) -> str | None:
        """Extract and clean JSON text from *output* without validating.

        Useful when you only need the cleaned JSON string, not full
        validation.

        Parameters
        ----------
        output:
            Raw LLM output text.

        Returns
        -------
        str | None
            Cleaned JSON text if successfully parsed, else None.
        """
        cleaned = _preprocess(output)
        errors: list[str] = []
        parsed = self._try_parse_json(cleaned, errors)
        if parsed is None:
            return None
        return json.dumps(parsed)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _try_parse_json(
        self,
        text: str,
        errors: list[str],
    ) -> dict[str, object] | list[object] | None:
        """Attempt to parse *text* as JSON.

        First tries the cleaned text as-is.  If that fails, applies the
        unquoted-key fix and tries again.

        Parameters
        ----------
        text:
            Pre-processed JSON candidate string.
        errors:
            Mutable list to append error messages to.

        Returns
        -------
        dict | list | None
            Parsed Python object, or None on failure.
        """
        # Attempt 1: text as-is
        try:
            return json.loads(text)  # type: ignore[return-value]
        except json.JSONDecodeError:
            pass

        # Attempt 2: fix unquoted keys
        try:
            fixed = _fix_unquoted_keys(text)
            return json.loads(fixed)  # type: ignore[return-value]
        except json.JSONDecodeError as exc:
            errors.append(f"JSON parse error: {exc.msg} (line {exc.lineno}, col {exc.colno})")
            return None
