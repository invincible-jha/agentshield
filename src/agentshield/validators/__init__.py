"""agentshield.validators — Structured output validation for LLM responses.

Validates that LLM-generated text conforms to a JSON schema or a Pydantic
model.  Handles common LLM JSON formatting issues (trailing commas, single
quotes, unquoted keys, markdown code fences).

Public surface
--------------
OutputValidator
    Main validator class.
ValidationResult
    The result of a single validation call.
OutputValidatorError
    Base exception for this sub-package.

Example
-------
::

    from agentshield.validators import OutputValidator

    validator = OutputValidator()
    schema = {"type": "object", "properties": {"name": {"type": "string"}}}
    result = validator.validate('{"name": "Alice"}', schema)
    print(result.valid, result.parsed)
"""
from __future__ import annotations

from agentshield.validators.output_validator import (
    OutputValidator,
    OutputValidatorError,
    ValidationResult,
)

__all__ = [
    "OutputValidator",
    "OutputValidatorError",
    "ValidationResult",
]
