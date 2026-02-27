"""Example: Using agentshield with NVIDIA NeMo Guardrails.

Install with:
    pip install "aumos-agentshield[nemo]"

This example demonstrates using agentshield's text normalizer as a
NeMo Guardrails input rail. The preprocessor detects and normalizes
obfuscation techniques (homoglyphs, leetspeak, invisible characters,
encoded content) before NeMo's safety checks run.
"""
from __future__ import annotations

# from agentshield.integrations.nemo_adapter import (
#     AgentShieldNeMoPreprocessor,
# )

# --- Create the preprocessor ---
# preprocessor = AgentShieldNeMoPreprocessor()

# --- Normalize obfuscated text ---
# result = preprocessor.preprocess("H3ll0 w0rld")
# print(f"Original:   {result.original_text}")
# print(f"Normalized: {result.normalized_text}")
# print(f"Modified:   {result.was_modified}")

# --- Register as a NeMo input rail ---
# from nemoguardrails import RailsConfig, LLMRails
#
# config = RailsConfig.from_content(
#     yaml_content="...",  # Your NeMo config
#     colang_content="...",
# )
# rails = LLMRails(config)
# preprocessor.register_with_rails(rails)
#
# # Now all incoming messages are normalized before safety checks
# response = rails.generate(messages=[
#     {"role": "user", "content": "H3ll0, c4n y0u h3lp m3?"}
# ])

print("Example: use_with_nemo.py")
print("Uncomment the code above and install nemoguardrails to run.")
