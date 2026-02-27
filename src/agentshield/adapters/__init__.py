"""Framework adapters for agentshield.

Each adapter is in its own submodule to keep optional framework imports
isolated.  Import only the adapter you need to avoid unnecessary dependency
errors when a framework is not installed.

Framework-specific adapter classes are available as named imports:

* :class:`LangChainShield` — LangChain ``BaseCallbackHandler`` adapter
* :class:`CrewAIShield` — CrewAI task middleware adapter
* :class:`AutoGenShield` — AutoGen message hook adapter
* :class:`MCPShield` — Model Context Protocol tool-call interceptor
* :class:`AnthropicShield` — Anthropic SDK ``messages.create`` interceptor
* :class:`MicrosoftAgentShield` — Microsoft Agents SDK activity handler interceptor

Low-level decorator helpers:

* :func:`shield` — async decorator for any agent callable
* :func:`shield_sync` — sync decorator for any agent callable
"""
from __future__ import annotations

from agentshield.adapters.anthropic_sdk import AnthropicShield
from agentshield.adapters.autogen import AgentShieldAutoGenHook as AutoGenShield
from agentshield.adapters.crewai import AgentShieldCrewMiddleware as CrewAIShield
from agentshield.adapters.generic import shield, shield_sync
from agentshield.adapters.langchain import AgentShieldCallback as LangChainShield
from agentshield.adapters.mcp import MCPShield
from agentshield.adapters.microsoft_agents import MicrosoftAgentShield

__all__ = [
    "AnthropicShield",
    "AutoGenShield",
    "CrewAIShield",
    "LangChainShield",
    "MCPShield",
    "MicrosoftAgentShield",
    "shield",
    "shield_sync",
]
