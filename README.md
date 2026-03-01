# agentshield

Multi-layer agent defense framework for AI security

[![CI](https://github.com/aumos-ai/agentshield/actions/workflows/ci.yaml/badge.svg)](https://github.com/aumos-ai/agentshield/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/agentshield.svg)](https://pypi.org/project/agentshield/)
[![Python versions](https://img.shields.io/pypi/pyversions/agentshield.svg)](https://pypi.org/project/agentshield/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Part of the [AumOS](https://github.com/aumos-ai) open-source agent infrastructure portfolio.

---

## Features

- `SecurityPipeline` scans agent input, output, and tool calls through an ordered chain of scanners with configurable severity thresholds and BLOCK/WARN/LOG actions
- Eight built-in scanners: regex injection detection, PII detection, credential detection, output safety, tool call validation, behavioral checking, output validation, and tool call integrity checking
- `Scanner` ABC makes it straightforward to write and register custom scanners; load them from a `shield.yaml` config file or inject them at runtime
- Phase-aware dispatch — each scanner declares which phases (`INPUT`, `OUTPUT`, `TOOL_CALL`) it runs in, so no scanner is invoked unnecessarily
- Cumulative findings tracked across the session with JSON, Markdown, and HTML report generation
- Adapters for LangChain, CrewAI, AutoGen, OpenAI Agents, and MCP that wrap existing agent code with a single decorator or context manager
- OWASP ASI Top 10 category mapper tags each finding with its corresponding ASI category for structured vulnerability reporting

## Current Limitations

> **Transparency note**: We list known limitations to help you evaluate fit.

- **Detection**: Regex-based injection detection. No ML/neural detection models.
- **Red Team**: Template-based red team generation — not generative/LLM-powered.
- **Coverage**: Focused on prompt injection and PII — limited malware/exploit detection.

## Quick Start

Install from PyPI:

```bash
pip install agentshield
```

Verify the installation:

```bash
agentshield version
```

Basic usage:

```python
import agentshield

# See examples/01_quickstart.py for a working example
```

## Documentation

- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Examples](examples/README.md)

## Enterprise Upgrade

For production deployments requiring SLA-backed support and advanced
integrations, contact the maintainers or see the commercial extensions documentation.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a pull request.

## License

Apache 2.0 — see [LICENSE](LICENSE) for full terms.

---

Part of [AumOS](https://github.com/aumos-ai) — open-source agent infrastructure.
