# Examples

| # | Example | Description |
|---|---------|-------------|
| 01 | [Quickstart](01_quickstart.py) | Minimal working example with the Shield convenience class |
| 02 | [Custom Pipeline](02_custom_pipeline.py) | Build a SecurityPipeline with selected scanners |
| 03 | [Multi-Layer Defense](03_multilayer_defense.py) | DefenseChain with adaptive FeedbackLoop |
| 04 | [Tool Risk Analysis](04_tool_risk_analysis.py) | Assess risk levels in tool descriptions |
| 05 | [OWASP Mapping](05_owasp_mapping.py) | Map security findings to OWASP LLM Top 10 |
| 06 | [Agent Wrapper](06_agent_wrapper.py) | Wrap any agent function with automatic scanning |
| 07 | [CrewAI Shield](07_crewai_shield.py) | Shield CrewAI task inputs and outputs |

## Running the examples

```bash
pip install agentshield
python examples/01_quickstart.py
```

For framework integrations:

```bash
pip install crewai   # for example 07
```
