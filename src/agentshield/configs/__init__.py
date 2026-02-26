"""Bundled pipeline configuration presets.

The YAML files in this directory are importable via ``importlib.resources``::

    import importlib.resources
    pkg = importlib.resources.files("agentshield") / "configs" / "default.yaml"
    content = pkg.read_text(encoding="utf-8")
"""
