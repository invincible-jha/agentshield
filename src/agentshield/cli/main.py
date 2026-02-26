"""CLI entry point for agentshield.

Invoked as::

    agentshield [OPTIONS] COMMAND [ARGS]...

or, during development::

    python -m agentshield.cli.main
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
error_console = Console(stderr=True, style="bold red")


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option()
def cli() -> None:
    """agentshield — Multi-layer agent defense framework for AI security."""


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@cli.command(name="version")
def version_command() -> None:
    """Show detailed version and environment information."""
    import platform

    from agentshield import __version__

    console.print(Panel.fit(
        f"[bold cyan]agentshield[/bold cyan] [green]v{__version__}[/green]\n"
        f"Python  {platform.python_version()}  ({platform.python_implementation()})\n"
        f"Platform  {platform.system()} {platform.release()}",
        title="Version Info",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@cli.command(name="scan")
@click.option("--input", "input_text", required=True, help="Text to scan for security issues.")
@click.option(
    "--phase",
    type=click.Choice(["input", "output"], case_sensitive=False),
    default="input",
    show_default=True,
    help="Scan phase (input or output).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=False),
    default=None,
    help="Path to shield.yaml config file.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["pretty", "json"], case_sensitive=False),
    default="pretty",
    show_default=True,
    help="Output format.",
)
def scan_command(
    input_text: str,
    phase: str,
    config_path: str | None,
    output_format: str,
) -> None:
    """Scan TEXT for security issues and print the report."""
    pipeline = _load_pipeline(config_path)

    if phase == "input":
        report = asyncio.run(pipeline.scan_input(input_text))
    else:
        report = asyncio.run(pipeline.scan_output(input_text))

    if output_format == "json":
        console.print_json(report.to_json())
    else:
        _print_report(report)

    sys.exit(1 if report.has_high else 0)


# ---------------------------------------------------------------------------
# scan-file
# ---------------------------------------------------------------------------


@cli.command(name="scan-file")
@click.argument("file", type=click.Path(exists=True, readable=True))
@click.option(
    "--phase",
    type=click.Choice(["input", "output"], case_sensitive=False),
    default="input",
    show_default=True,
    help="Scan phase.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=False),
    default=None,
    help="Path to shield.yaml config file.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["pretty", "json"], case_sensitive=False),
    default="pretty",
    show_default=True,
)
def scan_file_command(
    file: str,
    phase: str,
    config_path: str | None,
    output_format: str,
) -> None:
    """Scan the contents of FILE for security issues."""
    try:
        content = Path(file).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        error_console.print(f"Cannot read file {file!r}: {exc}")
        sys.exit(2)

    pipeline = _load_pipeline(config_path)

    if phase == "input":
        report = asyncio.run(pipeline.scan_input(content, metadata={"source_file": file}))
    else:
        report = asyncio.run(pipeline.scan_output(content, metadata={"source_file": file}))

    if output_format == "json":
        console.print_json(report.to_json())
    else:
        console.print(f"[dim]Source:[/dim] {file}")
        _print_report(report)

    sys.exit(1 if report.has_high else 0)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@cli.command(name="report")
@click.option(
    "--session-dir",
    type=click.Path(exists=True, file_okay=False),
    required=True,
    help="Directory containing agentshield JSON report files.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "md", "html"], case_sensitive=False),
    default="md",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write report to this file instead of stdout.",
)
def report_command(
    session_dir: str,
    output_format: str,
    output_path: str | None,
) -> None:
    """Generate a cumulative security report from a session directory.

    The session directory should contain one or more JSON files produced by
    `agentshield scan --format json` or by the pipeline's generate_report().
    """
    from agentshield.core.scanner import Finding, FindingSeverity
    from agentshield.reporting.report import SecurityReportGenerator

    session_path = Path(session_dir)
    all_findings: list[Finding] = []

    json_files = list(session_path.glob("*.json"))
    if not json_files:
        error_console.print(
            f"No JSON files found in {session_dir!r}. "
            "Run scans with --format json first."
        )
        sys.exit(2)

    for json_file in sorted(json_files):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            error_console.print(f"Skipping {json_file.name}: {exc}")
            continue
        findings_data = data.get("findings", [])
        for fd in findings_data:
            try:
                finding = Finding(
                    scanner_name=str(fd.get("scanner_name", "")),
                    severity=FindingSeverity(fd.get("severity", "info")),
                    category=str(fd.get("category", "")),
                    message=str(fd.get("message", "")),
                    details=dict(fd.get("details", {})),
                )
                all_findings.append(finding)
            except (ValueError, KeyError):
                continue

    generator = SecurityReportGenerator()
    fmt_map = {"json": "json", "md": "markdown", "html": "html"}
    content = generator.generate(all_findings, fmt_map[output_format])

    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
        console.print(
            f"[green]Report written to[/green] {output_path} "
            f"({len(all_findings)} findings from {len(json_files)} file(s))"
        )
    else:
        console.print(content)


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


@cli.command(name="init")
@click.option(
    "--preset",
    type=click.Choice(["default", "strict", "minimal"], case_sensitive=False),
    default="default",
    show_default=True,
    help="Configuration preset to use.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default="shield.yaml",
    show_default=True,
    help="Output file path.",
)
def init_command(preset: str, output_path: str) -> None:
    """Create a shield.yaml configuration file from a preset."""
    import importlib.resources

    pkg = importlib.resources.files("agentshield") / "configs" / f"{preset}.yaml"
    try:
        content = pkg.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        error_console.print(f"Cannot load preset {preset!r}: {exc}")
        sys.exit(2)

    dest = Path(output_path)
    if dest.exists():
        overwrite = click.confirm(
            f"{output_path!r} already exists. Overwrite?", default=False
        )
        if not overwrite:
            console.print("[yellow]Aborted.[/yellow]")
            sys.exit(0)

    dest.write_text(content, encoding="utf-8")
    console.print(
        f"[green]Created[/green] {output_path!r} "
        f"([cyan]{preset}[/cyan] preset)"
    )


# ---------------------------------------------------------------------------
# scanners group
# ---------------------------------------------------------------------------


@cli.group(name="scanners")
def scanners_group() -> None:
    """Manage and inspect registered scanners."""


@scanners_group.command(name="list")
def scanners_list_command() -> None:
    """List all built-in and registered scanners."""
    from agentshield.plugins.registry import register_builtin_scanners, scanner_registry

    register_builtin_scanners()

    table = Table(
        title="Registered Scanners",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Name", style="bold", min_width=24)
    table.add_column("Class", style="dim")
    table.add_column("Phases", style="green")

    for slug in scanner_registry.list_scanners():
        cls = scanner_registry.get_scanner(slug)
        phases_attr = getattr(cls, "phases", [])
        phases_str = ", ".join(p.value for p in phases_attr)
        table.add_row(slug, cls.__name__, phases_str)

    console.print(table)


# ---------------------------------------------------------------------------
# owasp-map
# ---------------------------------------------------------------------------


@cli.command(name="owasp-map")
def owasp_map_command() -> None:
    """Show the OWASP Agentic AI Top 10 mapping table."""
    from agentshield.reporting.owasp_mapper import OWASPMapper

    mapper = OWASPMapper()
    table = Table(
        title="OWASP Agentic AI Security Top 10 Mapping",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("ID", style="bold", min_width=8)
    table.add_column("Name", min_width=32)
    table.add_column("Scanners", style="green")
    table.add_column("Coverage Notes", style="yellow", min_width=20)

    for cat in mapper.all_categories():
        scanners_str = ", ".join(cat.related_scanners) if cat.related_scanners else "[dim]None[/dim]"
        coverage_str = cat.coverage_note[:60] + "..." if len(cat.coverage_note) > 60 else cat.coverage_note or "[dim]N/A[/dim]"
        table.add_row(cat.id, cat.name, scanners_str, coverage_str)

    console.print(table)


# ---------------------------------------------------------------------------
# plugins (backward compat)
# ---------------------------------------------------------------------------


@cli.command(name="plugins")
def plugins_command() -> None:
    """List all registered plugins loaded from entry-points."""
    from agentshield.plugins.registry import register_builtin_scanners, scanner_registry

    register_builtin_scanners()
    slugs = scanner_registry.list_scanners()
    console.print(f"[bold]Registered scanners ({len(slugs)}):[/bold]")
    for slug in slugs:
        console.print(f"  [cyan]{slug}[/cyan]")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_pipeline(config_path: str | None):  # type: ignore[return]
    from agentshield.core.exceptions import ConfigError
    from agentshield.core.pipeline import SecurityPipeline

    if config_path:
        try:
            return SecurityPipeline.from_config(config_path)
        except ConfigError as exc:
            error_console.print(f"Config error: {exc}")
            sys.exit(2)

    # Auto-discover shield.yaml in CWD
    default_cfg = Path("shield.yaml")
    if default_cfg.exists():
        try:
            return SecurityPipeline.from_config(default_cfg)
        except ConfigError as exc:
            error_console.print(f"Config error in shield.yaml: {exc}")
            sys.exit(2)

    return SecurityPipeline.default()


def _print_report(report) -> None:  # type: ignore[no-untyped-def]
    from rich.text import Text

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }

    if report.is_clean:
        console.print(Panel("[green]No findings detected.[/green]", title="Security Report"))
        return

    console.print(
        Panel(
            f"[bold]{report.summary}[/bold]\n"
            f"[dim]Phase: {report.phase} | Duration: {report.scan_duration_ms:.1f}ms[/dim]",
            title="Security Report",
            border_style="red" if report.has_high else "yellow",
        )
    )

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Severity", min_width=10)
    table.add_column("Scanner", min_width=20)
    table.add_column("Category", min_width=20)
    table.add_column("Message")

    for finding in report.findings:
        sev = finding.severity.value
        style = severity_styles.get(sev, "")
        table.add_row(
            Text(sev.upper(), style=style),
            finding.scanner_name,
            finding.category,
            finding.message,
        )

    console.print(table)


if __name__ == "__main__":
    cli()
