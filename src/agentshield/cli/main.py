"""CLI entry point for agentshield.

Invoked as::

    agentshield [OPTIONS] COMMAND [ARGS]...

or, during development::

    python -m agentshield.cli.main
"""
from __future__ import annotations

import asyncio
import importlib
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
# redteam
# ---------------------------------------------------------------------------


@cli.command(name="redteam")
@click.option(
    "--target",
    "target_spec",
    required=True,
    help=(
        "Target callable in 'module:function' format, "
        "e.g. 'myapp.agent:handle_message'. "
        "The callable must accept a str and return a str."
    ),
)
@click.option(
    "--categories",
    "categories_str",
    default=None,
    help=(
        "Comma-separated list of attack categories to run. "
        "Defaults to all categories. "
        "Valid values: injection,exfiltration,tool_abuse,memory_poison"
    ),
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write JSON report to this file instead of stdout.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["pretty", "json"], case_sensitive=False),
    default="pretty",
    show_default=True,
    help="Output format when --output is not set.",
)
def redteam_command(
    target_spec: str,
    categories_str: str | None,
    output_path: str | None,
    output_format: str,
) -> None:
    """Run automated red team attack patterns against a target callable.

    The target is loaded dynamically from MODULE:FUNCTION notation.
    Attack patterns are drawn from publicly documented security research
    (OWASP ASI, OASIS CoSAI, arXiv papers, Simon Willison's blog, etc.).

    Exit codes:

    \b
      0 — grade A+ (95–100 % of attacks blocked)
      1 — grade below A+ (some attacks got through)
      2 — configuration or import error
    """
    from agentshield.redteam import CATEGORIES, RedTeamRunner, create_runner

    # ------------------------------------------------------------------
    # Resolve target callable
    # ------------------------------------------------------------------
    if ":" not in target_spec:
        error_console.print(
            f"[bold red]Invalid --target format:[/bold red] {target_spec!r}\n"
            "Expected 'module:function', e.g. 'myapp.agent:handle_message'"
        )
        sys.exit(2)

    module_path, func_name = target_spec.rsplit(":", 1)
    try:
        module = importlib.import_module(module_path)
    except ModuleNotFoundError as exc:
        error_console.print(
            f"[bold red]Cannot import module[/bold red] {module_path!r}: {exc}"
        )
        sys.exit(2)

    target_callable = getattr(module, func_name, None)
    if target_callable is None:
        error_console.print(
            f"[bold red]Function {func_name!r} not found in module {module_path!r}[/bold red]"
        )
        sys.exit(2)

    if not callable(target_callable):
        error_console.print(
            f"[bold red]{target_spec!r} is not callable.[/bold red]"
        )
        sys.exit(2)

    # ------------------------------------------------------------------
    # Resolve categories
    # ------------------------------------------------------------------
    if categories_str:
        requested = [c.strip() for c in categories_str.split(",") if c.strip()]
        invalid = [c for c in requested if c not in CATEGORIES]
        if invalid:
            error_console.print(
                f"[bold red]Unknown categories:[/bold red] {', '.join(invalid)}\n"
                f"Valid categories: {', '.join(CATEGORIES)}"
            )
            sys.exit(2)
        run_categories = requested
    else:
        run_categories = list(CATEGORIES)

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------
    runner: RedTeamRunner = create_runner(
        target=target_callable,
        target_description=target_spec,
    )

    console.print(
        f"[bold cyan]agentshield red team[/bold cyan] "
        f"target=[cyan]{target_spec}[/cyan] "
        f"categories=[cyan]{', '.join(run_categories)}[/cyan]"
    )

    from agentshield.redteam.attacks import get_patterns_by_category

    all_results = []
    for category in run_categories:
        patterns = get_patterns_by_category(category)
        console.print(
            f"  Running [yellow]{len(patterns)}[/yellow] "
            f"[bold]{category}[/bold] patterns..."
        )
        all_results.extend(runner.run_category(category))

    from agentshield.redteam.report import RedTeamReport

    report = RedTeamReport(
        results=all_results,
        target_description=target_spec,
    )

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    if output_path:
        Path(output_path).write_text(report.to_json(), encoding="utf-8")
        console.print(
            f"[green]Report written to[/green] {output_path}"
        )
        _print_redteam_summary(report)
    elif output_format == "json":
        console.print_json(report.to_json())
    else:
        _print_redteam_summary(report)

    sys.exit(0 if report.grade == "A+" else 1)


def _print_redteam_summary(report: object) -> None:  # type: ignore[no-untyped-def]
    """Render a rich table summarising a red team report."""
    from agentshield.redteam.report import RedTeamReport

    assert isinstance(report, RedTeamReport)

    grade_style = {
        "A+": "bold green",
        "A": "green",
        "B": "yellow",
        "C": "dark_orange",
        "D": "red",
        "F": "bold red",
    }.get(report.grade, "white")

    console.print(
        Panel.fit(
            f"Grade: [{grade_style}]{report.grade}[/{grade_style}]  |  "
            f"Blocked: [green]{report.blocked_count}[/green]/"
            f"[white]{report.total_attacks}[/white]  |  "
            f"Block rate: [cyan]{report.block_rate:.1%}[/cyan]",
            title="Red Team Report",
            border_style=grade_style,
        )
    )

    table = Table(
        title="Results by Category",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Category", style="bold", min_width=16)
    table.add_column("Total", justify="right")
    table.add_column("Blocked", justify="right", style="green")
    table.add_column("Unblocked", justify="right", style="red")
    table.add_column("Block Rate", justify="right")
    table.add_column("Grade", justify="center")

    for entry in report.to_dict()["by_category"]:  # type: ignore[index]
        table.add_row(
            str(entry["category"]),
            str(entry["total"]),
            str(entry["blocked"]),
            str(entry["unblocked"]),
            f"{float(entry['block_rate']):.1%}",
            str(entry["grade"]),
        )

    console.print(table)

    unblocked = report.unblocked_by_severity
    if unblocked:
        console.print("\n[bold red]Unblocked findings by severity:[/bold red]")
        for severity in ("critical", "high", "medium", "low"):
            patterns = unblocked.get(severity, [])
            if patterns:
                style = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "cyan",
                }[severity]
                console.print(f"  [{style}]{severity.upper()} ({len(patterns)})[/{style}]")
                for pattern in patterns[:5]:  # show at most 5 per severity
                    console.print(f"    - {pattern.name}: {pattern.description[:60]}...")
                if len(patterns) > 5:
                    console.print(f"    ... and {len(patterns) - 5} more")


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
