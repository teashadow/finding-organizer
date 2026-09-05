"""CLI entrypoint for ferret."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.json import JSON
from rich.table import Table

from .banner import FERRET_BANNER
from .board import FerretBoard
from .exporter import export_finding
from .models import Finding, PLATFORMS, SEVERITIES, STATUSES
from .store import (
    ingest_tool_report,
    list_findings,
    list_runs,
    load_finding,
    next_id,
    record_run,
    run_stats,
    save_finding,
    update_status,
)

console = Console()

CLOSED_NEXT = {
    "queue": "in-progress",
    "in-progress": "reported",
    "reported": "disclosed",
    "disclosed": "rejected",
    "rejected": "queue",
}


def _print_banner() -> None:
    console.print(f"[bold cyan]{FERRET_BANNER}[/bold cyan]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _print_banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD finding tracker."""


@main.command("new")
@click.option("--title", prompt=True)
@click.option("--platform", type=click.Choice(PLATFORMS), prompt=True)
@click.option("--program", prompt=True)
@click.option("--severity", type=click.Choice(SEVERITIES), prompt=True)
@click.option("--type", "vuln_type", prompt=True)
@click.option("--target", prompt=True)
@click.option("--description", prompt=True)
@click.option("--impact", default="", prompt=True)
@click.option("--notes", default="", prompt=False)
@click.option("--steps", default="", help="Use '||' as a separator for non-interactive calls.")
@click.option("--tags", default="", help="Comma-separated tags.")
@click.option("--attachments", default="", help="Comma-separated file paths.")
@click.option("--cvss", default=None)
def new_finding(
    title: str,
    platform: str,
    program: str,
    severity: str,
    vuln_type: str,
    target: str,
    description: str,
    impact: str,
    notes: str,
    steps: str,
    tags: str,
    attachments: str,
    cvss: str | None,
) -> None:
    """Create a new finding."""
    finding = Finding.create(
        id=next_id(),
        title=title,
        platform=platform,
        program=program,
        severity=severity,
        type=vuln_type,
        status="queue",
        target=target,
        description=description,
        impact=impact,
        notes=notes,
        cvss=cvss,
        steps=[item.strip() for item in steps.split("||") if item.strip()],
        tags=[item.strip() for item in tags.split(",") if item.strip()],
        attachments=[item.strip() for item in attachments.split(",") if item.strip()],
    )
    path = save_finding(finding)
    console.print(f"[green]Created[/green] {finding.id} at {path}")


@main.command("ingest")
@click.argument("report_json", type=click.Path(exists=True))
def ingest_cmd(report_json: str) -> None:
    """Принять JSON-отчёт инструмента семьи (overreach/spike/…) в общую БД находок."""
    отчёт = json.loads(Path(report_json).read_text(encoding="utf-8"))
    заведены = ingest_tool_report(отчёт)
    if not заведены:
        console.print("[green]находок для заноса нет[/green] (инструмент вернул ПРОШЁЛ или пусто)")
        return
    t = Table(title=f"занесено находок инструмента: {len(заведены)}")
    t.add_column("id"); t.add_column("severity"); t.add_column("tool"); t.add_column("title")
    for f in заведены:
        t.add_row(f.id, f.severity, f.tool, f.title)
    console.print(t)


@main.command("list")
@click.option("--status", type=click.Choice(STATUSES))
def list_cmd(status: str | None) -> None:
    """List findings."""
    rows = list_findings(status=status)
    table = Table(title="Findings")
    table.add_column("ID", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Severity")
    table.add_column("Program")
    table.add_column("Title")
    for finding in rows:
        table.add_row(finding.id, finding.status, finding.severity, finding.program, finding.title)
    console.print(table)


@main.command("record")
@click.option("--tool", required=True)
@click.option("--target", default="")
@click.option("--verdict", default="")
@click.option("--rc", type=int, required=True)
@click.option("--findings", "findings_count", type=int, default=0)
def record_cmd(tool: str, target: str, verdict: str, rc: int, findings_count: int) -> None:
    """Записать один прогон инструмента в общий лог прогонов (runs.jsonl)."""
    rec = record_run(tool, target, verdict, rc, findings_count)
    console.print(f"[green]recorded[/green] {rec['tool']} rc={rec['rc']} @ {rec['ts']}")


@main.command("runs")
@click.option("--limit", type=int, default=50)
def runs_cmd(limit: int) -> None:
    """Таблица последних прогонов из общей БД прогонов."""
    rows = list_runs(limit=limit)
    table = Table(title=f"Runs (last {len(rows)})")
    table.add_column("Time", style="cyan")
    table.add_column("Tool", style="magenta")
    table.add_column("Target")
    table.add_column("Verdict")
    table.add_column("RC", justify="right")
    table.add_column("Findings", justify="right")
    for r in rows:
        rc = int(r.get("rc", 0))
        rc_style = "red" if rc >= 1 else "green"
        table.add_row(
            str(r.get("ts", "")), str(r.get("tool", "")), str(r.get("target", "")),
            str(r.get("verdict", "")), f"[{rc_style}]{rc}[/{rc_style}]",
            str(r.get("findings_count", 0)),
        )
    console.print(table)


@main.command("stats")
def stats_cmd() -> None:
    """Сводка по общей БД прогонов: всего, провалов (rc>=1), разбивка по инструментам."""
    stats = run_stats()
    console.print(
        f"[bold]всего прогонов:[/bold] {stats['total']}   "
        f"[bold]провалов (rc>=1):[/bold] [red]{stats['failures']}[/red]"
    )
    table = Table(title="По инструментам")
    table.add_column("Tool", style="magenta")
    table.add_column("Runs", justify="right")
    table.add_column("Failures", justify="right")
    for tool, slot in sorted(stats["by_tool"].items()):
        table.add_row(tool, str(slot["runs"]), str(slot["failures"]))
    console.print(table)


@main.command("show")
@click.argument("finding_id")
def show_cmd(finding_id: str) -> None:
    """Show one finding."""
    finding = load_finding(finding_id)
    console.print(JSON.from_data(finding.to_dict()))


@main.command("status")
@click.argument("finding_id")
@click.argument("new_status", type=click.Choice(STATUSES))
def status_cmd(finding_id: str, new_status: str) -> None:
    """Update finding status."""
    finding = update_status(finding_id, new_status)
    console.print(f"[green]{finding.id}[/green] -> {finding.status}")


@main.command("export")
@click.argument("finding_id")
@click.option("--output", type=click.Path(path_type=Path))
def export_cmd(finding_id: str, output: Path | None) -> None:
    """Export finding to markdown."""
    finding = load_finding(finding_id)
    path = export_finding(finding, output=output)
    console.print(f"[green]Exported[/green] {path}")


@main.command("board")
def board_cmd() -> None:
    """Open the Textual kanban board."""
    _print_banner()

    def cycle_status(finding_id: str) -> None:
        finding = load_finding(finding_id)
        update_status(finding_id, CLOSED_NEXT[finding.status])

    def export_current(finding_id: str) -> None:
        path = export_finding(load_finding(finding_id))
        console.print(f"[green]Exported[/green] {path}")

    app = FerretBoard(list_findings(), on_cycle_status=cycle_status, on_export=export_current)
    app.run()


if __name__ == "__main__":
    main()
