"""Textual board for findings."""

from __future__ import annotations

from collections import defaultdict

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Footer, Header, Label, ListItem, ListView, Static

from .banner import FERRET_BANNER
from .models import Finding

BOARD_COLUMNS = ("queue", "in-progress", "reported", "closed")

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "cyan",
    "info": "blue",
}


class FindingDetailScreen(ModalScreen[None]):
    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        body = [
            f"ID: {self.finding.id}",
            f"Title: {self.finding.title}",
            f"Severity: {self.finding.severity}",
            f"Platform: {self.finding.platform}",
            f"Program: {self.finding.program}",
            f"Status: {self.finding.status}",
            f"Target: {self.finding.target}",
            "",
            "Description:",
            self.finding.description,
            "",
            "Impact:",
            self.finding.impact,
            "",
            "Notes:",
            self.finding.notes or "-",
        ]
        yield Static("\n".join(body), id="finding-detail")

    def on_key(self, event) -> None:  # type: ignore[override]
        if event.key in {"escape", "enter"}:
            self.dismiss(None)


class FerretBoard(App[None]):
    CSS = """
    Screen {
        layout: vertical;
    }
    #banner {
        padding: 1 2;
        color: cyan;
    }
    #board {
        height: 1fr;
    }
    .column {
        width: 1fr;
        border: round #666666;
        margin: 0 1 1 1;
    }
    .column-title {
        content-align: center middle;
        height: 3;
        background: #202020;
        color: white;
    }
    ListView {
        height: 1fr;
    }
    #finding-detail {
        width: 80%;
        height: 80%;
        border: round white;
        background: $panel;
        padding: 1 2;
    }
    """

    BINDINGS = [
        ("enter", "details", "Details"),
        ("s", "cycle_status", "Cycle Status"),
        ("e", "export", "Export"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, findings: list[Finding], on_cycle_status, on_export) -> None:
        super().__init__()
        self.findings = findings
        self.on_cycle_status = on_cycle_status
        self.on_export = on_export
        self.lookup: dict[str, Finding] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(FERRET_BANNER, id="banner")
        with Horizontal(id="board"):
            for column in BOARD_COLUMNS:
                with VerticalScroll(classes="column"):
                    yield Label(column, classes="column-title")
                    yield ListView(*self._items_for(column), id=f"list-{column}")
        yield Footer()

    def _grouped(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for finding in self.findings:
            column = "closed" if finding.status in {"disclosed", "rejected"} else finding.status
            grouped[column].append(finding)
        return grouped

    def _items_for(self, column: str) -> list[ListItem]:
        items = []
        for finding in self._grouped().get(column, []):
            self.lookup[finding.id] = finding
            label = Text(f"{finding.id}  {finding.title}")
            label.stylize(SEVERITY_STYLES.get(finding.severity, "white"), 0, len(finding.id) + 2)
            label.append(f" [{finding.severity}]")
            items.append(ListItem(Static(label), id=finding.id))
        if not items:
            items.append(ListItem(Static("(empty)"), disabled=True))
        return items

    def _current_finding(self) -> Finding | None:
        focused = self.focused
        if not isinstance(focused, ListView):
            return None
        item = focused.highlighted_child
        if item is None or item.id is None:
            return None
        return self.lookup.get(item.id)

    def action_details(self) -> None:
        finding = self._current_finding()
        if finding:
            self.push_screen(FindingDetailScreen(finding))

    def action_cycle_status(self) -> None:
        finding = self._current_finding()
        if finding:
            self.on_cycle_status(finding.id)
            self.exit()

    def action_export(self) -> None:
        finding = self._current_finding()
        if finding:
            self.on_export(finding.id)
            self.exit()
