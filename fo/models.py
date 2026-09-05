"""Finding data structures."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

STATUSES = ("queue", "in-progress", "reported", "disclosed", "rejected")
PLATFORMS = ("h1", "bugcrowd", "intigriti", "immunefi", "private")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class Finding:
    id: str
    created: str
    updated: str
    title: str
    platform: str
    program: str
    severity: str
    type: str
    status: str
    target: str
    description: str
    steps: list[str] = field(default_factory=list)
    impact: str = ""
    cvss: str | None = None
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    attachments: list[str] = field(default_factory=list)
    # Поля для находок ИНСТРУМЕНТОВ (source="tool") — чтобы 10 проб семьи писали в общую БД
    # наравне с ручными H1-репортами (source="manual"). Дефолты держат обратную совместимость:
    # старые F-*.json без этих ключей грузятся как manual.
    source: str = "manual"          # manual | tool
    tool: str = ""                  # имя инструмента-источника (overreach, spike, …)
    raw_verdict: str = ""           # исходный вердикт пробы (ПРОВАЛ/ВНИМАНИЕ)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        # игнорируем незнакомые ключи и подставляем дефолты для отсутствующих — миграция без боли
        поля = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in поля})

    @classmethod
    def create(cls, **values: Any) -> "Finding":
        stamp = now_iso()
        return cls(created=stamp, updated=stamp, **values)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
