"""Filesystem store for findings."""

from __future__ import annotations

import contextlib
import fcntl
import json
from pathlib import Path

from .models import Finding, now_iso

DATA_DIR = Path.home() / ".local" / "share" / "mad" / "findings"
_LOCK_PATH = DATA_DIR / ".write.lock"


def ensure_data_dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


@contextlib.contextmanager
def _lock():
    """Межпроцессный эксклюзивный лок на запись (flock). Сериализует конкурентных писателей,
    чтобы аллокация id и запись файла-находки не гонялись. НЕ реентрантен — не вкладывать."""
    ensure_data_dir()
    fh = open(_LOCK_PATH, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def _finding_path(finding_id: str) -> Path:
    return ensure_data_dir() / f"{finding_id}.json"


def _compute_next_id() -> str:  # без лока — звать только внутри _lock()
    ids = []
    for path in DATA_DIR.glob("F-*.json"):
        try:
            ids.append(int(path.stem.split("-", 1)[1]))
        except (IndexError, ValueError):
            continue
    return f"F-{(max(ids, default=0) + 1):03d}"


def next_id() -> str:
    with _lock():
        return _compute_next_id()


def create_finding(finding: Finding) -> Finding:
    """Атомарно: под ОДНИМ локом выделить свежий F-id и записать. Для НОВЫХ находок —
    закрывает гонку next_id→save (два писателя больше не получат один id)."""
    with _lock():
        finding.id = _compute_next_id()
        finding.updated = now_iso()
        _finding_path(finding.id).write_text(
            json.dumps(finding.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return finding


def save_finding(finding: Finding) -> Path:
    # Запись под локом (сериализует писателей). Семантика прежняя: тот же id = обновление.
    # 🔴 Для НОВЫХ находок использовать create_finding — иначе TOCTOU next_id→save остаётся.
    path = _finding_path(finding.id)
    finding.updated = now_iso()
    with _lock():
        path.write_text(json.dumps(finding.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def load_finding(finding_id: str) -> Finding:
    path = _finding_path(finding_id)
    if not path.exists():
        raise FileNotFoundError(f"finding not found: {finding_id}")
    return Finding.from_dict(json.loads(path.read_text(encoding="utf-8")))


def list_findings(status: str | None = None) -> list[Finding]:
    ensure_data_dir()
    items = []
    # 🔴 И ручные (F-*), И находки инструментов (T-*): БД должна показывать всё, что приняла.
    # Прежде list глобил только F-* — ingest заносил T-*, но list их не видел (разрыв контракта).
    for path in sorted(list(DATA_DIR.glob("F-*.json")) + list(DATA_DIR.glob("T-*.json"))):
        items.append(Finding.from_dict(json.loads(path.read_text(encoding="utf-8"))))
    if status:
        items = [item for item in items if item.status == status]
    return sorted(items, key=lambda item: item.id)


def update_status(finding_id: str, new_status: str) -> Finding:
    finding = load_finding(finding_id)
    finding.status = new_status
    save_finding(finding)
    return finding


# ── общая БД ПРОГОНОВ (run-log) ──────────────────────────────────────────────
# Не находки, а факты запусков: каждый инструмент/компонент фреймворка пишет сюда
# одну строку на прогон. Это ЛОГ (append-only, идемпотентность не требуется), в
# том же каталоге данных, что и находки. Финдинги остаются в F-*/T-*.json — этот
# слой их не трогает (обратная совместимость).

RUNS_PATH = DATA_DIR / "runs.jsonl"


def _runs_path() -> Path:
    return ensure_data_dir() / "runs.jsonl"


def record_run(
    tool: str,
    target: str,
    verdict: str,
    rc: int,
    findings_count: int,
    ts: str | None = None,
) -> dict:
    """Записать один прогон инструмента в общий лог runs.jsonl.

    Атомарно на строку: одна `write()` дозаписью в конец файла (POSIX-append —
    строка не рвётся конкурентными писателями при O_APPEND). Возвращает записанную
    запись. rc>=1 считается провалом (см. run_stats)."""
    record = {
        "ts": ts or now_iso(),
        "tool": str(tool),
        "target": str(target),
        "verdict": str(verdict),
        "rc": int(rc),
        "findings_count": int(findings_count),
    }
    line = json.dumps(record, ensure_ascii=False) + "\n"
    path = _runs_path()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line)
    return record


def _read_runs() -> list[dict]:
    path = _runs_path()
    if not path.exists():
        return []
    runs: list[dict] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            runs.append(json.loads(raw))
        except json.JSONDecodeError:
            # битую строку пропускаем, но не теряем остальной лог
            continue
    return runs


def list_runs(limit: int = 50) -> list[dict]:
    """Последние `limit` прогонов, новейшие первыми (порядок дозаписи = хронологический)."""
    runs = _read_runs()
    if limit is not None and limit >= 0:
        runs = runs[-limit:]
    return list(reversed(runs))


def run_stats() -> dict:
    """Сводка по всему логу прогонов: всего, провалов (rc>=1), разбивка по инструментам."""
    runs = _read_runs()
    total = len(runs)
    failures = sum(1 for r in runs if int(r.get("rc", 0)) >= 1)
    by_tool: dict[str, dict] = {}
    for r in runs:
        tool = str(r.get("tool", "unknown"))
        slot = by_tool.setdefault(tool, {"runs": 0, "failures": 0})
        slot["runs"] += 1
        if int(r.get("rc", 0)) >= 1:
            slot["failures"] += 1
    return {"total": total, "failures": failures, "by_tool": by_tool}


# ── мост: находки ИНСТРУМЕНТОВ → общая БД ────────────────────────────────────
# Первый кирпич БД фреймворка: 10 доведённых инструментов выдают общий контракт
# {инструмент:{имя,цель}, verdict, findings:[...]}. Здесь он превращается в Finding'и.

_VERDICT_SEVERITY = {  # вердикт пробы → severity трекера
    "ПРОВАЛ": "high", "критический": "critical", "высокий": "high",
    "ВНИМАНИЕ": "medium", "PROVAL": "high",
}


def _ключ_идемпотентности(tool: str, target: str, вектор: str) -> str:
    """Стабильный id находки инструмента — чтобы повторный ingest того же прогона не задваивал."""
    import hashlib
    сырьё = f"{tool}|{target}|{вектор}".encode()
    return "T-" + hashlib.sha256(сырьё).hexdigest()[:10].upper()


def ingest_tool_report(отчёт: dict) -> list[Finding]:
    """Принять JSON-контракт инструмента, завести Finding на каждую проблемную находку.

    Заносим только то, что реально проблема (ПРОВАЛ/ВНИМАНИЕ/критический/высокий) — «ПРОШЁЛ» в
    трекер не пишем (это не находка). Идемпотентно по (инструмент+цель+вектор): id стабилен.
    """
    ensure_data_dir()
    инстр = отчёт.get("инструмент", {})
    tool = инстр.get("имя", отчёт.get("url", "unknown"))
    target = инстр.get("цель", отчёт.get("url", ""))
    заведены: list[Finding] = []

    # Находки живут в разных ключах у разных инструментов — собираем единообразно:
    #   findings (spike/needler/babel/snare/collider) · security_findings (mcpx) ·
    #   tools где критический (overreach). Каждую нормализуем к {вердикт, вектор, почему}.
    список: list[dict] = []
    for f in (отчёт.get("findings") or отчёт.get("пробы") or []):
        список.append(f)
    for f in отчёт.get("security_findings", []):
        # mcpx: severity уже в находке — переносим напрямую
        список.append({"вердикт": {"critical": "критический", "high": "высокий",
                                   "medium": "ВНИМАНИЕ"}.get(f.get("severity"), ""),
                       "вектор": f.get("code", "-"), "почему": f.get("message", "")})
    for t in отчёт.get("tools", []):
        # overreach: проблемные — критические инструменты
        if t.get("критический") or (isinstance(t.get("score"), (int, float)) and t["score"] >= 9):
            список.append({"вердикт": "критический", "вектор": t.get("name", "-"),
                           "почему": t.get("почему", "")})
    # 🔴 Дедуп по id ВНУТРИ вызова: несколько техник одной категории (spike: 16 техник → 4
    # категории) схлопываются в одну находку на класс проблемы — это осознанно (клиенту нужно
    # «категория direct проходит», а не 16 строк), но ingest обязан вернуть УНИКАЛЬНЫЕ и честное
    # число, а не число попыток. В записи копим счётчик схлопнутых техник.
    по_id: dict[str, Finding] = {}
    схлопнуто: dict[str, int] = {}
    for f in список:
        вердикт = str(f.get("вердикт") or f.get("класс") or отчёт.get("verdict", ""))
        severity = _VERDICT_SEVERITY.get(вердикт)
        if not severity:
            continue  # ПРОШЁЛ и прочее не-проблемное — не заносим
        вектор = str(f.get("вектор") or f.get("id") or f.get("категория") or f.get("класс") or "-")
        fid = _ключ_идемпотентности(tool, target, вектор)
        схлопнуто[fid] = схлопнуто.get(fid, 0) + 1
        по_id[fid] = Finding(
            id=fid, created=now_iso(), updated=now_iso(),
            title=f"[{tool}] {вектор} на {target}"[:120],
            platform="private", program=str(target), severity=severity,
            type=str(вектор), status="queue", target=str(target),
            description=str(f.get("почему") or f.get("детектор") or ""),
            source="tool", tool=str(tool), raw_verdict=вердикт,
            notes=json.dumps(f, ensure_ascii=False)[:2000],
        )
    # записываем уникальные; в notes — сколько техник схлопнулось в этот класс
    for fid, finding in по_id.items():
        if схлопнуто.get(fid, 1) > 1:
            finding.notes = f"[{схлопнуто[fid]} техник(и) в этом классе] " + finding.notes
        _finding_path(fid).write_text(
            json.dumps(finding.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        заведены.append(finding)

    # инструменты с вердиктом на УРОВНЕ отчёта, но без разложенных findings (напр. пустой список
    # при общем ПРОВАЛ) — заведём одну сводную находку
    if not заведены and _VERDICT_SEVERITY.get(str(отчёт.get("verdict", ""))):
        вердикт = str(отчёт["verdict"])
        fid = _ключ_идемпотентности(tool, target, "overall")
        finding = Finding(
            id=fid, created=now_iso(), updated=now_iso(),
            title=f"[{tool}] {вердикт} на {target}"[:120], platform="private",
            program=str(target), severity=_VERDICT_SEVERITY[вердикт], type="overall",
            status="queue", target=str(target), description=str(отчёт.get("почему", "")),
            source="tool", tool=str(tool), raw_verdict=вердикт)
        _finding_path(fid).write_text(
            json.dumps(finding.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        заведены.append(finding)
    return заведены
