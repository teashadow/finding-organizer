"""Markdown export helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import Finding


def _fallback_markdown(finding: Finding) -> str:
    steps = "\n".join(f"{idx}. {step}" for idx, step in enumerate(finding.steps, start=1)) or "1. [Add reproduction steps]"
    payload = finding.notes or "[Exact payload used]"
    response = finding.description or "[Observed response]"
    return f"""# [{finding.severity.upper()}] {finding.title}

## Summary
{finding.description}

## Platform
- **Platform:** {finding.platform}
- **Program:** {finding.program}
- **Severity:** {finding.severity}
- **CVSS:** {finding.cvss or "[score if applicable]"}

## Steps to Reproduce
{steps}

## Proof of Concept
```
{payload}
```

**Response:**
```
{response}
```

## Impact
{finding.impact}

## Notes
{finding.notes}

## Finding Metadata
- **ID:** {finding.id}
- **Status:** {finding.status}
"""


def render_finding_markdown(finding: Finding) -> str:
    try:
        from dt.renderer import render_template
    except ImportError:
        return _fallback_markdown(finding)

    platform = finding.platform if finding.platform in {"h1", "bugcrowd", "intigriti"} else "h1"
    context: dict[str, Any] = {
        "program": finding.program,
        "severity": finding.severity.title(),
        "severity_label": finding.severity.upper(),
        "target": finding.target,
        "vector": finding.type,
        "type_label": finding.type.replace("-", " ").title(),
        "payload": "\n".join(finding.steps) or "[Exact payload used]",
        "response": finding.notes or finding.description or "[LLM response demonstrating the issue]",
        "cvss": finding.cvss or ("[required]" if platform == "h1" and finding.severity in {"critical", "high"} else "[score if applicable]"),
    }
    try:
        rendered = render_template(platform, finding.type, context=context)
    except Exception:
        return _fallback_markdown(finding)
    rendered += f"\n\n## Finding Metadata\n- **ID:** {finding.id}\n- **Status:** {finding.status}\n"
    if finding.attachments:
        rendered += "- **Attachments:** " + ", ".join(finding.attachments) + "\n"
    return rendered


def export_finding(finding: Finding, output: Path | None = None) -> Path:
    base_dir = Path.home() / ".local" / "share" / "mad" / "exports"
    base_dir.mkdir(parents=True, exist_ok=True)
    path = output or (base_dir / f"{finding.id}__{finding.type}.md")
    path.write_text(render_finding_markdown(finding), encoding="utf-8")
    return path
