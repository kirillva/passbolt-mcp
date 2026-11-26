"""Summarize the local tool-error log for instruction work.

Run: uv run python scripts/tool_log_report.py [--path FILE] [--top 5] [--samples 3]

The log holds no secrets (see ``zai_passbolt.tool_log``), so the report can be
pasted next to the guides. Group by tool, error code and hint, then show a few
argument shapes for the failures worth a documentation fix.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zai_passbolt.tool_log import DEFAULT_NAME, ROTATED_FILES, log_path  # noqa: E402

DEFAULT_STATE = "~/.config/passbolt-mcp/state/passbolt.sqlite"
DOC_WORTHY = ("validation_failed", "provider_configuration_invalid", "provider_disabled")


def default_log_path() -> Path:
    state = Path(os.environ.get("PASSBOLT_STATE_PATH", DEFAULT_STATE)).expanduser()
    return log_path(state)


def read_entries(base: Path) -> list[dict]:
    """Oldest rotation first, so the report reads chronologically. Bad lines are skipped."""
    files = [base.with_name(f"{base.name}.{index}") for index in range(ROTATED_FILES, 0, -1)]
    entries: list[dict] = []
    for path in [*files, base]:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entry = json.loads(stripped)
            except ValueError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
    return entries


def describe(entry: dict) -> str:
    arguments = entry.get("arguments")
    if not isinstance(arguments, dict) or not arguments:
        return "-"
    return " ".join(f"{key}={value}" for key, value in sorted(arguments.items()))[:160]


def report(entries: list[dict], *, top: int, samples: int) -> list[str]:
    if not entries:
        return ["no tool errors logged yet"]
    lines: list[str] = [
        f"tool errors: {len(entries)}",
        f"period: {entries[0].get('ts')} .. {entries[-1].get('ts')}",
        f"version: {entries[-1].get('version')}",
        "",
        "## by tool",
    ]
    for (tool, code), count in Counter(
        (str(e.get("tool")), str(e.get("code"))) for e in entries
    ).most_common(top):
        lines.append(f"- {count:>4}  {tool}  {code}")

    hints = Counter(str(e.get("hint")) for e in entries if e.get("hint"))
    if hints:
        lines += ["", "## hints the model saw"]
        for hint, count in hints.most_common(top):
            lines.append(f"- {count:>4}  {hint[:160]}")

    lines += ["", "## arguments that need a documentation fix"]
    seen: Counter[tuple[str, str, str]] = Counter()
    for entry in entries:
        if str(entry.get("code")) not in DOC_WORTHY:
            continue
        seen[(str(entry.get("tool")), str(entry.get("code")), describe(entry))] += 1
    if not seen:
        lines.append("- none")
    for (tool, code, shape), count in seen.most_common(samples):
        lines.append(f"- {count:>4}  {tool}  {code}  {shape}")

    lines += ["", "## latest failures"]
    for entry in entries[-samples:]:
        lines.append(
            f"- {entry.get('ts')}  {entry.get('tool')}  {entry.get('outcome')}"
            f"  {entry.get('code')}  {entry.get('duration_ms')}ms  {describe(entry)}"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", help="log file (default: next to the state database)")
    parser.add_argument("--top", type=int, default=5, help="groups per section (default 5)")
    parser.add_argument("--samples", type=int, default=3, help="sample rows (default 3)")
    args = parser.parse_args(argv)
    path = Path(args.path).expanduser() if args.path else default_log_path()
    if path.name != DEFAULT_NAME and not path.exists():
        print(f"no log at {path}", file=sys.stderr)
        return 1
    print("\n".join(report(read_entries(path), top=max(1, args.top), samples=max(1, args.samples))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
