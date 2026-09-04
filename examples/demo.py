#!/usr/bin/env python3
"""Print-friendly mock: clean weather server vs poisoned + public-cache cases.

Run from the repo root:

    PYTHONPATH=src python examples/demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp_discovery_sanitizer import Policy, sanitize_discovery  # noqa: E402

FIXTURES = ROOT / "fixtures"
WIDTH = 72


def _box(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def _kv(label: str, value: str) -> None:
    print(f"  {label:<14} {value}")


def _show(title: str, path: Path, policy: Policy | None = None) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = sanitize_discovery(payload, policy)
    _box(title)
    _kv("fixture", path.name)
    _kv("verdict", result.verdict.upper())
    _kv("server", result.server_id or "(unknown)")
    _kv("hash", result.original_hash)
    if result.sanitized_hash and result.sanitized_hash != result.original_hash:
        _kv("fwd hash", result.sanitized_hash)
    if result.actions:
        _kv("actions", ", ".join(result.actions))
    print("  reasons")
    if not result.reasons:
        print("    (none — payload is within policy)")
    for reason in result.reasons:
        loc = f" [{reason.field}]" if reason.field else ""
        print(f"    - {reason.code}{loc}: {reason.message}")
    if result.sanitized is None:
        print("  forwarded    <blocked — gateway must not fold this into the prompt>")
    else:
        body = result.sanitized.get("result", result.sanitized)
        instructions = body.get("instructions")
        preview = "(none)"
        if isinstance(instructions, str):
            preview = instructions.replace("\n", " ")
            if len(preview) > 90:
                preview = preview[:87] + "..."
        _kv("instructions", preview)


def main() -> int:
    print("MCP Discovery Sanitizer — mock gateway walkthrough")
    print("No LLM. No GPU. Stage discovery only.")
    print()
    print("  agent  -->  [ sanitizer ]  -->  system prompt")
    print("                 |")
    print("                 +-- allow | allow_stripped | block")
    print("                 +-- sha256 of the discovery blob")

    _show(
        "1 / CLEAN — weather.internal, private cache",
        FIXTURES / "clean_discovery.json",
        Policy(isolate_untrusted=True),
    )
    _show(
        "2 / POISONED — jailbreak instructions (fail-closed BLOCK)",
        FIXTURES / "poisoned_instructions.json",
        Policy(fail_closed=True),
    )
    _show(
        "3 / POISONED — same payload, fail-open STRIP",
        FIXTURES / "poisoned_instructions.json",
        Policy(fail_closed=False, isolate_untrusted=False),
    )
    _show(
        "4 / PUBLIC CACHE — untrusted server (MCP-2026-008)",
        FIXTURES / "public_cache_untrusted.json",
        Policy(fail_closed=True),
    )
    _show(
        "5 / OVERLONG — tool/prompt/resource descriptions",
        FIXTURES / "overlong_descriptions.json",
        Policy(fail_closed=True),
    )

    print()
    print("-" * WIDTH)
    print(" Demo done. Clean allows. Poisoned blocks or strips.")
    print(" CLI:  python -m mcp_discovery_sanitizer fixtures/poisoned_instructions.json")
    print("-" * WIDTH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
