"""CLI: ``python -m mcp_discovery_sanitizer path/to/discovery.json``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from mcp_discovery_sanitizer.models import Policy, SanitizerResult
from mcp_discovery_sanitizer.sanitize import sanitize_discovery

_EXIT_OK = 0
_EXIT_USAGE = 1
_EXIT_BLOCK = 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        payload = _load_payload(args.path)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: failed to read discovery JSON: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    try:
        policy = _policy_from_args(args)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: invalid policy: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    result = sanitize_discovery(payload, policy, server_id=args.server_id)
    _emit(result, sys.stdout)
    return _EXIT_OK if result.allowed else _EXIT_BLOCK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-discovery-sanitizer",
        description=(
            "Sanitize an MCP discovery payload (initialize / tools/list / "
            "prompts / resources) before an agent trusts it."
        ),
    )
    parser.add_argument(
        "path",
        help="Path to discovery JSON, or '-' for stdin.",
    )
    parser.add_argument(
        "--server-id",
        default=None,
        help="Override server id used for the trusted-server cache check.",
    )
    parser.add_argument(
        "--policy",
        default=None,
        metavar="FILE",
        help="Optional JSON policy file.",
    )
    parser.add_argument(
        "--fail-closed",
        dest="fail_closed",
        action="store_true",
        default=None,
        help="Block on injection / public cache / overlong fields (default).",
    )
    parser.add_argument(
        "--no-fail-closed",
        dest="fail_closed",
        action="store_false",
        help="Strip or downgrade instead of blocking.",
    )
    parser.add_argument(
        "--allow-public-cache",
        dest="allow_public_cache",
        action="store_true",
        default=None,
        help="Permit cacheScope=public even from untrusted servers.",
    )
    parser.add_argument(
        "--max-instructions-len",
        type=int,
        default=None,
        help="Override max_instructions_len.",
    )
    parser.add_argument(
        "--trusted-server",
        action="append",
        default=[],
        metavar="ID",
        help="Trusted server id (repeatable). Public cache is allowed for these.",
    )
    return parser


def _load_payload(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _policy_from_args(args: argparse.Namespace) -> Policy:
    data: dict[str, Any] = {}
    if args.policy:
        data.update(json.loads(Path(args.policy).read_text(encoding="utf-8")))
    if args.fail_closed is not None:
        data["fail_closed"] = args.fail_closed
    if args.allow_public_cache is not None:
        data["allow_public_cache"] = args.allow_public_cache
    if args.max_instructions_len is not None:
        data["max_instructions_len"] = args.max_instructions_len
    if args.trusted_server:
        existing = set(data.get("trusted_server_ids") or [])
        existing.update(args.trusted_server)
        data["trusted_server_ids"] = sorted(existing)
    return Policy.from_mapping(data)


def _emit(result: SanitizerResult, stream: TextIO) -> None:
    json.dump(result.to_dict(), stream, indent=2, ensure_ascii=False)
    stream.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
