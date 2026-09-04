"""Apply policy to an MCP discovery payload. No model, no GPU."""

from __future__ import annotations

import copy
import re
from typing import Any, Iterable

from mcp_discovery_sanitizer.envelope import rewrap, unwrap_discovery
from mcp_discovery_sanitizer.hashutil import canonical_hash
from mcp_discovery_sanitizer.models import Policy, Reason, SanitizerResult
from mcp_discovery_sanitizer.patterns import ISOLATION_PREFIX, ISOLATION_SUFFIX

_LIST_KEYS = ("tools", "prompts", "resources")
_DISCOVERY_HINTS = frozenset(
    {
        "instructions",
        "serverInfo",
        "server_info",
        "capabilities",
        "protocolVersion",
        "protocol_version",
        "tools",
        "prompts",
        "resources",
        "cacheScope",
        "_meta",
    }
)


def sanitize_discovery(
    payload: Any,
    policy: Policy | None = None,
    *,
    server_id: str | None = None,
) -> SanitizerResult:
    """Sanitize one discovery blob before an agent trusts it.

    ``payload`` may be a raw result object or a JSON-RPC ``{"result": ...}``
    envelope. ``server_id`` overrides ``serverInfo.name`` when deciding
    whether public cache is allowed.
    """
    policy = policy or Policy()
    reasons: list[Reason] = []
    actions: list[str] = []
    stripped = False
    blocked = False

    if not isinstance(payload, dict):
        reason = Reason(
            code="invalid_payload",
            message="Discovery payload must be a JSON object.",
            field="$",
            detail=type(payload).__name__,
        )
        dummy_hash = canonical_hash({"_invalid": type(payload).__name__})
        if policy.fail_closed:
            return SanitizerResult(
                verdict="block",
                reasons=(reason,),
                sanitized=None,
                original_hash=dummy_hash,
                sanitized_hash=None,
                actions=(),
                server_id=server_id,
            )
        return SanitizerResult(
            verdict="allow_stripped",
            reasons=(reason,),
            sanitized={},
            original_hash=dummy_hash,
            sanitized_hash=canonical_hash({}),
            actions=("replaced_invalid_payload",),
            server_id=server_id,
        )

    envelope, body, is_envelope, is_error = unwrap_discovery(payload)
    if is_error or not isinstance(body, dict):
        err_hash = canonical_hash(body if body is not None else {"error": True})
        reason = Reason(
            code="jsonrpc_error" if is_error else "invalid_payload",
            message=(
                "JSON-RPC error response has no discovery result."
                if is_error
                else "Discovery result must be a JSON object."
            ),
            field="error" if is_error else "result",
        )
        if policy.fail_closed:
            return SanitizerResult(
                verdict="block",
                reasons=(reason,),
                sanitized=None,
                original_hash=err_hash,
                sanitized_hash=None,
                actions=(),
                server_id=server_id,
                envelope=is_envelope,
            )
        empty = {}
        sanitized: dict[str, Any] = rewrap(envelope, empty) if is_envelope else empty
        return SanitizerResult(
            verdict="allow_stripped",
            reasons=(reason,),
            sanitized=sanitized,
            original_hash=err_hash,
            sanitized_hash=canonical_hash(empty),
            actions=("dropped_error_or_invalid_result",),
            server_id=server_id,
            envelope=is_envelope,
        )

    original_hash = canonical_hash(body)
    resolved_id = server_id or _infer_server_id(body)
    compiled = _compile_patterns(policy.block_patterns)
    work = copy.deepcopy(body)

    if not _looks_like_discovery(work):
        reasons.append(
            Reason(
                code="unrecognized_discovery",
                message="Payload has no discovery fields; treated as untrusted blob.",
                field="$",
            )
        )
        if policy.fail_closed:
            blocked = True

    cache_blocked, cache_stripped = _apply_cache_scope(
        work, policy, resolved_id, reasons, actions
    )
    blocked = blocked or cache_blocked
    stripped = stripped or cache_stripped

    inst_blocked, inst_stripped = _apply_instructions(
        work, policy, compiled, reasons, actions
    )
    blocked = blocked or inst_blocked
    stripped = stripped or inst_stripped

    for list_key in _LIST_KEYS:
        items = work.get(list_key)
        if items is None:
            continue
        if not isinstance(items, list):
            reasons.append(
                Reason(
                    code="invalid_list",
                    message=f"{list_key!r} must be an array.",
                    field=list_key,
                    detail=type(items).__name__,
                )
            )
            if policy.fail_closed:
                blocked = True
            else:
                work[list_key] = []
                stripped = True
                actions.append(f"replaced_{list_key}_with_empty_list")
            continue
        item_blocked, item_stripped = _apply_named_items(
            work, list_key, items, policy, compiled, reasons, actions
        )
        blocked = blocked or item_blocked
        stripped = stripped or item_stripped

    if blocked:
        return SanitizerResult(
            verdict="block",
            reasons=tuple(reasons),
            sanitized=None,
            original_hash=original_hash,
            sanitized_hash=None,
            actions=tuple(actions),
            server_id=resolved_id,
            envelope=is_envelope,
        )

    out_body = work
    sanitized_hash = canonical_hash(out_body)
    if is_envelope:
        sanitized_out: dict[str, Any] | None = rewrap(envelope, out_body)
    else:
        sanitized_out = out_body

    verdict: str = "allow_stripped" if stripped else "allow"
    return SanitizerResult(
        verdict=verdict,  # type: ignore[arg-type]
        reasons=tuple(reasons),
        sanitized=sanitized_out,
        original_hash=original_hash,
        sanitized_hash=sanitized_hash,
        actions=tuple(actions),
        server_id=resolved_id,
        envelope=is_envelope,
    )


def _looks_like_discovery(body: dict[str, Any]) -> bool:
    return bool(_DISCOVERY_HINTS.intersection(body.keys())) or (
        isinstance(body.get("_meta"), dict) and "cacheScope" in body["_meta"]
    )


def _infer_server_id(body: dict[str, Any]) -> str | None:
    info = body.get("serverInfo") or body.get("server_info")
    if isinstance(info, dict):
        name = info.get("name")
        if isinstance(name, str) and name:
            return name
    for key in ("server_id", "serverId", "server"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _compile_patterns(patterns: Iterable[str]) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for raw in patterns:
        try:
            compiled.append(re.compile(raw, re.IGNORECASE))
        except re.error:
            compiled.append(re.compile(re.escape(raw), re.IGNORECASE))
    return compiled


def _first_match(text: str, compiled: list[re.Pattern[str]]) -> re.Pattern[str] | None:
    for pat in compiled:
        if pat.search(text):
            return pat
    return None


def _read_cache_scope(body: dict[str, Any]) -> tuple[str | None, str]:
    if isinstance(body.get("cacheScope"), str):
        return body["cacheScope"], "cacheScope"
    meta = body.get("_meta")
    if isinstance(meta, dict) and isinstance(meta.get("cacheScope"), str):
        return meta["cacheScope"], "_meta.cacheScope"
    return None, "cacheScope"


def _write_cache_scope(body: dict[str, Any], field_path: str, value: str) -> None:
    if field_path.startswith("_meta"):
        meta = body.get("_meta")
        if not isinstance(meta, dict):
            meta = {}
            body["_meta"] = meta
        meta["cacheScope"] = value
        return
    body["cacheScope"] = value


def _apply_cache_scope(
    body: dict[str, Any],
    policy: Policy,
    server_id: str | None,
    reasons: list[Reason],
    actions: list[str],
) -> tuple[bool, bool]:
    scope, field_path = _read_cache_scope(body)
    if scope is None or scope.lower() != "public":
        return False, False
    if policy.allow_public_cache or policy.is_trusted(server_id):
        return False, False

    who = server_id or "unknown"
    if policy.fail_closed:
        reasons.append(
            Reason(
                code="public_cache_untrusted",
                message=(
                    f"Refused cacheScope=public from untrusted server {who!r} "
                    "(MCP-2026-008)."
                ),
                field=field_path,
                detail=who,
            )
        )
        return True, False

    _write_cache_scope(body, field_path, "private")
    reasons.append(
        Reason(
            code="public_cache_downgraded",
            message=(
                f"Downgraded cacheScope from public to private for "
                f"untrusted server {who!r}."
            ),
            field=field_path,
            detail=who,
        )
    )
    actions.append("downgraded_public_cache")
    return False, True


def _apply_instructions(
    body: dict[str, Any],
    policy: Policy,
    compiled: list[re.Pattern[str]],
    reasons: list[Reason],
    actions: list[str],
) -> tuple[bool, bool]:
    if "instructions" not in body:
        return False, False
    raw = body["instructions"]
    if raw is None:
        return False, False
    if not isinstance(raw, str):
        reasons.append(
            Reason(
                code="invalid_instructions",
                message="instructions must be a string.",
                field="instructions",
                detail=type(raw).__name__,
            )
        )
        if policy.fail_closed:
            return True, False
        del body["instructions"]
        actions.append("dropped_nonstring_instructions")
        return False, True

    blocked = False
    stripped = False
    text = raw

    hit = _first_match(text, compiled)
    if hit:
        reasons.append(
            Reason(
                code="instructions_blocklist",
                message="instructions matched an obvious injection pattern.",
                field="instructions",
                detail=hit.pattern,
            )
        )
        if policy.fail_closed:
            blocked = True
        else:
            body["instructions"] = ""
            text = ""
            stripped = True
            actions.append("stripped_poisoned_instructions")

    if len(text) > policy.max_instructions_len:
        reasons.append(
            Reason(
                code="instructions_overlong",
                message=(
                    f"instructions length {len(text)} exceeds "
                    f"max_instructions_len={policy.max_instructions_len}."
                ),
                field="instructions",
                detail=str(len(text)),
            )
        )
        if policy.fail_closed:
            blocked = True
        else:
            text = text[: policy.max_instructions_len]
            body["instructions"] = text
            stripped = True
            actions.append("truncated_instructions")

    if (
        policy.isolate_untrusted
        and isinstance(body.get("instructions"), str)
        and body["instructions"]
        and not blocked
    ):
        isolated = _isolate(body["instructions"])
        if isolated != body["instructions"]:
            body["instructions"] = isolated
            actions.append("isolated_instructions")
            reasons.append(
                Reason(
                    code="instructions_isolated",
                    message="Wrapped remaining instructions in an untrusted marker.",
                    field="instructions",
                )
            )
            # Isolation is a presentation transform, not a security strip.
    return blocked, stripped


def _isolate(text: str) -> str:
    if text.startswith(ISOLATION_PREFIX) and text.endswith(ISOLATION_SUFFIX):
        return text
    return f"{ISOLATION_PREFIX}{text}{ISOLATION_SUFFIX}"


def _apply_named_items(
    body: dict[str, Any],
    list_key: str,
    items: list[Any],
    policy: Policy,
    compiled: list[re.Pattern[str]],
    reasons: list[Reason],
    actions: list[str],
) -> tuple[bool, bool]:
    blocked = False
    stripped = False
    cleaned: list[Any] = []

    for index, item in enumerate(items):
        path = f"{list_key}[{index}]"
        if not isinstance(item, dict):
            reasons.append(
                Reason(
                    code="invalid_item",
                    message=f"{list_key} entry must be an object.",
                    field=path,
                    detail=type(item).__name__,
                )
            )
            if policy.fail_closed:
                blocked = True
                cleaned.append(item)
            else:
                stripped = True
                actions.append(f"dropped_invalid_{list_key}_item")
            continue

        entry = copy.deepcopy(item)
        for field_name, max_len, overlong_code in (
            ("name", policy.max_name_len, "name_overlong"),
            ("description", policy.max_description_len, "description_overlong"),
        ):
            value = entry.get(field_name)
            if value is None:
                continue
            if not isinstance(value, str):
                reasons.append(
                    Reason(
                        code="invalid_field",
                        message=f"{field_name} must be a string.",
                        field=f"{path}.{field_name}",
                        detail=type(value).__name__,
                    )
                )
                if policy.fail_closed:
                    blocked = True
                else:
                    entry[field_name] = ""
                    stripped = True
                    actions.append(f"cleared_nonstring_{list_key}_{field_name}")
                continue

            hit = _first_match(value, compiled)
            if hit:
                reasons.append(
                    Reason(
                        code=f"{field_name}_blocklist",
                        message=(
                            f"{list_key} {field_name} matched an obvious "
                            "injection pattern."
                        ),
                        field=f"{path}.{field_name}",
                        detail=hit.pattern,
                    )
                )
                if policy.fail_closed:
                    blocked = True
                else:
                    entry[field_name] = ""
                    stripped = True
                    actions.append(f"stripped_poisoned_{list_key}_{field_name}")
                    value = ""

            if isinstance(value, str) and len(value) > max_len:
                reasons.append(
                    Reason(
                        code=overlong_code,
                        message=(
                            f"{list_key} {field_name} length {len(value)} "
                            f"exceeds max {max_len}."
                        ),
                        field=f"{path}.{field_name}",
                        detail=str(len(value)),
                    )
                )
                if policy.fail_closed:
                    blocked = True
                else:
                    entry[field_name] = value[:max_len]
                    stripped = True
                    actions.append(f"truncated_{list_key}_{field_name}")

        if policy.isolate_untrusted and isinstance(entry.get("description"), str):
            desc = entry["description"]
            if desc and not desc.startswith(ISOLATION_PREFIX):
                entry["description"] = _isolate(desc)
                actions.append(f"isolated_{list_key}_description")
                # Isolation alone does not flip the verdict.

        cleaned.append(entry)

    body[list_key] = cleaned
    return blocked, stripped
