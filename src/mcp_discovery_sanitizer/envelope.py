"""Unwrap JSON-RPC envelopes without assuming a full MCP client."""

from __future__ import annotations

from typing import Any

# Keys that belong to a JSON-RPC request/response wrapper. If the payload
# only uses these, ``result`` (or ``error``) is the discovery object.
_ENVELOPE_KEYS = frozenset({"jsonrpc", "id", "result", "error", "method", "params"})


def unwrap_discovery(payload: Any) -> tuple[Any, Any, bool, bool]:
    """Return ``(envelope_or_payload, body, is_envelope, is_error)``.

    Accepts:
    - a raw result object (``initialize`` / ``tools/list`` / combined blob)
    - ``{"result": {...}}``
    - a JSON-RPC 2.0 response with ``result`` or ``error``
    """
    if not isinstance(payload, dict):
        return payload, payload, False, False

    keys = set(payload.keys())
    if "error" in payload and keys <= _ENVELOPE_KEYS and "result" not in payload:
        return payload, payload.get("error"), True, True

    if "result" in payload and keys <= _ENVELOPE_KEYS:
        return payload, payload.get("result"), True, False

    return payload, payload, False, False


def rewrap(envelope: dict[str, Any], body: Any) -> dict[str, Any]:
    """Put a sanitized body back into a JSON-RPC-shaped envelope."""
    out = dict(envelope)
    out["result"] = body
    out.pop("error", None)
    return out
