"""Canonical JSON + SHA-256 for audit diffs."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_dumps(obj: Any) -> bytes:
    """Stable UTF-8 JSON: sorted keys, no extra whitespace.

    Used only for hashing. Sanitized payloads keep the caller's structure.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def canonical_hash(obj: Any) -> str:
    """Return ``sha256:<hex>`` of the canonical discovery blob."""
    digest = hashlib.sha256(canonical_dumps(obj)).hexdigest()
    return f"sha256:{digest}"
