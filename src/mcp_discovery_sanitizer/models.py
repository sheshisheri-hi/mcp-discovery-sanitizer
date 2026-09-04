"""Policy, verdict, and result types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Mapping

from mcp_discovery_sanitizer.patterns import DEFAULT_BLOCK_PATTERNS

Verdict = Literal["allow", "allow_stripped", "block"]


@dataclass(frozen=True)
class Policy:
    """Knobs for one sanitizer pass.

    ``allow_public_cache`` defaults to False: an untrusted server that
    sets ``cacheScope: public`` is refused (fail-closed) or downgraded
    (fail-open). Trusted ids skip that cache check only; instructions
    and tool text are still bounded.
    """

    max_instructions_len: int = 1024
    max_description_len: int = 512
    max_name_len: int = 128
    allow_public_cache: bool = False
    trusted_server_ids: frozenset[str] = field(default_factory=frozenset)
    block_patterns: tuple[str, ...] = DEFAULT_BLOCK_PATTERNS
    fail_closed: bool = True
    isolate_untrusted: bool = True

    def is_trusted(self, server_id: str | None) -> bool:
        if not server_id:
            return False
        return server_id in self.trusted_server_ids

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> Policy:
        """Build a Policy from a JSON-ish dict. Unknown keys are ignored."""
        if not data:
            return cls()
        kwargs: dict[str, Any] = {}
        if "max_instructions_len" in data:
            kwargs["max_instructions_len"] = int(data["max_instructions_len"])
        if "max_description_len" in data:
            kwargs["max_description_len"] = int(data["max_description_len"])
        if "max_name_len" in data:
            kwargs["max_name_len"] = int(data["max_name_len"])
        if "allow_public_cache" in data:
            kwargs["allow_public_cache"] = bool(data["allow_public_cache"])
        if "trusted_server_ids" in data:
            kwargs["trusted_server_ids"] = frozenset(
                str(x) for x in data["trusted_server_ids"]
            )
        if "block_patterns" in data:
            kwargs["block_patterns"] = tuple(str(x) for x in data["block_patterns"])
        if "fail_closed" in data:
            kwargs["fail_closed"] = bool(data["fail_closed"])
        if "isolate_untrusted" in data:
            kwargs["isolate_untrusted"] = bool(data["isolate_untrusted"])
        return cls(**kwargs)


@dataclass(frozen=True)
class Reason:
    """One explainable finding. ``field`` is a dotted path when possible."""

    code: str
    message: str
    field: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True)
class SanitizerResult:
    """What a gateway should persist and what it may forward."""

    verdict: Verdict
    reasons: tuple[Reason, ...]
    sanitized: dict[str, Any] | None
    original_hash: str
    sanitized_hash: str | None
    actions: tuple[str, ...] = ()
    server_id: str | None = None
    envelope: bool = False

    @property
    def allowed(self) -> bool:
        return self.verdict in ("allow", "allow_stripped")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reasons": [r.to_dict() for r in self.reasons],
            "sanitized": self.sanitized,
            "original_hash": self.original_hash,
            "sanitized_hash": self.sanitized_hash,
            "actions": list(self.actions),
            "server_id": self.server_id,
            "envelope": self.envelope,
        }
