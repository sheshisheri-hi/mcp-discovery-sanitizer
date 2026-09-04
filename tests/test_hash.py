from mcp_discovery_sanitizer.hashutil import canonical_dumps, canonical_hash
from mcp_discovery_sanitizer.sanitize import sanitize_discovery


def test_canonical_hash_is_key_order_independent():
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert canonical_dumps(a) == canonical_dumps(b)
    assert canonical_hash(a) == canonical_hash(b)
    assert canonical_hash(a).startswith("sha256:")
    assert len(canonical_hash(a)) == 7 + 64


def test_envelope_and_raw_share_original_hash():
    inner = {"instructions": "hello", "cacheScope": "private", "tools": []}
    raw = sanitize_discovery(inner)
    wrapped = sanitize_discovery({"jsonrpc": "2.0", "id": 1, "result": inner})
    assert raw.original_hash == wrapped.original_hash


def test_hash_changes_when_instructions_change():
    a = sanitize_discovery({"instructions": "one", "tools": []})
    b = sanitize_discovery({"instructions": "two", "tools": []})
    assert a.original_hash != b.original_hash
