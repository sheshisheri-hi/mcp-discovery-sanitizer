from mcp_discovery_sanitizer.models import Policy
from mcp_discovery_sanitizer.patterns import DEFAULT_BLOCK_PATTERNS


def test_defaults():
    policy = Policy()
    assert policy.allow_public_cache is False
    assert policy.fail_closed is True
    assert policy.max_instructions_len == 1024
    assert policy.trusted_server_ids == frozenset()
    assert policy.block_patterns == DEFAULT_BLOCK_PATTERNS


def test_from_mapping_round_trip():
    policy = Policy.from_mapping(
        {
            "max_instructions_len": 50,
            "allow_public_cache": True,
            "trusted_server_ids": ["alpha", "beta"],
            "block_patterns": ["jailbreak"],
            "fail_closed": False,
            "unknown": "ignored",
        }
    )
    assert policy.max_instructions_len == 50
    assert policy.allow_public_cache is True
    assert policy.trusted_server_ids == frozenset({"alpha", "beta"})
    assert policy.block_patterns == ("jailbreak",)
    assert policy.fail_closed is False
    assert policy.is_trusted("alpha")
    assert not policy.is_trusted(None)


def test_from_mapping_empty():
    assert Policy.from_mapping(None) == Policy()
    assert Policy.from_mapping({}) == Policy()
