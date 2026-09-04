# Fixtures

Sample MCP discovery blobs for tests and `examples/demo.py`.

| File | What it shows |
| --- | --- |
| `clean_discovery.json` | Honest weather server, private cache. Verdict: `allow`. |
| `poisoned_instructions.json` | JSON-RPC envelope with jailbreak `instructions`. Verdict: `block` (fail-closed). |
| `public_cache_untrusted.json` | `_meta.cacheScope: public` from an unknown server. Verdict: `block`. |
| `overlong_descriptions.json` | Tool / prompt / resource descriptions past default bounds. Verdict: `block` when fail-closed. |
| `policy_fail_open.json` | Policy that strips / downgrades instead of blocking. |
