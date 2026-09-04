from mcp_discovery_sanitizer.envelope import rewrap, unwrap_discovery


def test_raw_result_is_not_an_envelope():
    payload = {"instructions": "hi", "tools": []}
    envelope, body, is_envelope, is_error = unwrap_discovery(payload)
    assert envelope is payload
    assert body is payload
    assert is_envelope is False
    assert is_error is False


def test_bare_result_wrapper():
    inner = {"tools": [{"name": "a"}]}
    envelope, body, is_envelope, is_error = unwrap_discovery({"result": inner})
    assert is_envelope is True
    assert is_error is False
    assert body == inner


def test_jsonrpc_result_wrapper():
    inner = {"instructions": "ok"}
    payload = {"jsonrpc": "2.0", "id": 3, "result": inner}
    envelope, body, is_envelope, is_error = unwrap_discovery(payload)
    assert is_envelope is True
    assert is_error is False
    assert body is inner
    assert envelope is payload


def test_jsonrpc_error_wrapper():
    payload = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "no"}}
    envelope, body, is_envelope, is_error = unwrap_discovery(payload)
    assert is_envelope is True
    assert is_error is True
    assert body == {"code": -32000, "message": "no"}


def test_discovery_with_result_field_is_not_unwrapped():
    """A combined blob that happens to have extra keys stays raw."""
    payload = {"result": {"nested": True}, "tools": [], "instructions": "x"}
    _, body, is_envelope, _ = unwrap_discovery(payload)
    assert is_envelope is False
    assert body is payload


def test_rewrap_replaces_result_and_drops_error():
    envelope = {"jsonrpc": "2.0", "id": 1, "error": {"code": 1}}
    out = rewrap(envelope, {"tools": []})
    assert out["result"] == {"tools": []}
    assert "error" not in out
    assert envelope.get("error") == {"code": 1}
