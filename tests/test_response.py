import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from tools._response import error_item, make_error, make_response, parse_int_arg


class TestResponseEnvelope:
    def test_make_response_is_json(self):
        raw = make_response(
            "windbg_context",
            "r",
            data={"registers": {"rip": "0x1"}},
            next_actions=[{"tool": "windbg_backtrace", "args": {"depth": "30"}, "reason": "test"}],
        )
        payload = json.loads(raw)
        assert payload["ok"] is True
        assert payload["tool"] == "windbg_context"
        assert payload["data"]["registers"]["rip"] == "0x1"
        assert payload["next_actions"][0]["tool"] == "windbg_backtrace"

    def test_make_error(self):
        raw = make_error("windbg_read_memory", "dd @rip L1", "debugger_error", "error: not connected")
        payload = json.loads(raw)
        assert payload["ok"] is False
        assert payload["errors"][0]["code"] == "debugger_error"

    def test_error_item_shape(self):
        item = error_item("invalid_argument", "bad input", recoverable=False)
        assert item == {"code": "invalid_argument", "message": "bad input", "recoverable": False}


class TestParseIntArg:
    def test_decimal(self):
        value, error = parse_int_arg("16", "count", min_value=1, max_value=32)
        assert error is None
        assert value == 16

    def test_hex(self):
        value, error = parse_int_arg("0x10", "count", min_value=1, max_value=32)
        assert error is None
        assert value == 16

    def test_windbg_hex_suffix(self):
        value, error = parse_int_arg("10h", "count", min_value=1, max_value=32)
        assert error is None
        assert value == 16

    def test_too_large(self):
        value, error = parse_int_arg("0x1000", "count", min_value=1, max_value=32)
        assert value is None
        assert error["code"] == "invalid_argument"
