import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from debugger.engine import ExecutionResult
from tools._models import ToolEnvelope, ToolError
from tools._parser import ParseResult
from tools._response import (
    error_item,
    make_error,
    make_response,
    next_action,
    parse_int_arg,
    source_item,
    validate_intent_text,
)


def _completed(output: str = "output") -> ExecutionResult:
    return ExecutionResult(
        status="completed",
        output=output,
        complete=True,
    )


class TestResponseEnvelope:
    def test_make_response_returns_pydantic_model(self):
        parsed = ParseResult("complete", {"registers": {"rip": "0x1"}}, "r", [], [])
        source = source_item("r", _completed("r"), parsed)

        result = make_response(
            "windbg_context",
            [source],
            data=dict(parsed.data),
            next_actions=[next_action(
                "windbg_backtrace",
                {"depth": "30"},
                "Inspect the stack.",
            )],
        )

        assert isinstance(result, ToolEnvelope)
        assert result.ok is True
        assert result.execution_status == "completed"
        assert result.parse_status == "complete"
        assert result.verification_status == "not_required"
        assert result.data["registers"]["rip"] == "0x1"
        assert result.sources[0].raw == "r"
        assert result.raw == "r"

    @pytest.mark.parametrize(
        ("parse_status", "expected_ok"),
        [("complete", True), ("partial", False), ("failed", False)],
    )
    def test_maps_every_parse_status(self, parse_status, expected_ok):
        if parse_status == "complete":
            parsed = ParseResult("complete", {"value": "0x1"}, "raw", [], [])
        elif parse_status == "partial":
            parsed = ParseResult(
                "partial",
                {"value": "0x1"},
                "raw\nextra",
                ["extra"],
                ["unparsed_lines"],
            )
        else:
            parsed = ParseResult(
                "failed",
                {},
                "garbage",
                ["garbage"],
                ["no_recognized_output"],
            )
        source = source_item("? 1", _completed(parsed.raw), parsed)

        result = make_response("windbg_evaluate", [source], dict(parsed.data))

        assert result.parse_status == parse_status
        assert result.ok is expected_ok
        assert result.data == dict(parsed.data)
        assert result.sources[0].unparsed_lines == list(parsed.unparsed_lines)
        if not expected_ok:
            assert result.errors[0].stage == "parsing"

    def test_aggregate_preserves_each_source_and_has_no_ambiguous_raw(self):
        first = source_item("r", _completed("register raw"))
        second = source_item("kP 0n30", _completed("stack raw"))

        result = make_response("windbg_analyze", [first, second], {"scope": "crash"})

        assert [source.command for source in result.sources] == ["r", "kP 0n30"]
        assert [source.raw for source in result.sources] == ["register raw", "stack raw"]
        assert result.raw == ""

    def test_execution_and_verification_status_are_independent(self):
        timed_out = ExecutionResult(
            status="timeout",
            output="partial",
            error="timed out",
        )

        result = make_response(
            "windbg_control",
            [source_item("g", timed_out)],
            {"target_state": "running"},
            verification_status="verified",
        )

        assert result.execution_status == "timeout"
        assert result.parse_status == "not_run"
        assert result.verification_status == "verified"
        assert result.ok is False

    def test_make_error_has_typed_stage(self):
        result = make_error(
            "windbg_read_memory",
            "invalid_argument",
            "bad address",
        )

        assert isinstance(result, ToolEnvelope)
        assert isinstance(result.errors[0], ToolError)
        assert result.errors[0].stage == "input"
        assert result.execution_status == "not_run"
        assert result.ok is False

    def test_error_item_shape(self):
        item = error_item(
            "verification_failed",
            "bytes differ",
            recoverable=False,
            stage="verification",
        )
        assert item.model_dump() == {
            "code": "verification_failed",
            "message": "bytes differ",
            "stage": "verification",
            "recoverable": False,
        }


class TestInputHelpers:
    @pytest.mark.parametrize("value", ["@rip; g", "@rip\ng", "@rip\rg"])
    def test_rejects_command_composition(self, value):
        error = validate_intent_text(value, "address")
        assert error is not None
        assert error.code == "unsafe_argument"
        assert error.recoverable is False

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
        assert error is not None
        assert error.code == "invalid_argument"
