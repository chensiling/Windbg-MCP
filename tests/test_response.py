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
    validate_module_name,
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
        assert result.schema_version == "2.0"
        assert result.core_result_status == "usable"
        assert result.sources[0].raw == ""
        assert result.sources[0].raw_size == 1
        assert result.sources[0].raw_included is False
        assert result.sources[0].command_id
        assert result.raw == ""

    def test_source_can_explicitly_include_raw_output(self):
        parsed = ParseResult("complete", {"value": "0x1"}, "raw", [], [])
        source = source_item(
            "? 1",
            _completed("raw"),
            parsed,
            include_raw=True,
        )

        assert source.raw == "raw"
        assert source.raw_included is True
        assert source.raw_size == 3

    def test_source_item_bounds_async_output_but_preserves_engine_evidence(self):
        async_output = "HEAD:" + ("x" * 2_500) + ":TAIL"
        execution = ExecutionResult(
            status="completed",
            output="command output",
            complete=True,
            async_output=async_output,
        )

        source = source_item("r", execution)

        assert len(source.async_output) == 2_000
        assert source.async_output.startswith("HEAD:")
        assert source.async_output.endswith(":TAIL")
        assert "...[ASYNC OUTPUT TRUNCATED]..." in source.async_output
        assert source.warnings == ["async_output_truncated"]
        assert execution.async_output == async_output

    def test_source_item_preserves_short_async_output(self):
        execution = ExecutionResult(
            status="completed",
            output="command output",
            complete=True,
            async_output="short asynchronous output",
        )

        source = source_item("r", execution)

        assert source.async_output == "short asynchronous output"
        assert source.warnings == []

    def test_source_item_merges_parse_and_async_output_warnings(self):
        execution = ExecutionResult(
            status="completed",
            output="parsed output\nextra",
            complete=True,
            async_output="a" * 2_001,
        )
        parsed = ParseResult(
            "partial",
            {"value": "0x1"},
            execution.output,
            ["extra"],
            ["unparsed_lines"],
        )

        source = source_item("? 1", execution, parsed)

        assert source.warnings == [
            "unparsed_lines",
            "async_output_truncated",
        ]

    @pytest.mark.parametrize(
        ("parse_status", "expected_ok"),
        [("complete", True), ("partial", True), ("failed", False)],
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
        if parse_status == "partial":
            assert result.errors == []
            assert result.warnings[0].code == "parse_partial"
            assert result.core_result_status == "usable"
        elif not expected_ok:
            assert result.errors[0].stage == "parsing"

    def test_aggregate_preserves_each_source_and_has_no_ambiguous_raw(self):
        first = source_item("r", _completed("register raw"))
        second = source_item("kP 0n30", _completed("stack raw"))

        result = make_response("windbg_analyze", [first, second], {"scope": "crash"})

        assert [source.command for source in result.sources] == ["r", "kP 0n30"]
        assert [source.raw for source in result.sources] == ["", ""]
        assert [source.raw_size for source in result.sources] == [12, 9]
        assert all(source.command_id for source in result.sources)
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
        assert result.core_result_status == "unavailable"
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
        assert result.core_result_status == "unavailable"
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

    @pytest.mark.parametrize("value", ["-f nt", "nt other", "nt!KeBugCheck"])
    def test_module_name_rejects_flags_extra_arguments_and_symbols(self, value):
        error = validate_module_name(value)

        assert error is not None
        assert error.code == "invalid_argument"

    @pytest.mark.parametrize("value", ["nt", "my-driver.sys", "win32kbase"])
    def test_module_name_accepts_one_bounded_module_token(self, value):
        assert validate_module_name(value) is None

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
