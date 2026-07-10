import pytest

from src.debugger.engine import ExecutionResult
from src.server import _DebugExecutor, _parse_connect


@pytest.mark.parametrize(
    ("connect_string", "expected"),
    [
        ("tcp:localhost:50000", ("localhost", 50000)),
        ("tcp:50001", ("127.0.0.1", 50001)),
    ],
)
def test_parse_connect_forms(connect_string, expected):
    assert _parse_connect(connect_string, 50000) == expected


def test_parse_connect_rejects_invalid_port():
    with pytest.raises(ValueError, match="between 1 and 65535"):
        _parse_connect("tcp:70000", 50000)


def test_debug_executor_preserves_execution_result(capsys):
    expected = ExecutionResult(
        status="timeout",
        output="partial output",
        error="command timed out",
    )

    class _Executor:
        def execute(self, command, **policy):
            assert command == "r"
            assert policy == {"read_only": True, "retryable": True}
            return expected

    result = _DebugExecutor(_Executor()).execute(
        "r",
        read_only=True,
        retryable=True,
    )

    assert result is expected
    assert '"status": "timeout"' in capsys.readouterr().out
