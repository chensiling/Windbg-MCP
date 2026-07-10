import io

import pytest

from src.debugger.engine import (
    DebugEngine,
    ExecutionContractError,
    ExecutionResult,
)
from src.debugger.executor import CommandExecutor
from src.debugger import executor as executor_module
from src.debugger import native_engine
from src.debugger.native_engine import SubprocessEngine, _StreamClosed
from src.tools import _registry


class _FakeStdin:
    def __init__(self, on_flush=None):
        self.writes = []
        self._on_flush = on_flush

    def write(self, value):
        self.writes.append(value)

    def flush(self):
        if self._on_flush is not None:
            self._on_flush()


class _FakeProcess:
    def __init__(self, stdin=None, stdout=None):
        self.stdin = stdin or _FakeStdin()
        self.stdout = stdout or io.StringIO("")
        self.pid = 1234
        self._returncode = None

    def poll(self):
        return self._returncode


def _connected_engine(on_flush=None):
    engine = SubprocessEngine()
    proc = _FakeProcess()
    proc.stdin = _FakeStdin(on_flush)
    engine._proc = proc
    engine._connected = True
    return engine, proc


def _marker_from_last_write(proc):
    marker_command = proc.stdin.writes[-1].splitlines()[-1]
    marker_with_newline = marker_command.split('"')[1]
    return marker_with_newline.removesuffix(r"\n")


class TestSubprocessEngine:
    def test_timeout_preserves_partial_output(self):
        engine = None

        def emit_partial():
            engine._output_queue.put("partial register output\n")

        engine, _ = _connected_engine(emit_partial)

        result = engine.execute("r", timeout=0.01)

        assert result.status == "timeout"
        assert result.output == "partial register output\n"
        assert result.complete is False
        assert result.error is not None
        assert result.attempts == 1

    def test_uses_unique_command_markers_and_requires_marker_line(self, monkeypatch):
        tokens = iter(["1" * 32, "2" * 32])
        monkeypatch.setattr(native_engine.secrets, "token_hex", lambda _: next(tokens))
        engine = None
        proc = None

        def complete_command():
            marker = _marker_from_last_write(proc)
            engine._output_queue.put(f"ordinary text containing {marker}\n")
            engine._output_queue.put(f"{marker}\n")

        engine, proc = _connected_engine(complete_command)

        first = engine.execute("r", timeout=0.1)
        second = engine.execute("k", timeout=0.1)

        assert first.complete is True
        assert second.complete is True
        assert "ordinary text containing" in first.output
        first_marker = _marker_from_write(proc.stdin.writes[0])
        second_marker = _marker_from_write(proc.stdin.writes[1])
        assert first_marker != second_marker
        assert first_marker.startswith(native_engine.MARKER_PREFIX)

    @pytest.mark.parametrize(
        "prompt",
        ["0:000> ", "0:000:x86> ", "0: kd> ", "kd> "],
    )
    def test_accepts_real_user_and_kernel_prompt_markers(self, prompt):
        engine = None
        proc = None

        def complete_command():
            marker = _marker_from_last_write(proc)
            engine._output_queue.put("command output\n")
            engine._output_queue.put(f"{prompt}{marker}\n")

        engine, proc = _connected_engine(complete_command)

        result = engine.execute("r", timeout=0.1)

        assert result.status == "completed"
        assert result.complete is True
        assert result.output == "command output\n"
        assert native_engine.MARKER_PREFIX not in result.output

    def test_preserves_output_observed_before_command(self):
        engine = None
        proc = None

        def complete_command():
            engine._output_queue.put("command output\n")
            engine._output_queue.put(f"{_marker_from_last_write(proc)}\n")

        engine, proc = _connected_engine(complete_command)
        engine._output_queue.put("asynchronous break event\n")

        result = engine.execute("r", timeout=0.1)

        assert result.status == "completed"
        assert result.output == "command output\n"
        assert result.async_output == "asynchronous break event\n"

    def test_eof_returns_partial_output_and_clears_connection(self):
        engine = None
        proc = None

        def close_stream():
            engine._output_queue.put("partial before EOF\n")
            engine._mark_disconnected(proc)
            engine._output_queue.put(_StreamClosed())

        engine, proc = _connected_engine(close_stream)

        result = engine.execute("r", timeout=0.1)

        assert result.status == "disconnected"
        assert result.output == "partial before EOF\n"
        assert result.complete is False
        assert engine.connected is False

    def test_reader_eof_clears_connected_state(self):
        engine, proc = _connected_engine()
        output_queue = engine._output_queue

        engine._read_loop(proc, output_queue)

        assert engine.connected is False
        assert isinstance(output_queue.get_nowait(), _StreamClosed)

    @pytest.mark.parametrize("through_executor", [False, True])
    def test_eof_before_request_preserves_async_output(self, through_executor):
        engine, _ = _connected_engine()
        engine._output_queue.put("async before EOF\n")
        engine._output_queue.put(_StreamClosed())
        engine._connected = False

        if through_executor:
            result = CommandExecutor(engine).execute("r")
        else:
            result = engine.execute("r")

        assert result.status == "disconnected"
        assert result.async_output == "async before EOF\n"
        assert result.error == "debugger output stream reached EOF"
        assert result.attempts == 0
        assert result.complete is False
        assert engine.connected is False
        assert engine._output_queue.empty()

    def test_marker_generation_failure_is_proven_pre_submission(self, monkeypatch):
        engine, proc = _connected_engine()
        calls = []

        def fail_marker():
            calls.append(True)
            raise RuntimeError("entropy unavailable")

        monkeypatch.setattr(engine, "_new_marker", fail_marker)
        executor = CommandExecutor(engine, max_retries=3)

        result = executor.execute("eb 0x1000 90")

        assert result.status == "failed"
        assert result.attempts == 0
        assert result.error == (
            "could not create command completion marker: entropy unavailable"
        )
        assert proc.stdin.writes == []
        assert len(calls) == 1

    @pytest.mark.parametrize("failure_stage", ["write", "flush"])
    def test_ambiguous_submission_failure_is_indeterminate_and_not_replayed(
        self,
        failure_stage,
    ):
        class _FailingStdin(_FakeStdin):
            def write(self, value):
                self.writes.append(value)
                if failure_stage == "write":
                    raise BrokenPipeError("pipe closed during write")

            def flush(self):
                if failure_stage == "flush":
                    raise BrokenPipeError("pipe closed during flush")

        engine, proc = _connected_engine()
        proc.stdin = _FailingStdin()
        executor = CommandExecutor(engine, max_retries=3)

        result = executor.execute("eb 0x1000 90")

        assert result.status == "indeterminate"
        assert result.attempts == 1
        assert result.complete is False
        assert len(proc.stdin.writes) == 1
        assert engine.connected is False


def _marker_from_write(value):
    marker_command = value.splitlines()[-1]
    return marker_command.split('"')[1].removesuffix(r"\n")


class _ScriptedEngine(DebugEngine):
    def __init__(self, results):
        self.results = list(results)
        self.calls = []
        self.disconnect_count = 0
        self.connect_count = 0
        self._connected = True

    def execute(self, command, timeout=30.0):
        self.calls.append((command, timeout))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def connect(self):
        self.connect_count += 1
        self._connected = True

    def disconnect(self):
        self.disconnect_count += 1
        self._connected = False

    @property
    def connected(self):
        return self._connected

    @property
    def target_running(self):
        return False


class TestCommandExecutor:
    def test_passes_configured_timeout_and_retries_explicit_read_only_command(
        self,
        monkeypatch,
    ):
        monkeypatch.setattr(executor_module.time, "sleep", lambda _: None)
        engine = _ScriptedEngine(
            [
                ExecutionResult(
                    status="timeout",
                    output="partial\n",
                    error="timed out",
                ),
                ExecutionResult(
                    status="completed",
                    output="rax=1\n",
                    complete=True,
                ),
            ]
        )
        executor = CommandExecutor(engine, timeout=1.25, max_retries=2)

        result = executor.execute("r", read_only=True, retryable=True)

        assert engine.calls == [("r", 1.25), ("r", 1.25)]
        assert engine.disconnect_count == 1
        assert engine.connect_count == 1
        assert result.status == "completed"
        assert result.output == "partial\nrax=1\n"
        assert result.attempts == 2
        assert result.session_restarted is True

    @pytest.mark.parametrize(
        ("read_only", "retryable"),
        [(False, False), (False, True), (True, False)],
    )
    def test_does_not_replay_without_both_retry_flags(
        self,
        read_only,
        retryable,
    ):
        engine = _ScriptedEngine(
            [
                ExecutionResult(
                    status="indeterminate",
                    error="submission outcome unknown",
                )
            ]
        )
        executor = CommandExecutor(engine, max_retries=3)

        result = executor.execute(
            "eb 0x1000 90",
            read_only=read_only,
            retryable=retryable,
        )

        assert len(engine.calls) == 1
        assert engine.disconnect_count == 0
        assert result.status == "indeterminate"
        assert result.attempts == 1

    def test_engine_exception_is_a_contract_error_and_is_not_replayed(self):
        engine = _ScriptedEngine([RuntimeError("engine implementation failed")])
        executor = CommandExecutor(engine, max_retries=3)

        with pytest.raises(ExecutionContractError):
            executor.execute("eb 0x1000 90")

        assert len(engine.calls) == 1
        assert engine.disconnect_count == 0

    def test_rejects_invalid_result_returned_by_engine(self):
        invalid = ExecutionResult(
            status="completed",
            output="r",
            complete=True,
        )
        object.__setattr__(invalid, "complete", False)
        engine = _ScriptedEngine([invalid])

        with pytest.raises(
            ExecutionContractError,
            match="invalid ExecutionResult",
        ):
            CommandExecutor(engine).execute("r")

    @pytest.mark.parametrize(
        "result",
        [
            ExecutionResult(status="completed", complete=True),
            ExecutionResult(status="timeout", error="timed out"),
            ExecutionResult(
                status="indeterminate",
                error="submission outcome unknown",
            ),
        ],
    )
    def test_rejects_zero_attempt_submission_result_from_engine(self, result):
        object.__setattr__(result, "attempts", 0)
        engine = _ScriptedEngine([result])

        with pytest.raises(
            ExecutionContractError,
            match="invalid ExecutionResult",
        ):
            CommandExecutor(engine).execute("r")


class TestExecutionResultValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"status": "unknown", "error": "bad status"},
            {"status": "timeout", "error": "timed out", "attempts": -1},
            {
                "status": "timeout",
                "error": "timed out",
                "complete": True,
            },
            {"status": "completed", "complete": False},
            {"status": "completed", "complete": True, "attempts": 0},
            {"status": "timeout", "error": "timed out", "attempts": 0},
            {
                "status": "indeterminate",
                "error": "submission outcome unknown",
                "attempts": 0,
            },
            {
                "status": "completed",
                "complete": True,
                "error": "contradictory error",
            },
            {"status": "failed"},
        ],
    )
    def test_rejects_semantically_invalid_results(self, kwargs):
        with pytest.raises((TypeError, ValueError)):
            ExecutionResult(**kwargs)

    @pytest.mark.parametrize("status", ["failed", "disconnected"])
    def test_pre_submission_failure_statuses_allow_zero_attempts(self, status):
        result = ExecutionResult(
            status=status,
            error="failure before command submission",
            attempts=0,
        )

        assert result.attempts == 0


class TestRegistryCompatibility:
    def test_legacy_entry_returns_text_and_result_entry_preserves_status(
        self,
        monkeypatch,
    ):
        class _Executor:
            def execute(self, command, **policy):
                return ExecutionResult(
                    status="completed",
                    output=f"output for {command}",
                    complete=True,
                )

        monkeypatch.setattr(_registry, "_executor", _Executor())

        assert _registry._exec("r") == "output for r"
        assert _registry._exec_result("r").status == "completed"

    def test_legacy_entry_exposes_incomplete_result_as_error(self, monkeypatch):
        class _Executor:
            def execute(self, command, **policy):
                return ExecutionResult(
                    status="timeout",
                    output="partial",
                    error="command timed out",
                )

        monkeypatch.setattr(_registry, "_executor", _Executor())

        raw = _registry._exec("r")

        assert raw.startswith("error: command timed out")
        assert "partial" in raw

    def test_result_entry_revalidates_executor_result(self, monkeypatch):
        invalid = ExecutionResult(
            status="completed",
            output="r",
            complete=True,
        )
        object.__setattr__(invalid, "attempts", -1)

        class _Executor:
            def execute(self, command, **policy):
                return invalid

        monkeypatch.setattr(_registry, "_executor", _Executor())

        with pytest.raises(
            ExecutionContractError,
            match="invalid ExecutionResult",
        ):
            _registry._exec_result("r")
