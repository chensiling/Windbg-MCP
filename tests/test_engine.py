import io
import signal
import time

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
        assert result.session_state == "draining"
        assert result.cancellation_status == "unsupported"
        assert result.command_id

    def test_timeout_interrupts_old_command_before_accepting_next_command(self):
        engine = SubprocessEngine(interrupt_timeout=0.1)
        proc = _FakeProcess()
        flush_count = 0
        signals = []

        def on_flush():
            nonlocal flush_count
            flush_count += 1
            if flush_count == 1:
                engine._output_queue.put("old partial output\n")
            else:
                engine._output_queue.put("fresh command output\n")
                engine._output_queue.put(f"{_marker_from_last_write(proc)}\n")

        def send_signal(value):
            signals.append(value)
            engine._output_queue.put("old output after timeout\n")
            engine._output_queue.put(f"{_marker_from_last_write(proc)}\n")

        proc.stdin = _FakeStdin(on_flush)
        proc.send_signal = send_signal
        engine._proc = proc
        engine._connected = True

        timed_out = engine.execute("lm t n", timeout=0.01)
        following = engine.execute("? 1+1", timeout=0.1)

        assert signals == [signal.CTRL_BREAK_EVENT]
        assert timed_out.status == "timeout"
        assert timed_out.complete is True
        assert timed_out.cancellation_status == "confirmed"
        assert timed_out.session_state == "idle"
        assert timed_out.output == (
            "old partial output\nold output after timeout\n"
        )
        assert following.status == "completed"
        assert following.output == "fresh command output\n"
        assert "old" not in following.output

    def test_uninterruptible_timeout_blocks_until_old_marker_is_drained(self):
        engine = SubprocessEngine(interrupt_timeout=0.01)
        proc = _FakeProcess()
        flush_count = 0

        def on_flush():
            nonlocal flush_count
            flush_count += 1
            if flush_count == 1:
                engine._output_queue.put("old partial output\n")
            else:
                engine._output_queue.put("fresh output\n")
                engine._output_queue.put(f"{_marker_from_last_write(proc)}\n")

        proc.stdin = _FakeStdin(on_flush)
        engine._proc = proc
        engine._connected = True

        timed_out = engine.execute("lm t n", timeout=0.01)
        writes_after_timeout = len(proc.stdin.writes)
        blocked = engine.execute("? 1+1", timeout=0.1)

        assert timed_out.status == "timeout"
        assert timed_out.session_state == "draining"
        assert blocked.status == "busy"
        assert blocked.command_id == timed_out.command_id
        assert len(proc.stdin.writes) == writes_after_timeout

        engine._output_queue.put("old late output\n")
        engine._output_queue.put(
            f"{native_engine.MARKER_PREFIX}{timed_out.command_id}__\n"
        )
        deadline = time.monotonic() + 0.5
        while engine.session_snapshot().state != "idle":
            assert time.monotonic() < deadline
            time.sleep(0.005)

        following = engine.execute("? 1+1", timeout=0.1)

        assert following.status == "completed"
        assert following.output == "fresh output\n"
        assert "old" not in following.output

    def test_timeout_policy_can_leave_running_command_for_explicit_interrupt(self):
        engine = SubprocessEngine(interrupt_timeout=0.01)
        engine, proc = _connected_engine(
            lambda: engine._output_queue.put("target running\n")
        )

        result = engine.execute(
            "g",
            timeout=0.01,
            cancel_on_timeout=False,
        )

        assert result.status == "timeout"
        assert result.session_state == "draining"
        assert result.cancellation_status == "not_requested"
        assert result.output == "target running\n"
        assert len(proc.stdin.writes) == 1

    def test_running_target_can_be_interrupted_and_followed_by_fresh_command(self):
        engine = SubprocessEngine(interrupt_timeout=0.1)
        proc = _FakeProcess()
        flush_count = 0
        signals = []

        def on_flush():
            nonlocal flush_count
            flush_count += 1
            if flush_count == 1:
                engine._output_queue.put("target resumed\n")
            else:
                engine._output_queue.put("fresh output\n")
                engine._output_queue.put(f"{_marker_from_last_write(proc)}\n")

        def send_signal(value):
            signals.append(value)
            engine._output_queue.put("break-in output\n")
            engine._output_queue.put(
                f"{native_engine.MARKER_PREFIX}{running.command_id}__\n"
            )

        proc.stdin = _FakeStdin(on_flush)
        proc.send_signal = send_signal
        engine._proc = proc
        engine._connected = True

        running = engine.execute("g", timeout=0.01, cancel_on_timeout=False)

        assert engine.interrupt(running.command_id) is True
        deadline = time.monotonic() + 0.5
        while engine.session_snapshot().state != "idle":
            assert time.monotonic() < deadline
            time.sleep(0.005)

        following = engine.execute("? 1+1", timeout=0.1)

        assert signals == [signal.CTRL_BREAK_EVENT]
        assert following.status == "completed"
        assert following.output == "fresh output\n"
        assert "break-in" not in following.output

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

    def test_accepts_repeated_prompts_before_marker(self):
        engine = None
        proc = None

        def complete_command():
            marker = _marker_from_last_write(proc)
            engine._output_queue.put(f"2: kd> 2: kd> {marker}\n")

        engine, proc = _connected_engine(complete_command)

        result = engine.execute("x nt!DefinitelyMissingSymbol", timeout=0.1)

        assert result.status == "completed"
        assert result.complete is True
        assert result.output == ""

    def test_preserves_output_observed_before_command(self):
        engine = None
        proc = None

        def complete_command():
            engine._output_queue.put("command output\n")
            engine._output_queue.put(f"{_marker_from_last_write(proc)}\n")

        engine, proc = _connected_engine(complete_command)
        engine._pending_async_output = "debugger startup output\n"
        engine._output_queue.put("asynchronous break event\n")

        result = engine.execute("r", timeout=0.1)

        assert result.status == "completed"
        assert result.output == "command output\n"
        assert result.async_output == (
            "debugger startup output\nasynchronous break event\n"
        )

    def test_startup_marker_separates_initial_output(self):
        engine, proc = _connected_engine()
        marker = engine._new_marker()
        engine._output_queue.put("debugger banner\n")
        engine._output_queue.put("Loading Symbols\n")
        engine._output_queue.put(f"0: kd> {marker}\n")

        startup_output = engine._wait_for_startup_marker(
            marker,
            0.1,
            proc,
            engine._output_queue,
        )

        assert startup_output == "debugger banner\nLoading Symbols\n"
        assert engine._output_queue.empty()

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

    def test_stale_reader_cannot_disconnect_replacement_process(self):
        engine, old_proc = _connected_engine()
        replacement = _FakeProcess()
        with engine._state_lock:
            engine._proc = replacement
            engine._connected = True
            engine._state = "idle"

        engine._mark_disconnected(old_proc)

        snapshot = engine.session_snapshot()
        assert snapshot.connected is True
        assert snapshot.state == "idle"
        assert engine._proc is replacement

    def test_queued_marker_survives_reader_disconnect_state_update(self):
        engine = None
        proc = None

        def complete_then_disconnect():
            engine._output_queue.put(f"{_marker_from_last_write(proc)}\n")
            engine._mark_disconnected(proc, preserve_active_command=True)

        engine, proc = _connected_engine(complete_then_disconnect)

        result = engine.execute("r", timeout=0.1)

        assert result.status == "completed"
        assert result.complete is True
        assert result.session_state == "disconnected"
        assert engine.session_snapshot().active_command_id is None

    def test_queued_cancel_marker_keeps_confirmation_after_reader_disconnect(self):
        engine = SubprocessEngine(interrupt_timeout=0.1)
        proc = _FakeProcess()

        def send_signal(_value):
            engine._output_queue.put(f"{_marker_from_last_write(proc)}\n")
            engine._mark_disconnected(proc, preserve_active_command=True)

        proc.send_signal = send_signal
        engine._proc = proc
        engine._connected = True

        result = engine.execute("lm t n", timeout=0.01)

        assert result.status == "timeout"
        assert result.complete is True
        assert result.cancellation_status == "confirmed"
        assert result.session_state == "disconnected"
        assert engine.session_snapshot().active_command_id is None

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

    def execute(self, command, timeout=30.0, *, cancel_on_timeout=True):
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
    def test_passes_configured_timeout_without_replaying_submitted_command(
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

        assert engine.calls == [("r", 1.25)]
        assert engine.disconnect_count == 0
        assert engine.connect_count == 0
        assert result.status == "timeout"
        assert result.output == "partial\n"
        assert result.attempts == 1
        assert result.session_restarted is False

    def test_retries_only_proven_pre_submission_disconnect(self, monkeypatch):
        monkeypatch.setattr(executor_module.time, "sleep", lambda _: None)
        engine = _ScriptedEngine(
            [
                ExecutionResult(
                    status="disconnected",
                    error="not connected",
                    attempts=0,
                    session_state="disconnected",
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
        assert result.output == "rax=1\n"
        assert result.attempts == 1
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
