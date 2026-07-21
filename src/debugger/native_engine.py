from dataclasses import dataclass
import logging
import queue
import re
import secrets
import signal
import subprocess
import threading
import time
from typing import Optional, Union

from .engine import (
    CancellationStatus,
    DebugEngine,
    ExecutionResult,
    SessionSnapshot,
    SessionState,
)

logger = logging.getLogger(__name__)

KD_X64 = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe"
CDB_X64 = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
MARKER_PREFIX = "__MCP_END_"
_STARTUP_TIMEOUT = 30.0
_PROMPT_TOKEN = (
    r"(?:\d+:[0-9a-f]+(?::(?:x86|amd64|arm|arm64))?|\d+:\s*kd|kd)>"
)
_PROMPT_RE = re.compile(
    rf"^(?:{_PROMPT_TOKEN}\s*)+$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _StreamClosed:
    error: Optional[str] = None


@dataclass
class _ActiveCommand:
    command_id: str
    marker: str
    cancellation_status: CancellationStatus = "not_requested"
    cancellation_reason: Optional[str] = None


_QueueItem = Union[str, _StreamClosed]


class SubprocessEngine(DebugEngine):

    def __init__(self, debugger_exe: Optional[str] = None,
                 remote_host: str = "127.0.0.1", remote_port: int = 50000,
                 pid: Optional[int] = None, exe: Optional[str] = None,
                 dump: Optional[str] = None, cmd_args: str = "",
                 interrupt_timeout: float = 3.0):
        if interrupt_timeout <= 0:
            raise ValueError("interrupt_timeout must be greater than zero")
        self._exe = debugger_exe or KD_X64
        self._remote_host = remote_host
        self._remote_port = remote_port
        self._pid = pid
        self._exe_path = exe
        self._dump = dump
        self._cmd_args = cmd_args
        self._interrupt_timeout = interrupt_timeout
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._output_queue: queue.Queue[_QueueItem] = queue.Queue()
        self._reader_thread: Optional[threading.Thread] = None
        self._connected = False
        self._state: SessionState = "disconnected"
        self._active_command: Optional[_ActiveCommand] = None
        self._pending_async_output = ""

    @property
    def connected(self) -> bool:
        return self._connected and self._proc is not None

    @property
    def target_running(self) -> bool:
        return True

    def session_snapshot(self) -> SessionSnapshot:
        with self._state_lock:
            active_command_id = (
                self._active_command.command_id
                if self._active_command is not None
                else None
            )
            state = self._state
            proc = self._proc
            connected = self._connected and proc is not None
        return SessionSnapshot(
            state=state,
            connected=connected,
            active_command_id=active_command_id,
            interrupt_supported=connected and self._can_interrupt(proc),
        )

    def connect(self) -> None:
        startup_marker = self._new_marker()
        if self._exe_path:
            exe = CDB_X64
            args = [exe]
            if self._cmd_args:
                args.append(self._exe_path)
                args.extend(self._cmd_args.split())
            else:
                args.append(self._exe_path)
        elif self._pid is not None:
            exe = CDB_X64
            args = [exe, "-p", str(self._pid)]
        elif self._dump:
            exe = CDB_X64
            args = [exe, "-z", self._dump]
        else:
            exe = CDB_X64
            remote_str = f"tcp:port={self._remote_port},server={self._remote_host}"
            args = [exe, "-remote", remote_str]

        logger.info("spawning: %s", " ".join(args))
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            # CTRL_BREAK_EVENT requires a distinct console process group.
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        output_queue: queue.Queue[_QueueItem] = queue.Queue()
        with self._state_lock:
            self._proc = proc
            self._output_queue = output_queue
            self._connected = True
            self._active_command = None
            self._pending_async_output = ""
            self._state = "executing"
        self._reader_thread = threading.Thread(
            target=self._read_loop,
            args=(proc, output_queue),
            daemon=True,
        )
        self._reader_thread.start()
        try:
            if proc.stdin is None:
                raise ConnectionError("debugger process has no stdin pipe")
            with self._write_lock:
                proc.stdin.write(f'.printf "{startup_marker}\\n"\n')
                proc.stdin.flush()
            startup_output = self._wait_for_startup_marker(
                startup_marker,
                _STARTUP_TIMEOUT,
                proc,
                output_queue,
            )
        except Exception as e:
            try:
                self.disconnect()
            except Exception as disconnect_error:
                logger.warning(
                    "debugger cleanup after startup failure failed: %s",
                    disconnect_error,
                )
            raise ConnectionError(f"debugger subprocess startup failed: {e}") from e

        with self._state_lock:
            if self._proc is not proc or not self._connected:
                raise ConnectionError("debugger subprocess exited during startup")
            self._pending_async_output = startup_output
            self._state = "idle"
        logger.info("debugger subprocess started (pid %d)", proc.pid)

    def disconnect(self) -> None:
        with self._state_lock:
            proc = self._proc
            self._connected = False
            self._active_command = None
            self._pending_async_output = ""
            self._state = "disconnected"
        if proc:
            try:
                with self._write_lock:
                    proc.stdin.write("q\n")  # type: ignore
                    proc.stdin.flush()  # type: ignore
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        with self._state_lock:
            if self._proc is proc:
                self._proc = None

    def execute(
        self,
        command: str,
        timeout: float = 30.0,
        *,
        cancel_on_timeout: bool = True,
    ) -> ExecutionResult:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        with self._lock:
            with self._state_lock:
                if self._state == "disconnected" and self.connected:
                    # Tests and embedders may inject an already-connected process.
                    self._state = "idle"
                state = self._state
                active_command_id = (
                    self._active_command.command_id
                    if self._active_command is not None
                    else None
                )
            if state not in ("idle", "disconnected"):
                return ExecutionResult(
                    status="busy",
                    error=(
                        f"debugger command channel is {state}; "
                        "wait for recovery or explicitly recover the session"
                    ),
                    attempts=0,
                    command_id=active_command_id or "",
                    session_state=state,
                )

            with self._state_lock:
                pending_async_output = self._pending_async_output
                self._pending_async_output = ""
            proc = self._proc
            output_queue = self._output_queue
            queued_async_output, stream_closed = self._drain_queue(output_queue)
            async_output = pending_async_output + queued_async_output

            if stream_closed is not None:
                if proc is not None:
                    self._mark_disconnected(proc)
                return ExecutionResult(
                    status="disconnected",
                    error=stream_closed.error or "debugger output stream reached EOF",
                    attempts=0,
                    async_output=async_output,
                    session_state="disconnected",
                )

            if proc is None or not self.connected:
                return ExecutionResult(
                    status="disconnected",
                    error="not connected to debugger process",
                    attempts=0,
                    async_output=async_output,
                    session_state="disconnected",
                )

            if proc.stdin is None:
                return ExecutionResult(
                    status="failed",
                    error="debugger process has no stdin pipe",
                    attempts=0,
                    async_output=async_output,
                    session_state="idle",
                )

            try:
                marker = self._new_marker()
            except Exception as e:
                return ExecutionResult(
                    status="failed",
                    error=f"could not create command completion marker: {e}",
                    attempts=0,
                    async_output=async_output,
                    session_state="idle",
                )

            command_id = marker.removeprefix(MARKER_PREFIX).removesuffix("__")
            with self._state_lock:
                self._active_command = _ActiveCommand(command_id, marker)
                self._state = "executing"

            try:
                with self._write_lock:
                    proc.stdin.write(f"{command}\n.printf \"{marker}\\n\"\n")
                    proc.stdin.flush()
            except Exception as e:
                self._mark_disconnected(proc)
                return ExecutionResult(
                    status="indeterminate",
                    error=f"debugger process rejected command: {e}",
                    attempts=1,
                    async_output=async_output,
                    command_id=command_id,
                    session_state="disconnected",
                )

            return self._read_until_marker(
                marker,
                timeout,
                proc,
                output_queue,
                async_output,
                command_id,
                cancel_on_timeout,
            )

    def interrupt(self, command_id: Optional[str] = None) -> bool:
        return self._request_interrupt(command_id, reason="explicit") == "requested"

    @staticmethod
    def _new_marker() -> str:
        return f"{MARKER_PREFIX}{secrets.token_hex(16)}__"

    @staticmethod
    def _drain_queue(
        output_queue: queue.Queue[_QueueItem],
    ) -> tuple[str, Optional[_StreamClosed]]:
        lines = []
        stream_closed = None
        while True:
            try:
                item = output_queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, _StreamClosed):
                stream_closed = item
            else:
                lines.append(item)
        return "".join(lines), stream_closed

    def _read_loop(
        self,
        proc: subprocess.Popen,
        output_queue: queue.Queue[_QueueItem],
    ) -> None:
        read_error = None
        if proc.stdout is None:
            output_queue.put(_StreamClosed("debugger process has no stdout pipe"))
            self._mark_disconnected(proc)
            return
        try:
            for line in iter(proc.stdout.readline, ""):
                output_queue.put(line)
        except Exception as e:
            read_error = f"debugger output reader failed: {e}"
            logger.error("read_loop died: %s", e)
        finally:
            output_queue.put(_StreamClosed(read_error))
            # The marker may already be queued ahead of EOF. Preserve the
            # active command until its queue consumer observes that boundary.
            self._mark_disconnected(proc, preserve_active_command=True)

    def _wait_for_startup_marker(
        self,
        marker: str,
        timeout: float,
        proc: subprocess.Popen,
        output_queue: queue.Queue[_QueueItem],
    ) -> str:
        lines: list[str] = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0:
                    item = output_queue.get_nowait()
                else:
                    item = output_queue.get(timeout=min(0.05, remaining))
            except queue.Empty:
                if not self.connected:
                    self._mark_disconnected(proc)
                    raise ConnectionError(
                        "debugger output stream closed during startup"
                    )
                if remaining <= 0:
                    raise TimeoutError(
                        f"debugger startup timed out after {timeout:g} seconds"
                    )
                continue

            if isinstance(item, _StreamClosed):
                self._mark_disconnected(proc)
                raise ConnectionError(
                    item.error or "debugger output stream reached EOF during startup"
                )
            if self._is_completion_line(item, marker):
                return "".join(lines)
            lines.append(item)

    def _read_until_marker(
        self,
        marker: str,
        timeout: float,
        proc: subprocess.Popen,
        output_queue: queue.Queue[_QueueItem],
        async_output: str,
        command_id: str,
        cancel_on_timeout: bool,
    ) -> ExecutionResult:
        lines = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if not self.connected:
                    self._mark_disconnected(proc)
                    return ExecutionResult(
                        status="disconnected",
                        output="".join(lines),
                        error="debugger output stream closed before completion marker",
                        attempts=1,
                        async_output=async_output,
                        command_id=command_id,
                        session_state="disconnected",
                    )
                if cancel_on_timeout:
                    return self._recover_timeout(
                        marker,
                        timeout,
                        proc,
                        output_queue,
                        async_output,
                        command_id,
                        lines,
                    )
                self._start_background_drain(
                    marker,
                    proc,
                    output_queue,
                    command_id,
                )
                return ExecutionResult(
                    status="timeout",
                    output="".join(lines),
                    error=f"command timed out after {timeout:g} seconds",
                    attempts=1,
                    async_output=async_output,
                    command_id=command_id,
                    session_state="draining",
                )

            try:
                item = output_queue.get(timeout=min(0.05, remaining))
            except queue.Empty:
                if not self.connected:
                    self._mark_disconnected(proc)
                    return ExecutionResult(
                        status="disconnected",
                        output="".join(lines),
                        error="debugger output stream closed before completion marker",
                        attempts=1,
                        async_output=async_output,
                        command_id=command_id,
                        session_state="disconnected",
                    )
                continue

            if isinstance(item, _StreamClosed):
                self._mark_disconnected(proc)
                return ExecutionResult(
                    status="disconnected",
                    output="".join(lines),
                    error=item.error or "debugger output stream reached EOF before completion marker",
                    attempts=1,
                    async_output=async_output,
                    command_id=command_id,
                    session_state="disconnected",
                )

            if self._is_completion_line(item, marker):
                cancellation_reason = self._finish_active_command(command_id)
                session_state = self.session_snapshot().state
                if cancellation_reason is not None:
                    return ExecutionResult(
                        status="cancelled",
                        output="".join(lines),
                        complete=True,
                        error="command was interrupted",
                        attempts=1,
                        async_output=async_output,
                        command_id=command_id,
                        session_state=session_state,
                        cancellation_status="confirmed",
                    )
                return ExecutionResult(
                    status="completed",
                    output="".join(lines),
                    complete=True,
                    attempts=1,
                    async_output=async_output,
                    command_id=command_id,
                    session_state=session_state,
                )
            lines.append(item)

    def _recover_timeout(
        self,
        marker: str,
        timeout: float,
        proc: subprocess.Popen,
        output_queue: queue.Queue[_QueueItem],
        async_output: str,
        command_id: str,
        lines: list[str],
    ) -> ExecutionResult:
        cancellation_status = self._request_interrupt(
            command_id,
            reason="timeout",
        )
        if cancellation_status in ("failed", "unsupported"):
            self._start_background_drain(
                marker,
                proc,
                output_queue,
                command_id,
            )
            return ExecutionResult(
                status="timeout",
                output="".join(lines),
                error=f"command timed out after {timeout:g} seconds",
                attempts=1,
                async_output=async_output,
                command_id=command_id,
                session_state="draining",
                cancellation_status=cancellation_status,
            )
        deadline = time.monotonic() + self._interrupt_timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._start_background_drain(
                    marker,
                    proc,
                    output_queue,
                    command_id,
                )
                return ExecutionResult(
                    status="timeout",
                    output="".join(lines),
                    error=f"command timed out after {timeout:g} seconds",
                    attempts=1,
                    async_output=async_output,
                    command_id=command_id,
                    session_state="draining",
                    cancellation_status=cancellation_status,
                )

            try:
                item = output_queue.get(timeout=min(0.05, remaining))
            except queue.Empty:
                if not self.connected:
                    self._mark_disconnected(proc)
                    return ExecutionResult(
                        status="disconnected",
                        output="".join(lines),
                        error="debugger output stream closed during timeout recovery",
                        attempts=1,
                        async_output=async_output,
                        command_id=command_id,
                        session_state="disconnected",
                        cancellation_status=cancellation_status,
                    )
                continue

            if isinstance(item, _StreamClosed):
                self._mark_disconnected(proc)
                return ExecutionResult(
                    status="disconnected",
                    output="".join(lines),
                    error=item.error or "debugger output stream closed during timeout recovery",
                    attempts=1,
                    async_output=async_output,
                    command_id=command_id,
                    session_state="disconnected",
                    cancellation_status=cancellation_status,
                )

            if self._is_completion_line(item, marker):
                cancellation_reason = self._finish_active_command(command_id)
                confirmed = (
                    cancellation_reason is not None
                    or cancellation_status == "requested"
                )
                session_state = self.session_snapshot().state
                return ExecutionResult(
                    status="timeout",
                    output="".join(lines),
                    complete=True,
                    error=(
                        f"command timed out after {timeout:g} seconds and was interrupted"
                        if confirmed
                        else f"command timed out after {timeout:g} seconds"
                    ),
                    attempts=1,
                    async_output=async_output,
                    command_id=command_id,
                    session_state=session_state,
                    cancellation_status=(
                        "confirmed" if confirmed else cancellation_status
                    ),
                )
            lines.append(item)

    def _request_interrupt(
        self,
        command_id: Optional[str],
        *,
        reason: str,
    ) -> CancellationStatus:
        with self._state_lock:
            active = self._active_command
            proc = self._proc
            if active is None:
                return "failed"
            if command_id is not None and active.command_id != command_id:
                return "failed"
            if active.cancellation_status == "requested":
                return "requested"
            if not self._connected:
                active.cancellation_status = "failed"
                active.cancellation_reason = reason
                return "failed"
            if not self._can_interrupt(proc):
                active.cancellation_status = "unsupported"
                active.cancellation_reason = reason
                return "unsupported"
            active.cancellation_status = "requested"
            active.cancellation_reason = reason
            self._state = "interrupting"

        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[union-attr]
        except Exception as e:
            logger.warning("could not interrupt debugger command %s: %s", active.command_id, e)
            with self._state_lock:
                if self._active_command is active:
                    active.cancellation_status = "failed"
                    self._state = (
                        "executing" if self._connected else "disconnected"
                    )
            return "failed"
        return "requested"

    @staticmethod
    def _can_interrupt(proc: Optional[subprocess.Popen]) -> bool:
        return (
            proc is not None
            and hasattr(proc, "send_signal")
            and hasattr(signal, "CTRL_BREAK_EVENT")
        )

    def _finish_active_command(self, command_id: str) -> Optional[str]:
        with self._state_lock:
            active = self._active_command
            if active is None or active.command_id != command_id:
                return None
            cancellation_confirmed = active.cancellation_status == "requested"
            reason = active.cancellation_reason if cancellation_confirmed else None
            if cancellation_confirmed:
                active.cancellation_status = "confirmed"
            self._active_command = None
            self._state = "idle" if self.connected else "disconnected"
            return reason

    def _start_background_drain(
        self,
        marker: str,
        proc: subprocess.Popen,
        output_queue: queue.Queue[_QueueItem],
        command_id: str,
    ) -> None:
        with self._state_lock:
            active = self._active_command
            if active is None or active.command_id != command_id:
                return
            self._state = "draining"

        def drain() -> None:
            while True:
                item = output_queue.get()
                if isinstance(item, _StreamClosed):
                    self._mark_disconnected(proc)
                    return
                if self._is_completion_line(item, marker):
                    self._finish_active_command(command_id)
                    return

        threading.Thread(
            target=drain,
            name=f"windbg-drain-{command_id[:8]}",
            daemon=True,
        ).start()

    @staticmethod
    def _is_completion_line(line: str, marker: str) -> bool:
        stripped = line.rstrip("\r\n")
        if stripped == marker:
            return True
        if not stripped.endswith(marker):
            return False
        prompt = stripped[:-len(marker)].strip()
        return bool(_PROMPT_RE.fullmatch(prompt))

    def _mark_disconnected(
        self,
        proc: subprocess.Popen,
        *,
        preserve_active_command: bool = False,
    ) -> None:
        with self._state_lock:
            if self._proc is not proc:
                return
            self._connected = False
            if not preserve_active_command:
                self._active_command = None
            self._state = "disconnected"
