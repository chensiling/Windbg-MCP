from dataclasses import dataclass
import logging
import queue
import re
import secrets
import subprocess
import threading
import time
from typing import Optional, Union

from .engine import DebugEngine, ExecutionResult

logger = logging.getLogger(__name__)

KD_X64 = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe"
CDB_X64 = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
MARKER_PREFIX = "__MCP_END_"
_PROMPT_RE = re.compile(
    r"^(?:\d+:[0-9a-f]+(?::(?:x86|amd64|arm|arm64))?|\d+:\s*kd|kd)>$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _StreamClosed:
    error: Optional[str] = None


_QueueItem = Union[str, _StreamClosed]


class SubprocessEngine(DebugEngine):

    def __init__(self, debugger_exe: Optional[str] = None,
                 remote_host: str = "127.0.0.1", remote_port: int = 50000,
                 pid: Optional[int] = None, exe: Optional[str] = None,
                 dump: Optional[str] = None, cmd_args: str = ""):
        self._exe = debugger_exe or KD_X64
        self._remote_host = remote_host
        self._remote_port = remote_port
        self._pid = pid
        self._exe_path = exe
        self._dump = dump
        self._cmd_args = cmd_args
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._output_queue: queue.Queue[_QueueItem] = queue.Queue()
        self._reader_thread: Optional[threading.Thread] = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected and self._proc is not None

    @property
    def target_running(self) -> bool:
        return True

    def connect(self) -> None:
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
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output_queue: queue.Queue[_QueueItem] = queue.Queue()
        self._proc = proc
        self._output_queue = output_queue
        self._connected = True
        self._reader_thread = threading.Thread(
            target=self._read_loop,
            args=(proc, output_queue),
            daemon=True,
        )
        self._reader_thread.start()
        time.sleep(1)
        if not self.connected:
            raise ConnectionError("debugger subprocess exited during startup")
        logger.info("debugger subprocess started (pid %d)", proc.pid)

    def disconnect(self) -> None:
        self._connected = False
        proc = self._proc
        if proc:
            try:
                with self._lock:
                    proc.stdin.write("q\n")  # type: ignore
                    proc.stdin.flush()  # type: ignore
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.terminate()
        if self._proc is proc:
            self._proc = None

    def execute(self, command: str, timeout: float = 30.0) -> ExecutionResult:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        with self._lock:
            proc = self._proc
            output_queue = self._output_queue
            async_output, stream_closed = self._drain_queue(output_queue)

            if stream_closed is not None:
                if proc is not None:
                    self._mark_disconnected(proc)
                return ExecutionResult(
                    status="disconnected",
                    error=stream_closed.error or "debugger output stream reached EOF",
                    attempts=0,
                    async_output=async_output,
                )

            if proc is None or not self.connected:
                return ExecutionResult(
                    status="disconnected",
                    error="not connected to debugger process",
                    attempts=0,
                    async_output=async_output,
                )

            if proc.stdin is None:
                return ExecutionResult(
                    status="failed",
                    error="debugger process has no stdin pipe",
                    attempts=0,
                    async_output=async_output,
                )

            try:
                marker = self._new_marker()
            except Exception as e:
                return ExecutionResult(
                    status="failed",
                    error=f"could not create command completion marker: {e}",
                    attempts=0,
                    async_output=async_output,
                )

            try:
                proc.stdin.write(f"{command}\n.printf \"{marker}\\n\"\n")
                proc.stdin.flush()
            except Exception as e:
                self._mark_disconnected(proc)
                return ExecutionResult(
                    status="indeterminate",
                    error=f"debugger process rejected command: {e}",
                    attempts=1,
                    async_output=async_output,
                )

            return self._read_until_marker(
                marker,
                timeout,
                proc,
                output_queue,
                async_output,
            )

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
            self._mark_disconnected(proc)

    def _read_until_marker(
        self,
        marker: str,
        timeout: float,
        proc: subprocess.Popen,
        output_queue: queue.Queue[_QueueItem],
        async_output: str,
    ) -> ExecutionResult:
        lines = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if not self.connected:
                    return ExecutionResult(
                        status="disconnected",
                        output="".join(lines),
                        error="debugger output stream closed before completion marker",
                        attempts=1,
                        async_output=async_output,
                    )
                return ExecutionResult(
                    status="timeout",
                    output="".join(lines),
                    error=f"command timed out after {timeout:g} seconds",
                    attempts=1,
                    async_output=async_output,
                )

            try:
                item = output_queue.get(timeout=min(0.05, remaining))
            except queue.Empty:
                if not self.connected:
                    return ExecutionResult(
                        status="disconnected",
                        output="".join(lines),
                        error="debugger output stream closed before completion marker",
                        attempts=1,
                        async_output=async_output,
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
                )

            if self._is_completion_line(item, marker):
                return ExecutionResult(
                    status="completed",
                    output="".join(lines),
                    complete=True,
                    attempts=1,
                    async_output=async_output,
                )
            lines.append(item)

    @staticmethod
    def _is_completion_line(line: str, marker: str) -> bool:
        stripped = line.rstrip("\r\n")
        if stripped == marker:
            return True
        if not stripped.endswith(marker):
            return False
        prompt = stripped[:-len(marker)].strip()
        return bool(_PROMPT_RE.fullmatch(prompt))

    def _mark_disconnected(self, proc: subprocess.Popen) -> None:
        if self._proc is proc:
            self._connected = False
