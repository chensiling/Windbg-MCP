import logging
import queue
import subprocess
import threading
import time
from typing import Optional
from .engine import DebugEngine

logger = logging.getLogger(__name__)

KD_X64 = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe"
CDB_X64 = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
MARKER = "__MCP_END__"


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
        self._output_queue: queue.Queue = queue.Queue()
        self._reader_thread: Optional[threading.Thread] = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

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
        self._proc = subprocess.Popen(
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
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()
        time.sleep(1)
        self._connected = True
        logger.info("debugger subprocess started (pid %d)", self._proc.pid)

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
        self._proc = None

    def execute(self, command: str) -> str:
        proc = self._proc
        if not self._connected or not proc:
            return "error: not connected"
        with self._lock:
            self._drain_queue()
            try:
                proc.stdin.write(f"{command}\n.printf \"{MARKER}\\n\"\n")  # type: ignore
                proc.stdin.flush()  # type: ignore
            except (BrokenPipeError, OSError) as e:
                self._connected = False
                return f"error: debugger process died: {e}"
            result = self._read_until_marker()
            return result

    def _drain_queue(self) -> None:
        while not self._output_queue.empty():
            try:
                self._output_queue.get_nowait()
            except queue.Empty:
                break

    def _read_loop(self) -> None:
        proc = self._proc
        if not proc:
            return
        try:
            for line in iter(proc.stdout.readline, ""):  # type: ignore
                self._output_queue.put(line)
        except Exception as e:
            logger.error("read_loop died: %s", e)

    def _read_until_marker(self, timeout: float = 30.0) -> str:
        lines = []
        start = time.time()
        while time.time() - start < timeout:
            try:
                line = self._output_queue.get(timeout=0.3)
                if MARKER in line:
                    break
                lines.append(line)
            except queue.Empty:
                if not self._connected:
                    break
                continue
        return "".join(lines)
