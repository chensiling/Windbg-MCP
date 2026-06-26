import time
import logging
from threading import Lock
from .engine import DebugEngine

logger = logging.getLogger(__name__)


class CommandExecutor:
    def __init__(self, engine: DebugEngine, timeout: int = 30, max_retries: int = 3):
        self._engine = engine
        self._timeout = timeout
        self._max_retries = max_retries
        self._lock = Lock()

    def execute(self, command: str) -> str:
        if not self._engine.connected:
            return "error: not connected to debug target"

        for attempt in range(1, self._max_retries + 1):
            try:
                with self._lock:
                    result = self._engine.execute(command)
                return result
            except Exception as e:
                logger.warning("command attempt %d failed: %s", attempt, e)
                if attempt < self._max_retries:
                    time.sleep(1)
                    try:
                        self._engine.disconnect()
                        self._engine.connect()
                    except Exception:
                        pass
                else:
                    return f"error: command failed after {self._max_retries} retries: {e}"

        return "error: unknown failure"
