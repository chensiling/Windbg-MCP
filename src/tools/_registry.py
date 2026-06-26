from typing import Any, Optional

_executor: Optional[Any] = None


def set_executor(executor: Any) -> None:
    global _executor
    _executor = executor


def _exec(command: str) -> str:
    if _executor is None:
        return "error: executor not initialized"
    return _executor.execute(command)
