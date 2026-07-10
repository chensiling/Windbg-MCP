from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal, Optional


ExecutionStatus = Literal[
    "completed",
    "timeout",
    "disconnected",
    "failed",
    "indeterminate",
]


@dataclass(frozen=True)
class ExecutionResult:
    """Outcome of one logical debugger command."""

    status: ExecutionStatus
    output: str = ""
    complete: bool = False
    error: Optional[str] = None
    attempts: int = 1
    session_restarted: bool = False
    async_output: str = ""


class DebugEngine(ABC):

    @abstractmethod
    def execute(self, command: str, timeout: float = 30.0) -> ExecutionResult:
        ...

    @abstractmethod
    def connect(self) -> None:
        ...

    @abstractmethod
    def disconnect(self) -> None:
        ...

    @property
    @abstractmethod
    def connected(self) -> bool:
        ...

    @property
    @abstractmethod
    def target_running(self) -> bool:
        ...
