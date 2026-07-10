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
_EXECUTION_STATUSES = {
    "completed",
    "timeout",
    "disconnected",
    "failed",
    "indeterminate",
}


class ExecutionContractError(RuntimeError):
    """Raised when a debugger engine violates the execution boundary."""


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

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.status not in _EXECUTION_STATUSES:
            raise ValueError(f"unknown execution status: {self.status!r}")
        if not isinstance(self.output, str):
            raise TypeError("output must be a string")
        if not isinstance(self.async_output, str):
            raise TypeError("async_output must be a string")
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be a boolean")
        if not isinstance(self.session_restarted, bool):
            raise TypeError("session_restarted must be a boolean")
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int):
            raise TypeError("attempts must be an integer")
        if self.attempts < 0:
            raise ValueError("attempts must not be negative")

        if self.status == "completed":
            if not self.complete:
                raise ValueError("completed results require an observed completion marker")
            if self.error is not None:
                raise ValueError("completed results cannot carry an error")
            return

        if self.complete:
            raise ValueError("only completed results can be complete")
        if not isinstance(self.error, str) or not self.error.strip():
            raise ValueError("non-completed results require an explicit error")


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
