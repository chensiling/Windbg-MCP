from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal, Optional


ExecutionStatus = Literal[
    "completed",
    "cancelled",
    "busy",
    "timeout",
    "disconnected",
    "failed",
    "indeterminate",
]
SessionState = Literal[
    "idle",
    "executing",
    "interrupting",
    "draining",
    "poisoned",
    "disconnected",
]
CancellationStatus = Literal[
    "not_requested",
    "requested",
    "confirmed",
    "failed",
    "unsupported",
]
_EXECUTION_STATUSES = {
    "completed",
    "cancelled",
    "busy",
    "timeout",
    "disconnected",
    "failed",
    "indeterminate",
}
_SESSION_STATES = {
    "idle",
    "executing",
    "interrupting",
    "draining",
    "poisoned",
    "disconnected",
}
_CANCELLATION_STATUSES = {
    "not_requested",
    "requested",
    "confirmed",
    "failed",
    "unsupported",
}
_SUBMISSION_REQUIRED_STATUSES = {
    "completed",
    "cancelled",
    "timeout",
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
    command_id: str = ""
    session_state: SessionState = "idle"
    cancellation_status: CancellationStatus = "not_requested"

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.status not in _EXECUTION_STATUSES:
            raise ValueError(f"unknown execution status: {self.status!r}")
        if not isinstance(self.output, str):
            raise TypeError("output must be a string")
        if not isinstance(self.async_output, str):
            raise TypeError("async_output must be a string")
        if not isinstance(self.command_id, str):
            raise TypeError("command_id must be a string")
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be a boolean")
        if not isinstance(self.session_restarted, bool):
            raise TypeError("session_restarted must be a boolean")
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int):
            raise TypeError("attempts must be an integer")
        if self.attempts < 0:
            raise ValueError("attempts must not be negative")
        if self.session_state not in _SESSION_STATES:
            raise ValueError(f"unknown session state: {self.session_state!r}")
        if self.cancellation_status not in _CANCELLATION_STATUSES:
            raise ValueError(
                f"unknown cancellation status: {self.cancellation_status!r}"
            )
        if self.status in _SUBMISSION_REQUIRED_STATUSES and self.attempts == 0:
            raise ValueError(
                f"{self.status} results require at least one command submission"
            )

        if self.status == "completed":
            if not self.complete:
                raise ValueError("completed results require an observed completion marker")
            if self.error is not None:
                raise ValueError("completed results cannot carry an error")
            return

        if self.complete and self.status not in ("cancelled", "timeout"):
            raise ValueError(
                "only completed, cancelled, or bounded timeout results can be complete"
            )
        if self.complete and self.status in ("cancelled", "timeout"):
            if self.cancellation_status != "confirmed":
                raise ValueError(
                    "cancelled or timed-out complete results require confirmed cancellation"
                )
        if not isinstance(self.error, str) or not self.error.strip():
            raise ValueError("non-completed results require an explicit error")


@dataclass(frozen=True)
class SessionSnapshot:
    """Current debugger command-channel state."""

    state: SessionState
    connected: bool
    active_command_id: Optional[str] = None
    interrupt_supported: bool = False


class DebugEngine(ABC):

    @abstractmethod
    def execute(
        self,
        command: str,
        timeout: float = 30.0,
        *,
        cancel_on_timeout: bool = True,
    ) -> ExecutionResult:
        ...

    @abstractmethod
    def connect(self) -> None:
        ...

    @abstractmethod
    def disconnect(self) -> None:
        ...

    def interrupt(self, command_id: Optional[str] = None) -> bool:
        """Request an out-of-band break for the active debugger command."""

        return False

    def session_snapshot(self) -> SessionSnapshot:
        state: SessionState = "idle" if self.connected else "disconnected"
        return SessionSnapshot(
            state=state,
            connected=self.connected,
            interrupt_supported=False,
        )

    @property
    @abstractmethod
    def connected(self) -> bool:
        ...

    @property
    @abstractmethod
    def target_running(self) -> bool:
        ...
