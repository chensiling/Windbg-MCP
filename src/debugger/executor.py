from dataclasses import replace
import logging
import time
from threading import Lock

from .engine import DebugEngine, ExecutionContractError, ExecutionResult

logger = logging.getLogger(__name__)


class CommandExecutor:
    def __init__(
        self,
        engine: DebugEngine,
        timeout: float = 30,
        max_retries: int = 3,
    ):
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if max_retries < 1:
            raise ValueError("max_retries must be at least one")
        self._engine = engine
        self._timeout = timeout
        self._max_retries = max_retries
        self._lock = Lock()

    def execute(
        self,
        command: str,
        *,
        read_only: bool = False,
        retryable: bool = False,
    ) -> ExecutionResult:
        with self._lock:
            return self._execute_locked(command, read_only, retryable)

    def _execute_locked(
        self,
        command: str,
        read_only: bool,
        retryable: bool,
    ) -> ExecutionResult:
        total_attempts = 0
        session_restarted = False
        command_output: list[str] = []
        async_output: list[str] = []

        for attempt in range(1, self._max_retries + 1):
            try:
                result = self._engine.execute(command, timeout=self._timeout)
            except Exception as e:
                raise ExecutionContractError(
                    "debugger engine raised instead of returning ExecutionResult"
                ) from e

            if not isinstance(result, ExecutionResult):
                raise ExecutionContractError(
                    "debugger engine execute() must return ExecutionResult"
                )
            try:
                result.validate()
            except (TypeError, ValueError) as e:
                raise ExecutionContractError(
                    "debugger engine returned an invalid ExecutionResult"
                ) from e

            total_attempts += result.attempts
            if result.output:
                command_output.append(result.output)
            if result.async_output:
                async_output.append(result.async_output)
            session_restarted = session_restarted or result.session_restarted
            result = replace(
                result,
                output="".join(command_output),
                attempts=total_attempts,
                session_restarted=session_restarted,
                async_output="".join(async_output),
            )

            if result.status == "completed" and result.complete:
                return result

            may_replay = read_only and retryable
            if not may_replay or attempt >= self._max_retries:
                return result

            time.sleep(1)
            restart_error = self._restart_engine()
            if restart_error is not None:
                return ExecutionResult(
                    status="disconnected",
                    output=result.output,
                    error=restart_error,
                    attempts=total_attempts,
                    session_restarted=session_restarted,
                    async_output="".join(async_output),
                )
            session_restarted = True

        return ExecutionResult(
            status="failed",
            error="command execution ended without a result",
            attempts=total_attempts,
            session_restarted=session_restarted,
            async_output="".join(async_output),
        )

    def _restart_engine(self) -> str | None:
        disconnect_error = None
        try:
            self._engine.disconnect()
        except Exception as e:
            disconnect_error = e
            logger.warning("debugger disconnect during recovery failed: %s", e)

        try:
            self._engine.connect()
        except Exception as e:
            logger.warning("debugger reconnect during recovery failed: %s", e)
            return f"debugger session recovery failed: {e}"

        if not self._engine.connected:
            return "debugger session recovery did not establish a connection"
        if disconnect_error is not None:
            logger.info("debugger session recovered after disconnect error")
        return None
