from typing import Any, Optional

try:
    from ..debugger.engine import (
        ExecutionContractError,
        ExecutionResult,
        SessionSnapshot,
    )
except ImportError:  # Tests import tools as a top-level package.
    from debugger.engine import ExecutionContractError, ExecutionResult, SessionSnapshot

_executor: Optional[Any] = None


def set_executor(executor: Any) -> None:
    global _executor
    _executor = executor


def _exec_result(
    command: str,
    *,
    read_only: bool = False,
    retryable: bool = False,
    timeout: float | None = None,
    cancel_on_timeout: bool = True,
) -> ExecutionResult:
    if _executor is None:
        return ExecutionResult(
            status="failed",
            error="executor not initialized",
            attempts=0,
        )

    policy = {
        "read_only": read_only,
        "retryable": retryable,
    }
    if timeout is not None:
        policy["timeout"] = timeout
    if not cancel_on_timeout:
        policy["cancel_on_timeout"] = False
    result = _executor.execute(command, **policy)
    if not isinstance(result, ExecutionResult):
        raise ExecutionContractError("executor.execute() must return ExecutionResult")
    try:
        result.validate()
    except (TypeError, ValueError) as e:
        raise ExecutionContractError(
            "executor.execute() returned an invalid ExecutionResult"
        ) from e
    return result


def _exec(
    command: str,
    *,
    read_only: bool = False,
    retryable: bool = False,
) -> str:
    """Temporary string adapter for tools awaiting ExecutionResult migration."""

    result = _exec_result(
        command,
        read_only=read_only,
        retryable=retryable,
    )
    if result.status == "completed" and result.complete:
        return result.output

    detail = result.error or f"command ended with status '{result.status}'"
    if result.output:
        return f"error: {detail}\npartial output:\n{result.output}"
    return f"error: {detail}"


def _session_snapshot() -> SessionSnapshot:
    if _executor is None:
        return SessionSnapshot(state="disconnected", connected=False)
    snapshot_method = getattr(_executor, "session_snapshot", None)
    if snapshot_method is None:
        return SessionSnapshot(state="disconnected", connected=False)
    snapshot = snapshot_method()
    if not isinstance(snapshot, SessionSnapshot):
        raise ExecutionContractError(
            "executor.session_snapshot() must return SessionSnapshot"
        )
    return snapshot


def _interrupt_session(command_id: str | None = None) -> bool:
    if _executor is None:
        return False
    interrupt_method = getattr(_executor, "interrupt", None)
    if interrupt_method is None:
        return False
    return bool(interrupt_method(command_id))


def _recover_session() -> str | None:
    if _executor is None:
        return "executor not initialized"
    recover_method = getattr(_executor, "recover", None)
    if recover_method is None:
        return "executor does not support session recovery"
    result = recover_method()
    if result is not None and not isinstance(result, str):
        raise ExecutionContractError(
            "executor.recover() must return an error string or None"
        )
    return result
