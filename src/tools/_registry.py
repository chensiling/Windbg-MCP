from typing import Any, Optional

try:
    from ..debugger.engine import ExecutionContractError, ExecutionResult
except ImportError:  # Tests import tools as a top-level package.
    from debugger.engine import ExecutionContractError, ExecutionResult

_executor: Optional[Any] = None


def set_executor(executor: Any) -> None:
    global _executor
    _executor = executor


def _exec_result(
    command: str,
    *,
    read_only: bool = False,
    retryable: bool = False,
) -> ExecutionResult:
    if _executor is None:
        return ExecutionResult(
            status="failed",
            error="executor not initialized",
            attempts=0,
        )

    result = _executor.execute(
        command,
        read_only=read_only,
        retryable=retryable,
    )
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
