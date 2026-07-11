"""Typed response helpers for LLM-facing tools."""

from collections.abc import Iterable, Sequence
from typing import Any

from ._models import (
    ErrorStage,
    ExecutionStageStatus,
    ParseStageStatus,
    ToolEnvelope,
    ToolError,
    ToolInference,
    ToolNextAction,
    ToolSource,
    VerificationStageStatus,
)
from ._parser import ParseResult

try:
    from ..debugger.engine import ExecutionResult
except ImportError:  # Tests may import tools as a top-level package.
    from debugger.engine import ExecutionResult


_ASYNC_OUTPUT_LIMIT = 2_000
_ASYNC_OUTPUT_TRUNCATION_MARKER = "\n...[ASYNC OUTPUT TRUNCATED]...\n"
_ASYNC_OUTPUT_TRUNCATION_WARNING = "async_output_truncated"


def _limit_async_output(output: str) -> tuple[str, bool]:
    if len(output) <= _ASYNC_OUTPUT_LIMIT:
        return output, False

    retained = _ASYNC_OUTPUT_LIMIT - len(_ASYNC_OUTPUT_TRUNCATION_MARKER)
    head_length = (retained + 1) // 2
    tail_length = retained - head_length
    return (
        output[:head_length]
        + _ASYNC_OUTPUT_TRUNCATION_MARKER
        + output[-tail_length:],
        True,
    )


def error_item(
    code: str,
    message: str,
    recoverable: bool = True,
    *,
    stage: ErrorStage = "input",
) -> ToolError:
    return ToolError(
        code=code,
        message=message,
        stage=stage,
        recoverable=recoverable,
    )


def next_action(tool: str, args: dict[str, Any], reason: str) -> ToolNextAction:
    return ToolNextAction(tool=tool, args=args, reason=reason)


def inference_item(name: str, value: Any, basis: str) -> ToolInference:
    return ToolInference(name=name, value=value, basis=basis)


def source_item(
    command: str,
    execution: ExecutionResult,
    parsed: ParseResult | None = None,
) -> ToolSource:
    async_output, async_output_truncated = _limit_async_output(
        execution.async_output,
    )
    warnings = list(parsed.warnings) if parsed is not None else []
    if (
        async_output_truncated
        and _ASYNC_OUTPUT_TRUNCATION_WARNING not in warnings
    ):
        warnings.append(_ASYNC_OUTPUT_TRUNCATION_WARNING)

    return ToolSource(
        command=command,
        execution_status=execution.status,
        raw=execution.output,
        complete=execution.complete,
        error=execution.error,
        attempts=execution.attempts,
        session_restarted=execution.session_restarted,
        async_output=async_output,
        parse_status=parsed.status if parsed is not None else "not_run",
        unparsed_lines=list(parsed.unparsed_lines) if parsed is not None else [],
        warnings=warnings,
    )


def _execution_status(sources: Sequence[ToolSource]) -> ExecutionStageStatus:
    if not sources:
        return "not_run"
    for source in sources:
        if source.execution_status != "completed":
            return source.execution_status
    return "completed"


def _parse_status(sources: Sequence[ToolSource]) -> ParseStageStatus:
    statuses = [
        source.parse_status
        for source in sources
        if source.parse_status != "not_run"
    ]
    if not statuses:
        return "not_run"
    if "failed" in statuses:
        return "failed"
    if "partial" in statuses:
        return "partial"
    return "complete"


def _source_errors(sources: Sequence[ToolSource]) -> list[ToolError]:
    errors: list[ToolError] = []
    for source in sources:
        if source.execution_status != "completed":
            errors.append(error_item(
                f"execution_{source.execution_status}",
                source.error or f"Command ended with {source.execution_status}.",
                source.execution_status in ("timeout", "disconnected"),
                stage="execution",
            ))
        if source.parse_status in ("partial", "failed"):
            detail = ", ".join(source.warnings) or "parser did not cover the output"
            errors.append(error_item(
                f"parse_{source.parse_status}",
                f"Command '{source.command}' parse was {source.parse_status}: {detail}.",
                True,
                stage="parsing",
            ))
    return errors


def make_response(
    tool: str,
    sources: Sequence[ToolSource] | None = None,
    data: dict[str, Any] | None = None,
    *,
    inferences: Iterable[ToolInference] | None = None,
    errors: Iterable[ToolError] | None = None,
    next_actions: Iterable[ToolNextAction] | None = None,
    verification_status: VerificationStageStatus = "not_required",
    raw: str | None = None,
) -> ToolEnvelope:
    source_list = list(sources or [])
    error_list = [*_source_errors(source_list), *(errors or [])]
    execution_status = _execution_status(source_list)
    parse_status = _parse_status(source_list)
    ok = (
        execution_status in ("completed", "not_run")
        and parse_status in ("complete", "not_run")
        and verification_status in ("verified", "not_required")
        and not error_list
    )
    compatibility_raw = raw
    if compatibility_raw is None:
        compatibility_raw = source_list[0].raw if len(source_list) == 1 else ""

    return ToolEnvelope(
        ok=ok,
        tool=tool,
        execution_status=execution_status,
        parse_status=parse_status,
        verification_status=verification_status,
        data=data or {},
        inferences=list(inferences or []),
        sources=source_list,
        errors=error_list,
        next_actions=list(next_actions or []),
        raw=compatibility_raw,
    )


def make_error(
    tool: str,
    code: str,
    message: str,
    *,
    stage: ErrorStage = "input",
    recoverable: bool = True,
    sources: Sequence[ToolSource] | None = None,
    data: dict[str, Any] | None = None,
    verification_status: VerificationStageStatus = "not_run",
    next_actions: Iterable[ToolNextAction] | None = None,
) -> ToolEnvelope:
    return make_response(
        tool,
        sources,
        data,
        errors=[error_item(
            code,
            message,
            recoverable,
            stage=stage,
        )],
        verification_status=verification_status,
        next_actions=next_actions,
    )


def parsed_response(
    tool: str,
    source: ToolSource,
    parsed: ParseResult,
    *,
    data: dict[str, Any] | None = None,
    inferences: Iterable[ToolInference] | None = None,
    next_actions: Iterable[ToolNextAction] | None = None,
) -> ToolEnvelope:
    observations = dict(parsed.data) if data is None else data
    return make_response(
        tool,
        [source],
        observations,
        inferences=inferences,
        next_actions=next_actions,
    )


def validate_intent_text(
    value: str,
    name: str,
    *,
    required: bool = True,
) -> ToolError | None:
    if required and not value.strip():
        return error_item("invalid_argument", f"'{name}' is required.")
    if any(separator in value for separator in (";", "\r", "\n", "\x00")):
        return error_item(
            "unsafe_argument",
            f"'{name}' contains a command separator or newline.",
            recoverable=False,
        )
    return None


def parse_int_arg(
    value: Any,
    name: str,
    *,
    default: int | None = None,
    min_value: int = 1,
    max_value: int | None = None,
) -> tuple[int | None, ToolError | None]:
    if value is None or str(value).strip() == "":
        if default is not None:
            return default, None
        return None, error_item("invalid_argument", f"'{name}' is required.")

    text = str(value).strip().lower()
    try:
        if text.endswith("h") and all(c in "0123456789abcdef" for c in text[:-1]):
            number = int(text[:-1], 16)
        else:
            number = int(text, 0)
    except ValueError:
        return None, error_item(
            "invalid_argument",
            f"'{name}' must be an integer; decimal and 0x-prefixed hex are supported.",
        )

    if number < min_value:
        return None, error_item("invalid_argument", f"'{name}' must be >= {min_value}.")
    if max_value is not None and number > max_value:
        return None, error_item("invalid_argument", f"'{name}' must be <= {max_value}.")
    return number, None
