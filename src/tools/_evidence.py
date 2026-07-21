"""Execution and parsing evidence helpers for intent tools."""

from dataclasses import dataclass
import re
from typing import Callable

from ._models import ToolSource
from ._parser import ParseResult, parse_evaluate, parse_target_info
from ._registry import _exec_result
from ._response import source_item

try:
    from ..debugger.engine import ExecutionResult
except ImportError:  # Tests may import tools as a top-level package.
    from debugger.engine import ExecutionResult


Parser = Callable[[str], ParseResult]
_UNPREFIXED_NUMBER = re.compile(
    r"(?<![A-Za-z0-9_.$!?@])(?P<value>[0-9][0-9a-fA-F]*)(?![A-Za-z0-9_])"
)


@dataclass(frozen=True)
class CommandEvidence:
    command: str
    execution: ExecutionResult
    parsed: ParseResult | None
    source: ToolSource


def run_command(
    command: str,
    parser: Parser | None = None,
    *,
    read_only: bool,
    retryable: bool,
    include_raw: bool = False,
    timeout: float | None = None,
    cancel_on_timeout: bool = True,
) -> CommandEvidence:
    execution = _exec_result(
        command,
        read_only=read_only,
        retryable=retryable,
        timeout=timeout,
        cancel_on_timeout=cancel_on_timeout,
    )
    parsed = None
    if parser is not None and (execution.output.strip() or execution.complete):
        parsed = parser(execution.output)
    return CommandEvidence(
        command=command,
        execution=execution,
        parsed=parsed,
        source=source_item(
            command,
            execution,
            parsed,
            include_raw=include_raw,
        ),
    )


def run_read(
    command: str,
    parser: Parser | None = None,
    *,
    include_raw: bool = False,
    timeout: float | None = None,
    cancel_on_timeout: bool = True,
) -> CommandEvidence:
    return run_command(
        command,
        parser,
        read_only=True,
        retryable=True,
        include_raw=include_raw,
        timeout=timeout,
        cancel_on_timeout=cancel_on_timeout,
    )


def run_mutation(
    command: str,
    parser: Parser | None = None,
    *,
    include_raw: bool = False,
    timeout: float | None = None,
    cancel_on_timeout: bool = True,
) -> CommandEvidence:
    return run_command(
        command,
        parser,
        read_only=False,
        retryable=False,
        include_raw=include_raw,
        timeout=timeout,
        cancel_on_timeout=cancel_on_timeout,
    )


def probe_target_info(
    *,
    include_raw: bool = False,
) -> tuple[CommandEvidence, dict[str, object]]:
    evidence = run_read("||", parse_target_info, include_raw=include_raw)
    data = (
        dict(evidence.parsed.data)
        if evidence.parsed is not None and evidence.parsed.status != "failed"
        else {
            "target_mode": "unknown",
            "session_kind": "unknown",
            "capabilities": {},
        }
    )
    return evidence, data


def resolve_expression(
    expression: str,
    *,
    include_raw: bool = False,
) -> tuple[CommandEvidence, str | None]:
    normalized = expression.strip()
    cleaned = normalized.replace("`", "")
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", cleaned):
        normalized = f"0x{cleaned.lower().removeprefix('0x')}"
    else:
        normalized = _UNPREFIXED_NUMBER.sub(
            lambda match: f"0x{match.group('value')}",
            normalized,
        )
    evidence = run_read(
        f"? {normalized}",
        parse_evaluate,
        include_raw=include_raw,
    )
    resolved = None
    if (
        evidence.execution.status == "completed"
        and evidence.parsed is not None
        and evidence.parsed.status == "complete"
    ):
        value = evidence.parsed.data.get("hex")
        if isinstance(value, str):
            resolved = value
    return evidence, resolved
