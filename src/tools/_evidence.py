"""Execution and parsing evidence helpers for intent tools."""

from dataclasses import dataclass
import re
from typing import Callable

from ._models import ToolSource
from ._parser import ParseResult, parse_evaluate
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
) -> CommandEvidence:
    execution = _exec_result(
        command,
        read_only=read_only,
        retryable=retryable,
    )
    parsed = None
    if parser is not None and (execution.output.strip() or execution.complete):
        parsed = parser(execution.output)
    return CommandEvidence(
        command=command,
        execution=execution,
        parsed=parsed,
        source=source_item(command, execution, parsed),
    )


def run_read(command: str, parser: Parser | None = None) -> CommandEvidence:
    return run_command(
        command,
        parser,
        read_only=True,
        retryable=True,
    )


def run_mutation(command: str, parser: Parser | None = None) -> CommandEvidence:
    return run_command(
        command,
        parser,
        read_only=False,
        retryable=False,
    )


def resolve_expression(expression: str) -> tuple[CommandEvidence, str | None]:
    normalized = expression.strip()
    cleaned = normalized.replace("`", "")
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", cleaned):
        normalized = f"0x{cleaned.lower().removeprefix('0x')}"
    else:
        normalized = _UNPREFIXED_NUMBER.sub(
            lambda match: f"0x{match.group('value')}",
            normalized,
        )
    evidence = run_read(f"? {normalized}", parse_evaluate)
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
