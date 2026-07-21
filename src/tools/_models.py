"""Typed MCP response models shared by business tools."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


ExecutionStageStatus = Literal[
    "completed",
    "cancelled",
    "busy",
    "timeout",
    "disconnected",
    "failed",
    "indeterminate",
    "not_run",
]
ParseStageStatus = Literal["complete", "partial", "failed", "not_run"]
CoreResultStatus = Literal["usable", "empty", "unavailable", "not_run"]
VerificationStageStatus = Literal[
    "verified",
    "failed",
    "indeterminate",
    "not_required",
    "not_run",
]
ErrorStage = Literal[
    "input",
    "execution",
    "parsing",
    "target",
    "output",
    "verification",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolError(_StrictModel):
    code: str
    message: str
    stage: ErrorStage
    recoverable: bool = True


class ToolWarning(_StrictModel):
    code: str
    message: str
    stage: ErrorStage


class ToolLimitation(_StrictModel):
    code: str
    message: str
    path: str | None = None


class ToolInference(_StrictModel):
    name: str
    value: Any
    basis: str
    certainty: Literal["inferred"] = "inferred"


class ToolSource(_StrictModel):
    command_id: str = ""
    command: str
    execution_status: ExecutionStageStatus
    raw: str
    complete: bool
    error: str | None = None
    attempts: int
    session_restarted: bool
    session_state: Literal[
        "idle",
        "executing",
        "interrupting",
        "draining",
        "poisoned",
        "disconnected",
    ] = "idle"
    cancellation_status: Literal[
        "not_requested",
        "requested",
        "confirmed",
        "failed",
        "unsupported",
    ] = "not_requested"
    raw_size: int = 0
    raw_included: bool = False
    raw_truncated: bool = False
    async_output: str = ""
    parse_status: ParseStageStatus = "not_run"
    unparsed_lines: list[str] = Field(default_factory=list)
    unparsed_line_count: int = 0
    unparsed_lines_truncated: bool = False
    warnings: list[str] = Field(default_factory=list)


class ToolNextAction(_StrictModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    reason: str


class ToolEnvelope(_StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    ok: bool
    tool: str
    execution_status: ExecutionStageStatus
    core_result_status: CoreResultStatus
    parse_status: ParseStageStatus
    verification_status: VerificationStageStatus
    data: dict[str, Any] = Field(default_factory=dict)
    inferences: list[ToolInference] = Field(default_factory=list)
    sources: list[ToolSource] = Field(default_factory=list)
    errors: list[ToolError] = Field(default_factory=list)
    warnings: list[ToolWarning] = Field(default_factory=list)
    limitations: list[ToolLimitation] = Field(default_factory=list)
    next_actions: list[ToolNextAction] = Field(default_factory=list)
    raw: str = ""
