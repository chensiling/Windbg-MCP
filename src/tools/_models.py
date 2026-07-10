"""Typed MCP response models shared by business tools."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


ExecutionStageStatus = Literal[
    "completed",
    "timeout",
    "disconnected",
    "failed",
    "indeterminate",
    "not_run",
]
ParseStageStatus = Literal["complete", "partial", "failed", "not_run"]
VerificationStageStatus = Literal[
    "verified",
    "failed",
    "indeterminate",
    "not_required",
    "not_run",
]
ErrorStage = Literal["input", "execution", "parsing", "verification"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolError(_StrictModel):
    code: str
    message: str
    stage: ErrorStage
    recoverable: bool = True


class ToolInference(_StrictModel):
    name: str
    value: Any
    basis: str
    certainty: Literal["inferred"] = "inferred"


class ToolSource(_StrictModel):
    command: str
    execution_status: ExecutionStageStatus
    raw: str
    complete: bool
    error: str | None = None
    attempts: int
    session_restarted: bool
    async_output: str = ""
    parse_status: ParseStageStatus = "not_run"
    unparsed_lines: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ToolNextAction(_StrictModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    reason: str


class ToolEnvelope(_StrictModel):
    ok: bool
    tool: str
    execution_status: ExecutionStageStatus
    parse_status: ParseStageStatus
    verification_status: VerificationStageStatus
    data: dict[str, Any] = Field(default_factory=dict)
    inferences: list[ToolInference] = Field(default_factory=list)
    sources: list[ToolSource] = Field(default_factory=list)
    errors: list[ToolError] = Field(default_factory=list)
    next_actions: list[ToolNextAction] = Field(default_factory=list)
    raw: str = ""
