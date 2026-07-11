"""Runtime MCP discovery and structured-output contract tests."""

from importlib.metadata import version
import json
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from src.config import Config
from src.debugger.engine import ExecutionResult
from src.server import SERVER_INSTRUCTIONS, create_mcp_server
from src.tools import _registry


BUSINESS_TOOLS = {
    "windbg_context",
    "windbg_control",
    "windbg_breakpoint",
    "windbg_read_memory",
    "windbg_write_memory",
    "windbg_disassemble",
    "windbg_backtrace",
    "windbg_lookup",
    "windbg_analyze",
    "windbg_evaluate",
    "windbg_sympath",
}

ENVELOPE_FIELDS = {
    "ok",
    "tool",
    "execution_status",
    "parse_status",
    "verification_status",
    "data",
    "inferences",
    "sources",
    "errors",
    "next_actions",
    "raw",
}

EXPECTED_ANNOTATIONS = {
    "windbg_context": (True, False, True, False),
    "windbg_control": (False, True, False, True),
    "windbg_breakpoint": (False, True, False, False),
    "windbg_read_memory": (True, False, True, False),
    "windbg_write_memory": (False, True, False, False),
    "windbg_disassemble": (True, False, True, False),
    "windbg_backtrace": (False, False, False, False),
    "windbg_lookup": (True, False, True, False),
    "windbg_analyze": (False, False, False, False),
    "windbg_evaluate": (True, False, True, False),
    "windbg_sympath": (False, True, False, True),
    "windbg_exec": (False, True, False, True),
}


def _annotation_tuple(tool):
    annotations = tool.annotations
    assert annotations is not None
    return (
        annotations.readOnlyHint,
        annotations.destructiveHint,
        annotations.idempotentHint,
        annotations.openWorldHint,
    )


def _major_minor(distribution: str) -> tuple[int, int]:
    parts = version(distribution).split(".")
    return int(parts[0]), int(parts[1])


def test_runtime_versions_satisfy_supported_constraints():
    assert (1, 28) <= _major_minor("mcp") < (2, 0)
    assert (2, 12) <= _major_minor("pydantic") < (3, 0)


@pytest.mark.asyncio
async def test_readme_numeric_examples_match_public_string_schemas():
    mcp = create_mcp_server()
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    readme = (Path(__file__).parents[1] / "README.md").read_text(
        encoding="utf-8",
    )

    assert tools["windbg_backtrace"].inputSchema["properties"]["depth"]["type"] == "string"
    assert tools["windbg_disassemble"].inputSchema["properties"]["count"]["type"] == "string"
    assert 'windbg_backtrace("30")' in readme
    assert 'windbg_disassemble("@rip", "8")' in readme
    assert "windbg_backtrace(30)" not in readme
    assert 'windbg_disassemble("@rip", 8)' not in readme


def test_dependency_docs_separate_constraints_from_validation_evidence():
    root = Path(__file__).parents[1]
    architecture = (root / "docs" / "architecture" / "README.md").read_text(
        encoding="utf-8",
    )
    readme = (root / "README.md").read_text(encoding="utf-8")

    for document in (architecture, readme):
        assert "Pydantic 2.13.4" in document
        assert "2.12.0" in document
    assert "validated dependency floor" not in architecture


@pytest.mark.asyncio
async def test_server_instructions_and_raw_exec_contract():
    mcp = create_mcp_server()
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    raw = tools["windbg_exec"]

    assert mcp.instructions == SERVER_INSTRUCTIONS
    assert "execution_status" in SERVER_INSTRUCTIONS
    assert "sources" in SERVER_INSTRUCTIONS
    assert "inferences" in SERVER_INSTRUCTIONS
    assert "optional suggestions" in SERVER_INSTRUCTIONS
    assert "open-world" in SERVER_INSTRUCTIONS
    assert mcp.settings.host == "127.0.0.1"
    assert raw.description
    assert raw.outputSchema is None
    assert _annotation_tuple(raw) == EXPECTED_ANNOTATIONS["windbg_exec"]


@pytest.mark.asyncio
async def test_runtime_discovery_exposes_descriptions_schemas_and_annotations():
    mcp = create_mcp_server()
    async with create_connected_server_and_client_session(
        mcp._mcp_server,
    ) as session:
        discovered = await session.list_tools()
    tools = {tool.name: tool for tool in discovered.tools}

    assert set(tools) == BUSINESS_TOOLS | {"windbg_exec"}
    for name, tool in tools.items():
        assert tool.description is not None
        assert tool.description.strip()
        assert _annotation_tuple(tool) == EXPECTED_ANNOTATIONS[name]

    for name in BUSINESS_TOOLS:
        output_schema = tools[name].outputSchema
        assert output_schema is not None
        assert output_schema["title"] == "ToolEnvelope"
        assert output_schema["additionalProperties"] is False
        assert set(output_schema["properties"]) == ENVELOPE_FIELDS

    assert tools["windbg_exec"].outputSchema is None


class _ContractExecutor:
    def execute(self, command, *, read_only=False, retryable=False):
        if command == "? @rip":
            assert read_only is True
            assert retryable is True
            return ExecutionResult(
                status="completed",
                output=(
                    "Evaluate expression: 140709204350861 = "
                    "00007ff9`850bd78d"
                ),
                complete=True,
            )

        assert command == "r"
        assert read_only is False
        assert retryable is False
        return ExecutionResult(
            status="completed",
            output="raw debugger output",
            complete=True,
        )


@pytest.mark.asyncio
async def test_runtime_calls_return_direct_envelope_and_explicit_raw_content(
    monkeypatch,
):
    monkeypatch.setattr(_registry, "_executor", _ContractExecutor())
    mcp = create_mcp_server()

    async with create_connected_server_and_client_session(
        mcp._mcp_server,
    ) as session:
        business_result = await session.call_tool(
            "windbg_evaluate",
            {"expression": "@rip"},
        )
        raw_result = await session.call_tool("windbg_exec", {"command": "r"})

    structured = business_result.structuredContent
    assert structured is not None
    assert set(structured) == ENVELOPE_FIELDS
    assert structured["tool"] == "windbg_evaluate"
    assert structured["ok"] is True
    assert structured["execution_status"] == "completed"
    assert structured["parse_status"] == "complete"
    assert structured["verification_status"] == "not_required"
    assert structured["data"] == {
        "input": "@rip",
        "value": "0x00007ff9850bd78d",
        "decimal": "140709204350861",
    }
    assert len(structured["sources"]) == 1
    source = structured["sources"][0]
    assert source["command"] == "? @rip"
    assert source["execution_status"] == "completed"
    assert source["parse_status"] == "complete"
    assert source["complete"] is True
    assert source["warnings"] == []
    assert json.loads(business_result.content[0].text) == structured

    assert raw_result.structuredContent is None
    assert len(raw_result.content) == 1
    assert raw_result.content[0].text == "raw debugger output"


def test_unused_token_environment_variable_is_not_a_security_surface(monkeypatch):
    monkeypatch.setenv("WINDBG_MCP_TOKEN", "not-implemented")

    config = Config.from_env()
    mcp = create_mcp_server()

    assert not hasattr(config, "auth_token")
    assert mcp._auth_server_provider is None
    assert mcp._token_verifier is None
