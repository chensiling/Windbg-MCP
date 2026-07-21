"""Structured access to Windows kernel blackbox records."""

from typing import Literal

from ._annotations import READ_ONLY_TOOL
from ._evidence import probe_target_info, run_read
from ._models import ToolEnvelope
from ._parser import parse_blackbox
from ._response import error_item, make_response


BlackboxKind = Literal["pnp", "ntfs", "winlogon", "all"]
_COMMANDS = {
    "pnp": "!blackboxpnp",
    "ntfs": "!blackboxntfs",
    "winlogon": "!blackboxwinlogon",
}


def register_blackbox_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_blackbox(
        kind: BlackboxKind = "all",
        include_raw: bool = False,
    ) -> ToolEnvelope:
        """Read one or all supported kernel blackbox diagnostic records."""

        normalized = kind.lower().strip()
        if normalized not in (*_COMMANDS, "all"):
            return make_response(
                "windbg_blackbox",
                errors=[error_item("invalid_argument", "Unknown blackbox kind.")],
            )
        target, target_info = probe_target_info(include_raw=include_raw)
        sources = [target.source]
        data: dict[str, object] = {"kind": normalized, **target_info, "records": {}}
        if target_info["target_mode"] != "kernel":
            return make_response(
                "windbg_blackbox",
                sources,
                data,
                errors=[error_item(
                    "command_unsupported_for_target",
                    "Kernel blackbox records require a kernel target.",
                    stage="target",
                )],
                core_result_status="unavailable",
            )

        selected = list(_COMMANDS) if normalized == "all" else [normalized]
        records = data["records"]
        assert isinstance(records, dict)
        for record_kind in selected:
            evidence = run_read(
                _COMMANDS[record_kind],
                parse_blackbox,
                include_raw=include_raw,
            )
            sources.append(evidence.source)
            if evidence.parsed is not None:
                records[record_kind] = dict(evidence.parsed.data)
            if evidence.execution.status != "completed":
                break
        return make_response("windbg_blackbox", sources, data)
