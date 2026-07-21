"""Out-of-band debugger command-channel status and recovery controls."""

from typing import Literal

from ._annotations import MIXED_EXTERNAL_TOOL
from ._models import ToolEnvelope
from ._registry import (
    _interrupt_session,
    _recover_session,
    _session_snapshot,
)
from ._response import error_item, make_response


SessionAction = Literal["status", "interrupt", "recover"]


def _snapshot_data() -> dict[str, object]:
    snapshot = _session_snapshot()
    return {
        "session_state": snapshot.state,
        "debugger_connected": snapshot.connected,
        "active_command_id": snapshot.active_command_id,
        "interrupt_supported": snapshot.interrupt_supported,
    }


def register_session_tool(mcp):
    @mcp.tool(annotations=MIXED_EXTERNAL_TOOL, structured_output=True)
    def windbg_session(
        action: SessionAction = "status",
        command_id: str = "",
    ) -> ToolEnvelope:
        """Inspect, interrupt, or explicitly recover the debugger command channel."""

        normalized = action.lower().strip()
        if normalized not in ("status", "interrupt", "recover"):
            return make_response(
                "windbg_session",
                errors=[error_item("invalid_argument", "Unknown session action.")],
            )

        before = _session_snapshot()
        if normalized == "status":
            return make_response("windbg_session", data=_snapshot_data())

        if normalized == "interrupt":
            requested_id = command_id.strip() or before.active_command_id
            if before.active_command_id is None:
                return make_response(
                    "windbg_session",
                    data=_snapshot_data(),
                    errors=[error_item(
                        "no_active_command",
                        "There is no active debugger command to interrupt.",
                    )],
                )
            if requested_id != before.active_command_id:
                return make_response(
                    "windbg_session",
                    data=_snapshot_data(),
                    errors=[error_item(
                        "command_not_active",
                        "The requested command_id is not the active command.",
                    )],
                )
            if not _interrupt_session(requested_id):
                return make_response(
                    "windbg_session",
                    data=_snapshot_data(),
                    errors=[error_item(
                        "interrupt_failed",
                        "The debugger did not accept an out-of-band interrupt.",
                        stage="execution",
                    )],
                )
            return make_response("windbg_session", data=_snapshot_data())

        recovery_error = _recover_session()
        if recovery_error is not None:
            return make_response(
                "windbg_session",
                data=_snapshot_data(),
                errors=[error_item(
                    "recovery_failed",
                    recovery_error,
                    stage="execution",
                )],
            )
        return make_response("windbg_session", data=_snapshot_data())
