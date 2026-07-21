"""Read-only paged access to retained raw command evidence."""

from ._annotations import READ_ONLY_TOOL
from ._evidence_store import get_evidence
from ._models import ToolEnvelope
from ._response import error_item, limitation_item, make_response, parse_int_arg


def register_output_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_output(
        command_id: str,
        offset: str = "0",
        limit: str = "0x2000",
    ) -> ToolEnvelope:
        """Read a bounded slice of raw debugger output retained for a command ID."""

        evidence_id = command_id.strip()
        if not evidence_id:
            return make_response(
                "windbg_output",
                errors=[error_item("invalid_argument", "'command_id' is required.")],
            )
        offset_value, offset_error = parse_int_arg(
            offset,
            "offset",
            default=0,
            min_value=0,
            max_value=1_000_000,
        )
        limit_value, limit_error = parse_int_arg(
            limit,
            "limit",
            default=0x2000,
            min_value=1,
            max_value=0x8000,
        )
        if offset_error or limit_error:
            return make_response(
                "windbg_output",
                errors=[
                    error for error in (offset_error, limit_error)
                    if error is not None
                ],
            )

        record = get_evidence(evidence_id)
        if record is None:
            return make_response(
                "windbg_output",
                data={"command_id": evidence_id},
                errors=[error_item(
                    "evidence_not_found",
                    "Raw evidence is unknown or has expired from the in-memory cache.",
                    stage="output",
                )],
            )

        end = min(offset_value + limit_value, record.stored_size)
        chunk = record.output[offset_value:end]
        limitations = []
        if record.truncated:
            limitations.append(limitation_item(
                "evidence_storage_truncated",
                (
                    f"Stored {record.stored_size} of {record.original_size} "
                    "raw output characters."
                ),
                path="data.output",
            ))
        return make_response(
            "windbg_output",
            data={
                "command_id": evidence_id,
                "offset": offset_value,
                "next_offset": end,
                "returned_size": len(chunk),
                "stored_size": record.stored_size,
                "original_size": record.original_size,
                "has_more": end < record.stored_size,
                "output": chunk,
            },
            limitations=limitations,
        )
