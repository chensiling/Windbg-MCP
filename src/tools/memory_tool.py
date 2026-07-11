"""Memory read and verified byte-write tools."""

import re
from typing import Literal

from ._annotations import DESTRUCTIVE_TOOL, READ_ONLY_TOOL
from ._evidence import resolve_expression, run_mutation, run_read
from ._models import ToolEnvelope
from ._parser import parse_memory_dump
from ._response import (
    error_item,
    make_response,
    parse_int_arg,
    validate_intent_text,
)


MemoryFormat = Literal[
    "auto", "byte", "b", "word", "w", "dword", "d",
    "qword", "q", "ascii", "a",
]
_FORMAT_COMMAND = {
    "auto": "d",
    "byte": "b",
    "b": "b",
    "word": "w",
    "w": "w",
    "dword": "d",
    "d": "d",
    "qword": "q",
    "q": "q",
    "ascii": "a",
    "a": "a",
}


def _parse_byte_values(values: str) -> tuple[list[str], object | None]:
    tokens = values.split()
    if not tokens:
        return [], error_item("invalid_argument", "'values' is required.")
    if len(tokens) > 0x400:
        return [], error_item(
            "invalid_argument",
            "'values' cannot contain more than 1024 bytes.",
        )
    parsed = []
    for token in tokens:
        if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,2}", token):
            return [], error_item(
                "invalid_argument",
                "'values' must contain space-separated byte values.",
            )
        parsed.append(f"0x{int(token, 16):02x}")
    return parsed, None


def _same_address(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return int(left.replace("`", ""), 0) == int(right.replace("`", ""), 0)
    except ValueError:
        return False


def register_memory_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_read_memory(
        address: str,
        size: str = "0x20",
        format: MemoryFormat = "auto",
    ) -> ToolEnvelope:
        """Read `size` selected-format elements; `size` is not a byte count."""

        input_error = validate_intent_text(address, "address")
        if input_error:
            return make_response("windbg_read_memory", errors=[input_error])
        normalized_format = format.lower().strip()
        if normalized_format not in _FORMAT_COMMAND:
            return make_response(
                "windbg_read_memory",
                errors=[error_item(
                    "invalid_argument",
                    "'format' must be auto, byte, word, dword, qword, or ascii.",
                )],
            )
        size_value, size_error = parse_int_arg(
            size,
            "size",
            default=0x20,
            min_value=1,
            max_value=0x400,
        )
        if size_error:
            return make_response("windbg_read_memory", errors=[size_error])

        resolution, resolved_address = resolve_expression(address)
        sources = [resolution.source]
        data = {
            "input": address,
            "requested_format": normalized_format,
            "requested_size": size_value,
        }
        if resolved_address is None:
            return make_response("windbg_read_memory", sources, data)
        data["resolved_address"] = resolved_address

        read = run_read(
            f"d{_FORMAT_COMMAND[normalized_format]} {resolved_address} L0n{size_value}",
            parse_memory_dump,
        )
        sources.append(read.source)
        if read.parsed is not None:
            data.update(dict(read.parsed.data))
        return make_response("windbg_read_memory", sources, data)

    @mcp.tool(
        annotations=DESTRUCTIVE_TOOL,
        structured_output=True,
    )
    def windbg_write_memory(address: str, values: str) -> ToolEnvelope:
        """Write bytes and verify the postcondition with an immediate readback."""

        address_error = validate_intent_text(address, "address")
        values_error = validate_intent_text(values, "values")
        if address_error or values_error:
            return make_response(
                "windbg_write_memory",
                errors=[error for error in (address_error, values_error) if error],
                verification_status="not_run",
            )
        expected_values, byte_error = _parse_byte_values(values)
        if byte_error:
            return make_response(
                "windbg_write_memory",
                errors=[byte_error],
                verification_status="not_run",
            )

        resolution, resolved_address = resolve_expression(address)
        sources = [resolution.source]
        data = {"input": address, "requested_values": expected_values}
        if resolved_address is None:
            return make_response(
                "windbg_write_memory",
                sources,
                data,
                verification_status="not_run",
            )
        data["resolved_address"] = resolved_address

        write = run_mutation(f"eb {resolved_address} {' '.join(expected_values)}")
        sources.append(write.source)
        if write.execution.status != "completed":
            return make_response(
                "windbg_write_memory",
                sources,
                data,
                verification_status="indeterminate",
                errors=[error_item(
                    "verification_not_run",
                    "Memory write did not complete; readback was not attempted.",
                    stage="verification",
                )],
            )

        readback = run_read(
            f"db {resolved_address} L0n{len(expected_values)}",
            parse_memory_dump,
        )
        sources.append(readback.source)
        readback_data = (
            dict(readback.parsed.data)
            if readback.parsed is not None
            else {}
        )
        entries = [
            entry for entry in readback_data.get("data", [])
            if isinstance(entry, dict)
        ]
        observed_values = []
        observed_offsets = []
        for entry in entries:
            value = entry.get("value")
            offset = entry.get("offset")
            if isinstance(value, str):
                observed_values.append(f"0x{value.lower().zfill(2)}")
            if isinstance(offset, str):
                observed_offsets.append(offset.lower())
        readback_address = readback_data.get("address")
        data["readback_address"] = readback_address
        data["readback_offsets"] = observed_offsets
        data["readback_values"] = observed_values

        readback_complete = (
            readback.execution.status == "completed"
            and readback.parsed is not None
            and readback.parsed.status == "complete"
        )
        address_matches = _same_address(readback_address, resolved_address)
        range_matches = (
            readback_data.get("format") == "hex_byte"
            and len(entries) == len(expected_values)
            and observed_offsets == [
                f"0x{offset:x}" for offset in range(len(expected_values))
            ]
        )
        values_match = observed_values == expected_values
        verified = (
            readback_complete
            and address_matches
            and range_matches
            and values_match
        )
        errors = []
        if not readback_complete:
            errors.append(error_item(
                "verification_indeterminate",
                "Memory readback was not complete enough to verify the write.",
                stage="verification",
            ))
        elif not address_matches or not range_matches:
            errors.append(error_item(
                "verification_failed",
                "Memory readback did not cover the requested address and contiguous byte range.",
                recoverable=False,
                stage="verification",
            ))
        elif not values_match:
            errors.append(error_item(
                "verification_failed",
                "Memory readback did not match the requested byte values.",
                recoverable=False,
                stage="verification",
            ))
        return make_response(
            "windbg_write_memory",
            sources,
            data,
            verification_status=(
                "verified" if verified else "failed" if readback_complete
                else "indeterminate"
            ),
            errors=errors,
        )
