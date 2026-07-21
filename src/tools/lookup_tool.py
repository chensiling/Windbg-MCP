"""Explicit symbol, type, and address lookup tool."""

import re
from typing import Literal

from ._annotations import READ_ONLY_TOOL
from ._evidence import resolve_expression, run_read
from ._models import ToolEnvelope
from ._parser import (
    parse_function_info,
    parse_nearest_symbol,
    parse_symbol_list,
    parse_type_info,
)
from ._response import (
    error_item,
    inference_item,
    make_response,
    next_action,
    validate_intent_text,
)


LookupKind = Literal["auto", "address", "symbol", "type", "function"]


def _auto_route(value: str) -> tuple[str, str]:
    cleaned = value.replace("`", "").lower()
    if (
        cleaned.startswith("0x")
        and re.fullmatch(r"0x[0-9a-f]+", cleaned)
    ) or re.fullmatch(r"[0-9a-f]{8,}", cleaned):
        return "address", "input is a hexadecimal address"
    if value.startswith("@") or value.lower().startswith(("poi(", "dwo(", "qwo(")):
        return "address", "input is a debugger address expression"
    if "*" in value or "?" in value:
        return "symbol", "input contains a symbol wildcard"
    basename = value.rsplit("!", 1)[-1]
    if basename.startswith("_") and basename[1:].upper() == basename[1:]:
        return "type", "input matches a conventional debugger type name"
    return "symbol", "default symbol-search route"


def register_lookup_tool(mcp):
    @mcp.tool(annotations=READ_ONLY_TOOL, structured_output=True)
    def windbg_lookup(what: str, kind: LookupKind = "auto") -> ToolEnvelope:
        """Look up an address, symbol pattern, or type using an explicit route."""

        input_error = validate_intent_text(what, "what")
        if input_error:
            return make_response("windbg_lookup", errors=[input_error])
        requested_kind = kind.lower().strip()
        if requested_kind not in ("auto", "address", "symbol", "type", "function"):
            return make_response(
                "windbg_lookup",
                errors=[error_item(
                    "invalid_argument",
                    "'kind' must be auto, address, symbol, type, or function.",
                )],
            )

        inferences = []
        route = requested_kind
        if route == "auto":
            route, basis = _auto_route(what.strip())
            inferences.append(inference_item("lookup_routing", route, basis))

        data = {"input": what, "kind": route}
        if route == "address":
            resolution, resolved_address = resolve_expression(what)
            sources = [resolution.source]
            if resolved_address is None:
                return make_response(
                    "windbg_lookup",
                    sources,
                    data,
                    inferences=inferences,
                )
            data["resolved_address"] = resolved_address
            evidence = run_read(f"ln {resolved_address}", parse_nearest_symbol)
            sources.append(evidence.source)
        elif route == "symbol":
            evidence = run_read(f"x {what.strip()}", parse_symbol_list)
            sources = [evidence.source]
        elif route == "type":
            evidence = run_read(f"dt {what.strip()}", parse_type_info)
            sources = [evidence.source]
        else:
            evidence = run_read(f".fnent {what.strip()}", parse_function_info)
            sources = [evidence.source]

        if evidence.parsed is not None:
            data.update(dict(evidence.parsed.data))
        actions = []
        if route == "symbol" and len(data.get("symbols", [])) > 50:
            actions.append(next_action(
                "windbg_lookup",
                {"what": what, "kind": "symbol"},
                "Narrow the symbol pattern to reduce matches.",
            ))
        return make_response(
            "windbg_lookup",
            sources,
            data,
            inferences=inferences,
            next_actions=actions,
            core_result_status=(
                "empty" if data.get("found") is False else None
            ),
        )
