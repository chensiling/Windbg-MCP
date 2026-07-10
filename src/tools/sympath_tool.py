"""Symbol path management and symbol-state observations."""

from fnmatch import fnmatchcase
import re
from typing import Literal

from ._annotations import MIXED_EXTERNAL_TOOL
from ._evidence import run_mutation, run_read
from ._models import ToolEnvelope
from ._parser import parse_modules
from ._response import (
    error_item,
    inference_item,
    make_response,
    validate_intent_text,
)


SympathAction = Literal["show", "set", "reload", "check"]


def _symbol_health(modules: list[dict[str, str]]) -> dict[str, object]:
    missing = []
    deferred = []
    partial = []
    for module in modules:
        info = module.get("info", "").lower()
        name = module.get("name", "")
        if "no symbols" in info:
            missing.append(name)
        elif "deferred" in info:
            deferred.append(name)
        elif "export symbols" in info:
            partial.append(name)
    if missing:
        status = "bad" if len(missing) == len(modules) else "partial"
    elif partial:
        status = "partial"
    elif deferred:
        status = "deferred"
    elif modules:
        status = "good"
    else:
        status = "unknown"
    return {
        "status": status,
        "missing_modules": [name for name in missing if name],
        "deferred_modules": [name for name in deferred if name],
        "partial_modules": [name for name in partial if name],
    }


def _health_inference(modules):
    return inference_item(
        "symbol_health",
        _symbol_health(modules),
        "derived from the symbol-state text reported for each module",
    )


def _reload_module_state(module: dict[str, str]) -> str:
    info = module.get("info", "").casefold()
    if any(
        marker in info
        for marker in ("deferred", "no symbols", "export symbols")
    ):
        return "unresolved"
    if "pdb symbols" in info or "symbols loaded" in info:
        return "loaded"
    return "unknown"


def _reload_targets(
    requested_module: str,
    modules: list[dict[str, str]],
) -> list[dict[str, str]]:
    if not requested_module:
        return modules
    pattern = requested_module.casefold()
    return [
        module for module in modules
        if fnmatchcase(module.get("name", "").casefold(), pattern)
    ]


def _validate_symbol_path(path: str):
    if not path.strip():
        return error_item("invalid_argument", "'path' is required.")
    if any(character in path for character in ('"', "\r", "\n", "\x00")):
        return error_item(
            "unsafe_argument",
            "'path' contains an unsafe quote or newline.",
            recoverable=False,
        )
    for segment in path.split(";"):
        value = segment.strip()
        if not value:
            return error_item("invalid_argument", "Symbol path segments cannot be empty.")
        allowed = (
            value.lower().startswith(("srv*", "cache*", "symsrv*", "http://", "https://"))
            or bool(re.match(r"^[a-zA-Z]:\\", value))
            or value.startswith("\\\\")
        )
        if not allowed:
            return error_item(
                "unsafe_argument",
                f"Unsupported symbol path segment: {value}",
                recoverable=False,
            )
    return None


def _normalize_symbol_path(path: str) -> str:
    return ";".join(
        segment.strip().rstrip("\\/").casefold()
        for segment in path.split(";")
    )


def _reported_symbol_paths(raw: str) -> list[str]:
    paths = []
    for line in raw.splitlines():
        label, separator, value = line.partition(":")
        if separator and "symbol search path" in label.casefold() and value.strip():
            paths.append(value.strip())
    return paths


def register_sympath_tool(mcp):
    @mcp.tool(annotations=MIXED_EXTERNAL_TOOL, structured_output=True)
    def windbg_sympath(
        action: SympathAction,
        path: str = "",
        module: str = "",
    ) -> ToolEnvelope:
        """Show, set, reload, or inspect debugger symbol configuration."""

        normalized = action.lower().strip()
        if normalized not in ("show", "set", "reload", "check"):
            return make_response(
                "windbg_sympath",
                errors=[error_item("invalid_argument", "Unknown symbol-path action.")],
                verification_status="not_run",
            )
        if path and normalized != "set":
            path_error = _validate_symbol_path(path)
            if path_error:
                return make_response(
                    "windbg_sympath",
                    errors=[path_error],
                    verification_status="not_run",
                )
        module_error = validate_intent_text(module, "module", required=False)
        if module and not re.fullmatch(r"[A-Za-z0-9_.?*-]+", module):
            module_error = error_item(
                "unsafe_argument",
                "'module' contains unsupported characters.",
                recoverable=False,
            )
        if module_error:
            return make_response(
                "windbg_sympath",
                errors=[module_error],
                verification_status="not_run",
            )

        if normalized == "show":
            evidence = run_read(".sympath")
            return make_response(
                "windbg_sympath",
                [evidence.source],
                {"sympath": evidence.execution.output.strip()},
            )

        if normalized == "set":
            path_error = _validate_symbol_path(path)
            if path_error:
                return make_response(
                    "windbg_sympath",
                    errors=[path_error],
                    verification_status="not_run",
                )
            mutation = run_mutation(f".sympath {path}")
            sources = [mutation.source]
            data = {"requested_path": path}
            if mutation.execution.status != "completed":
                return make_response(
                    "windbg_sympath",
                    sources,
                    data,
                    verification_status="indeterminate",
                )
            query = run_read(".sympath")
            sources.append(query.source)
            data["sympath"] = query.execution.output.strip()
            reported_paths = _reported_symbol_paths(query.execution.output)
            data["reported_paths"] = reported_paths
            query_complete = (
                query.execution.status == "completed"
                and query.execution.complete
            )
            verified = query_complete and any(
                _normalize_symbol_path(reported) == _normalize_symbol_path(path)
                for reported in reported_paths
            )
            if not query_complete or not reported_paths:
                verification_status = "indeterminate"
                errors = [error_item(
                    "verification_indeterminate",
                    "The effective symbol path query did not complete with a path.",
                    stage="verification",
                )]
            elif not verified:
                verification_status = "failed"
                errors = [error_item(
                    "verification_failed",
                    "The effective symbol path did not equal the requested path.",
                    recoverable=False,
                    stage="verification",
                )]
            else:
                verification_status = "verified"
                errors = []
            return make_response(
                "windbg_sympath",
                sources,
                data,
                verification_status=verification_status,
                errors=errors,
            )

        command = f"lm m {module}" if module else "lm"
        if normalized == "reload":
            reload_command = f".reload /f {module}" if module else ".reload /f"
            mutation = run_mutation(reload_command)
            sources = [mutation.source]
            if mutation.execution.status != "completed":
                return make_response(
                    "windbg_sympath",
                    sources,
                    {"module": module or None},
                    verification_status="indeterminate",
                )
        else:
            sources = []

        query = run_read(command, parse_modules)
        sources.append(query.source)
        modules = (
            list(query.parsed.data.get("modules", []))
            if query.parsed is not None
            else []
        )
        query_observed = (
            query.execution.status == "completed"
            and query.execution.complete
            and query.parsed is not None
            and query.parsed.status == "complete"
        )
        verification_errors = []
        verification_status = "not_required"
        if normalized == "reload":
            targets = _reload_targets(module, modules) if query_observed else []
            states = [_reload_module_state(target) for target in targets]
            if not query_observed or not targets:
                verification_status = "indeterminate"
                verification_errors.append(error_item(
                    "verification_indeterminate",
                    "The requested module state could not be observed after symbol reload.",
                    stage="verification",
                ))
            elif "unresolved" in states:
                verification_status = "failed"
                verification_errors.append(error_item(
                    "verification_failed",
                    "One or more requested modules still lack loaded PDB symbols.",
                    stage="verification",
                ))
            elif "unknown" in states:
                verification_status = "indeterminate"
                verification_errors.append(error_item(
                    "verification_indeterminate",
                    "The requested module symbol state was not explicit after reload.",
                    stage="verification",
                ))
            else:
                verification_status = "verified"
        return make_response(
            "windbg_sympath",
            sources,
            {"module": module or None, "modules": modules},
            inferences=[_health_inference(modules)],
            verification_status=verification_status,
            errors=verification_errors,
        )
