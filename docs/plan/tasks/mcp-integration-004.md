---
id: mcp-integration-004
scope: mcp-integration
status: done
depends-on: [mcp-tools-003]
---

## Objective

Expose field-level MCP output schemas, descriptions, server instructions, and safety annotations; update user documentation and add end-to-end contract tests.

## Context

- `docs/architecture/README.md`
- `docs/plan/analysis/mcp-determinism.md`

## Path

- `docs/plan/tasks/mcp-integration-004.md`
- `src/server.py`
- `src/config.py`
- `src/tools/`
- `pyproject.toml`
- `README.md`
- `tests/test_parser.py`
- `tests/test_mcp_contract.py`
- `docs/`

## Verification

- `python -m pytest tests/ -v`
- Runtime discovery confirms 12 tools, field-level business-tool output schemas, structured content, non-empty descriptions, and safety annotations.
