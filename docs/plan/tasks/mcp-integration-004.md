---
id: mcp-integration-004
scope: mcp-integration
status: ready
depends-on: [mcp-tools-003]
---

## Objective

Expose field-level MCP output schemas, descriptions, server instructions, and safety annotations; update user documentation and add end-to-end contract tests.

## Context

- `docs/architecture/README.md`
- `docs/plan/analysis/mcp-determinism.md`

## Path

- `src/server.py`
- `src/tools/`
- `pyproject.toml`
- `README.md`
- `tests/test_mcp_contract.py`
- `docs/`

## Verification

- `python -m pytest tests/ -v`
- Runtime discovery confirms 12 tools, field-level business-tool output schemas, structured content, non-empty descriptions, and safety annotations.
