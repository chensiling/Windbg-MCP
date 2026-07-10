---
id: mcp-tools-003
scope: tools-and-response
status: done
depends-on: [mcp-parser-001, mcp-engine-002]
---

## Objective

Add typed response models, migrate all business tools to the new execution/parser contracts, separate observations from inferences, preserve per-command evidence, verify mutations, normalize addresses and radix, and fix known WinDbg command semantics.

## Context

- `docs/architecture/README.md`
- `docs/plan/analysis/mcp-determinism.md`

## Path

- `docs/plan/tasks/mcp-tools-003.md`
- `pyproject.toml`
- `src/tools/`
- `tests/test_response.py`
- `tests/test_parser.py`
- `tests/test_tools.py`

## Verification

- `python -m pytest tests/test_response.py tests/test_tools.py -v`
- Tests cover all 12 tools, complete/partial/failed parsing, aggregate sources, address resolution, explicit radix, conditional breakpoints, step-out semantics, mutation verification, inference labeling, and command-separator rejection.
