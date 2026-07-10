---
id: mcp-parser-001
scope: parser
status: done
depends-on: []
---

## Objective

Introduce the `ParseResult` contract, migrate every shared parser, and correct known address, memory, stack-parameter, and partial-output defects.

## Context

- `docs/architecture/README.md`
- `docs/plan/analysis/mcp-determinism.md`

## Path

- `src/tools/_parser.py`
- `tests/test_parser.py`
- `docs/plan/tasks/mcp-parser-001.md`

## Verification

- `python -m pytest tests/test_parser.py -v`
- Tests cover complete, partial, failed, multi-line memory, word/qword/ascii formats, unmatched meaningful lines, and parser compatibility with real samples.
