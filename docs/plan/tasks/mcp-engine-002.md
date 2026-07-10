---
id: mcp-engine-002
scope: debugger-engine
status: done
depends-on: []
---

## Objective

Introduce `ExecutionResult`, enforce configured timeouts, use per-command markers, preserve asynchronous output, clear stale connection state, and prevent automatic replay of non-retryable commands. Correct `tcp:PORT` parsing.

## Context

- `docs/architecture/README.md`
- `docs/plan/analysis/mcp-determinism.md`

## Path

- `docs/plan/tasks/mcp-engine-002.md`
- `src/debugger/engine.py`
- `src/debugger/native_engine.py`
- `src/debugger/executor.py`
- `src/tools/_registry.py`
- `src/server.py`
- `tests/test_engine.py`
- `tests/test_server.py`

## Verification

- `python -m pytest tests/test_engine.py tests/test_server.py -v`
- Tests cover timeout, partial output, unique markers, EOF, async output preservation, read-only retry, mutation no-replay, and both connect-string forms.
