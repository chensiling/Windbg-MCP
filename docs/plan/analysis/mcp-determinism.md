# Deterministic MCP Delivery Analysis

## Objective

Implement the contract in `docs/architecture/README.md` without expanding the public tool count.

## Module Decomposition

| Module | Inputs | Outputs | Task |
|---|---|---|---|
| `src/tools/_parser.py` | debugger text | `ParseResult` | `mcp-parser-001` |
| `src/debugger/*` | command, timeout, retry policy | `ExecutionResult` | `mcp-engine-002` |
| `src/tools/_response.py`, `_registry.py` | execution and parse results | typed `ToolEnvelope` | `mcp-tools-003` |
| intent tool modules | validated intent | observations, inferences, sources | `mcp-tools-003` |
| FastMCP registration | typed tools | MCP schemas and annotations | `mcp-integration-004` |

## Integration Enumeration

1. `server.main()` creates `SubprocessEngine`, injects it into `CommandExecutor`, then calls `set_executor()` before registering tools.
2. `_registry` forwards retry policy and returns `ExecutionResult` without flattening status into text.
3. Tools pass `ExecutionResult.output` to a parser and pass both results to response helpers.
4. Response helpers preserve every command in `sources`, derive stage statuses, and construct `ToolEnvelope`.
5. FastMCP derives a field-level output schema from the Pydantic return annotation.
6. Mutation tools execute a command and a deterministic verification query before reporting `verified`.

## Delivery Boundaries

Parser and engine foundations have no overlapping code paths and can be developed in parallel. Tool adaptation depends on both contracts and is delivered atomically so the main branch never contains half-migrated tools. Integration verification follows the complete tool migration.

## Explicitly Deferred

- A persistent debugger event stream or event database.
- Automated root-cause ranking.
- Authentication design beyond removing or documenting unused configuration.
- Guaranteed live coverage when no suitable WinDbg target is available.
