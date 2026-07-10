# MCP Architecture

## Purpose And Boundary

Windbg-MCP converts debugging intent into WinDbg commands and returns evidence that an LLM can reason about. The MCP layer owns every mechanically verifiable fact: input validity, command framing, response completeness, parsing completeness, address normalization, and mutation verification. The LLM owns hypotheses, cross-evidence interpretation, and the choice of optional next actions.

```text
LLM intent
   |
   v
FastMCP input schema -> tool orchestration -> CommandExecutor -> SubprocessEngine -> cdb.exe
                              |                     |
                              v                     v
                         ParseResult          ExecutionResult
                              \                   /
                               v                 v
                           typed ToolEnvelope -> MCP client -> LLM reasoning
```

## Execution Contract

`ExecutionResult` is the only result returned across the debugger engine boundary.

| Field | Contract |
|---|---|
| `status` | `completed`, `timeout`, `disconnected`, `failed`, or `indeterminate` |
| `output` | Text received for this command; may be partial when `complete=false` |
| `complete` | True only when the command-specific completion marker was observed |
| `error` | Explicit failure reason, otherwise `None` |
| `attempts` | Number of actual command submissions |
| `session_restarted` | Whether recovery replaced the debugger subprocess |
| `async_output` | Output observed before this command; never silently discarded |

Each command uses an unpredictable marker and the configured timeout. A timeout is never a successful empty response. EOF clears the connected state. Retry is allowed only for commands explicitly marked read-only and retryable. State-changing or unknown commands are never automatically replayed after an indeterminate result.

## Parsing Contract

Every parser returns `ParseResult`:

| Field | Contract |
|---|---|
| `status` | `complete`, `partial`, or `failed` |
| `data` | Mechanically extracted fields only |
| `raw` | Original debugger output |
| `unparsed_lines` | Meaningful lines not covered by the parser |
| `warnings` | Typed explanations of lossy or ambiguous parsing |

Matching one record does not prove completeness. Known prompts, headers, and blank lines may be ignored explicitly; other unmatched meaningful lines make the result `partial`. A failed parser returns no invented data. Address values cross MCP and JSON boundaries as canonical hexadecimal strings, never JSON numbers.

## Tool Response Contract

Business tools return a Pydantic `ToolEnvelope`, not a JSON-encoded string. FastMCP must expose envelope fields through `outputSchema` and `structuredContent`.

Required envelope fields:

- `ok`: true only when all required execution, parsing, and verification stages succeeded.
- `execution_status`, `parse_status`, `verification_status`: independent stage results.
- `data`: observations supported directly by command output.
- `inferences`: rule-based conclusions, each with a name, value, basis, and `certainty="inferred"`.
- `sources`: per-command output and completion metadata. Aggregate tools retain every command source.
- `errors`: typed errors with a stage and recoverability.
- `next_actions`: optional suggestions. They are never automatically executed.
- `raw`: compatibility field for single-command output; `sources` is authoritative.

`windbg_exec` remains an explicit raw escape hatch. It is documented and annotated as open-world and potentially destructive.

## MCP Integration Contract

FastMCP server instructions tell clients to prefer business tools, evaluate `execution_status`, `parse_status`, and `verification_status` independently, treat `sources` as authoritative evidence, and never execute `next_actions` automatically. `data` contains observations; `inferences` contains labeled inferred values.

All 11 business tools publish the field-level `ToolEnvelope` schema and return that envelope directly as MCP `structuredContent`. `windbg_exec` deliberately disables structured output: it publishes no output schema and returns raw text content.

The validated dependency floor for this integration contract is MCP Python SDK 1.28.0 and Pydantic 2.12.0; both are capped below their next major version.

Tool annotations are conservative for tools whose behavior depends on an action or optional argument:

| Tool | Read only | Destructive | Idempotent | Open world |
|---|---:|---:|---:|---:|
| `windbg_context` | yes | no | yes | no |
| `windbg_control` | no | yes | no | yes |
| `windbg_breakpoint` | no | yes | no | no |
| `windbg_read_memory` | yes | no | yes | no |
| `windbg_write_memory` | no | yes | no | no |
| `windbg_disassemble` | yes | no | yes | no |
| `windbg_backtrace` | no | no | no | no |
| `windbg_lookup` | yes | no | yes | no |
| `windbg_analyze` | no | no | no | no |
| `windbg_evaluate` | yes | no | yes | no |
| `windbg_sympath` | no | yes | no | yes |
| `windbg_exec` | no | yes | no | yes |

`windbg_backtrace`, `windbg_analyze`, and `windbg_sympath` are not annotated read-only because some argument combinations change debugger state. Symbol-path operations are open-world because reloads may contact configured symbol servers. Execution control is open-world because resumed target code can affect external systems beyond the debugger.

## State And Inference

Target architecture and session source are independent:

- `target_mode`: `user`, `kernel`, or `unknown`.
- `session_kind`: `live`, `dump`, or `unknown`.

Facts such as registers, parsed addresses, command completion, and verified byte values belong in `data`. Symbol health, likely target state, and routing guesses belong in `inferences` unless WinDbg provides an authoritative status. `deferred` symbol loading is not equivalent to missing symbols.

## Mutation And Safety

Mutation tools do not report `verified` until their postcondition is checked:

- memory write -> read back affected bytes;
- breakpoint change -> refresh and inspect the breakpoint list;
- symbol path/reload -> query the resulting path or module state;
- execution control -> report `running`, a verified break state, or `indeterminate`.

Intent tools reject command separators and newlines unless their documented grammar requires and validates them. Arbitrary command composition belongs only in `windbg_exec`. MCP tool annotations identify read-only, destructive, idempotent, and open-world behavior.

## Address And Numeric Rules

LLMs provide an address expression as text. WinDbg evaluates registers, symbols, pointer dereferences, and arithmetic. MCP validates the expression, invokes WinDbg, and returns both `input` and `resolved_address`. Commands use explicit radix prefixes rather than relying on the debugger's current `.radix` setting.

## Transport And Authentication

The HTTP transport binds to `127.0.0.1` by default. The server does not implement authentication and does not accept a token environment variable. It must not be exposed to an untrusted network without an authenticated reverse proxy or another explicit access-control layer. Debug JSON logs contain commands and target output and must be treated as sensitive.

## Required Tests

- Parser tests cover complete, partial, failed, malformed, multi-line, and architecture-specific samples.
- Engine tests cover timeout, EOF, marker collision resistance, async output preservation, and retry safety.
- Tool tests use an injected executor and verify commands, sources, stage status, postconditions, and inference labeling.
- MCP integration tests inspect discovered input/output schemas, structured content, descriptions, and safety annotations.
- Live sampling covers user/kernel and live/dump modes when suitable targets are available.
