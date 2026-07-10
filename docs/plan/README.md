# Delivery Plan

Task files under `tasks/` are executed in dependency order. A task is complete only after an independent review passes and its verification commands succeed.

| Task | Status | Depends on |
|---|---|---|
| `mcp-parser-001` | done | - |
| `mcp-engine-002` | ready | - |
| `mcp-tools-003` | pending | parser, engine |
| `mcp-integration-004` | pending | tools |

Review records are written under `reviews/` during delivery and removed after blocking findings are resolved and the task is merged.
