# plugins

Built-in plugins and the open plugin registry. Plugin authoring docs live under
[`authbridge/docs/`](../../docs/):

- Tutorial: [`docs/plugin-tutorial.md`](../../docs/plugin-tutorial.md)
- Reference: [`docs/plugin-reference.md`](../../docs/plugin-reference.md) — config conventions, invocation contract, registration rules
- Framework architecture: [`docs/framework-architecture.md`](../../docs/framework-architecture.md)

## Built-in plugins

| Name | Purpose |
|---|---|
| `jwt-validation` | Inbound JWT signature / issuer / audience verification |
| `token-exchange` | Outbound RFC 8693 token exchange with per-host routes |
| `a2a-parser` | Parse Agent-to-Agent JSON-RPC traffic into `Extensions.A2A` |
| `mcp-parser` | Parse Model Context Protocol traffic into `Extensions.MCP` |
| `inference-parser` | Parse OpenAI-style / Ollama inference traffic into `Extensions.Inference` |

## Registry

Plugins self-register via `RegisterPlugin(name, factory)` from `init()`.
Third-party plugins can register from any Go module and are linked in via
side-effect import. See
[`docs/plugin-reference.md`](../../docs/plugin-reference.md#registering-a-plugin)
for the contract and
[`docs/plugin-tutorial.md`](../../docs/plugin-tutorial.md#step-6--out-of-tree-plugins)
for the walkthrough.
