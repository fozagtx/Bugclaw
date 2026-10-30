# Bugclaw

Bugclaw is a private, user-owned source security review harness. It discovers candidates from an authorized source snapshot, tests them in a network-denied OpenShell sandbox, proposes a scoped fix, replays the same proof against a patched copy in a fresh sandbox, and preserves evidence for human review. No automated result is a confirmation; only a human may sign off.

The Bugclaw engine in `engine/` is derived from secgin at upstream commit `01a3d97`. Bugclaw owns the workflow and applies Nebius structured outputs and its sandbox-only reproduction/fix stages.

## Requirements

- Node.js >= 22.19 and Docker
- NVIDIA OpenShell CLI and a connected local gateway
- `NEBIUS_API_KEY` in the process environment

The default API is `https://api.tokenfactory.nebius.com/v1`. Defaults use Nemotron 3 Super for recon, hunt, and reproduction, and Nemotron 3 Ultra for validation, judgment, and fixes. `NEBIUS_BASE_URL` and the `BUGCLAW_*_MODEL` variables may override them. `BUGCLAW_DATA` selects the private data directory; `BUGCLAW_ENGINE_DIR` selects the source-discovery engine.

```sh
npm install
export NEBIUS_API_KEY="<your-token-factory-key>"
npm run test:engine
npm test
npm start scan ./source --auth "Authorized local review" --files src/index.js --domains web2
npm start reproduce <scan-id>
npm start serve --port 8787
```

The scanner sends selected source to Nebius Token Factory. The reproduction runner never falls back to host execution and fails closed if OpenShell or Docker is unavailable. Evidence, the SQLite database, and scan snapshots live under `data/`. To start the HTTP API instead, run `npm start serve`; MCP Streamable HTTP is available at `/mcp`. Human signoff is available only through the HTTP API.

`npm run test:engine` executes the engine's own test suite. The OpenShell integration test in `npm test` skips only when the local gateway is unavailable.
