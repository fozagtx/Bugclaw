# Bugclaw

**A private, user-owned security review harness for source code you are authorized to review.**

## Demo

**Working demo / test build:** `https://YOUR-DEMO-URL-HERE` _← replace with your hosted dashboard or a recorded walkthrough before submitting; see “Running the demo locally” for the fastest way to host one._

To run the demo yourself on any machine:

```bash
git clone https://github.com/fozagtx/Bugclaw && cd Bugclaw
npm install
export NEBIUS_API_KEY="<token-factory-key>"   # optional TAVILY_API_KEY below
npx localtunnel --port 8787                   # or cloudflared tunnel --url http://localhost:8787
npm start serve --port 8787
```

Then open the tunnel URL in a browser: the built-in dashboard shows a full scan — candidates, sandbox proofs, evidence bundles, and signoff status — served by `npm start serve`.

Bugclaw takes a local source snapshot, hunts for vulnerabilities with an agentic model pipeline, proves each finding by reproducing it in a network-denied sandbox, proposes a scoped fix, then replays the same proof against the patched code in a fresh sandbox. Every step writes evidence to disk for human review — **no automated result is ever a confirmation, and only a human may sign off**.

Bugclaw is designed to run entirely on your own machine against sources you own. Never point it at third-party live systems.

## Live web evidence (Tavily API)

At **scan time the engine makes real, runtime calls to the Tavily Search API** (`POST https://api.tavily.com/search`). Each first-pass hunt cell gets one bounded web-evidence query about that lens's vulnerability classes (identity, tenancy, oracle handling, reentrancy, …), and the results are injected into the hunt prompt as `WEB_EVIDENCE_DATA` alongside the offline audit corpus. Set a key to enable it:

```bash
export TAVILY_API_KEY="tvly-…"   # get one free at https://app.tavily.com
```

Privacy and safety properties, verified by tests:

- **Queries are lens-level only** — `common vulnerabilities and exploitation techniques: <lens>`. Your source code is never part of a search query.
- **Host-only calls** — Tavily calls happen in the orchestrating process; reproduction sandbox stays fully network-denied. The key never enters a sandbox.
- **Fails closed** — no key → feature silently off (`webEvidence.status: "no-key"`, zero HTTP calls); failed calls are counted in the report (`failedQueries`) and never abort a hunt cell.
- **Untrusted data** — search results are reference material the models may check against the source; the prompt forbids treating an advisory as proof that this code is vulnerable.

The scan report records what happened: `webEvidence: { provider: "tavily", status, queries, failedQueries, cells }`.

## How it works

```
source snapshot ──► engine scan ──► sandbox reproduction ──► scoped fix ──► fix replay ──► human signoff
                    │               │                       │              │
                    recon           fresh micro-sandbox      only cited     same PoC,
                    hunt            per attempt              source files   fresh sandbox
and validate        network denied
```

1. **Snapshot** — Bugclaw copies an authorized source tree into `data/scans/<scan-id>/snapshot/`, records a deterministic manifest with SHA-256 hashes, and pins the scan to that exact content. Git URLs are supported with an optional `#tag-or-ref`; refs with ranges, credentials, or queries are rejected.
2. **Scan (engine, `engine/`)** — recon builds an architecture map, hunts probe the attack surface domain by domain (Web2: identity, tenancy, injection... / Web3: flow gaps, oracle math...), and a validator filters keepers. The engine in `engine/` is derived from secgin at upstream commit `01a3d97`; Bugclaw owns the workflow and adds Nebius structured outputs plus its own sandbox-only reproduction and fix stages.
3. **Reproduce (`src/repro.ts`)** — for each surviving candidate, the model writes a proof-of-concept that must live under `.bugclaw/poc/` and must exercise the exact cited source files. The PoC runs in a **fresh sandbox with networking denied**. Sandboxed stdout, stderr, exit code, file edits, and metadata are preserved under `data/scans/<scan-id>/evidence/`.
4. **Fix (optional, `--fix`)** — the model proposes edits restricted to the cited source files only. The same PoC is replayed in a *fresh* sandbox against the patched copy, and the fix only counts when the proof flips.
5. **Human signoff** — available only through the HTTP API. It is deliberately **not** exposed as an MCP tool, so agents can reproduce and report findings but can never confirm them.

Model validators can be wrong, so validator-rejected candidates still get a sandbox reproduction.

## Requirements

- **Node.js ≥ 22.19** (native TypeScript stripping is used — no build step)
- **Docker** — the reproduction runner builds a local sandbox image on demand
- **OpenShell CLI** with a connected local gateway for network namespaces (pinned by NemoClaw, currently **0.0.116**; the runner image needs `iproute2`)
- **A Nebius Token Factory API key** in the environment

```bash
npm install
export NEBIUS_API_KEY="<your-token-factory-key>"
```

## Quickstart

```bash
npm start scan ./source --auth "Authorized local review" --files src/index.js --domains web2
npm start reproduce <scan-id>
npm start serve --port 8787
```

The scanner sends only the *selected* source files to Nebius Token Factory. Output is JSON: a scan id, candidate findings with citations, and statuses you can pipe into the next command.

### Full workflow

```bash
# 1. Scan an authorized snapshot (a local path or a git URL)
npm start scan ./source --auth "Authorized local review" --files src,lib --domains web2

# 2. Reproduce every candidate in sandboxes
npm start reproduce <scan-id>

# 3. Reproduce and also verify a scoped fix for one candidate
npm start reproduce <scan-id> --candidate <candidate-id> --fix

# 4. Serve the dashboard, HTTP API, and MCP server
npm start serve --port 8787
```

### Terminal reproduction statuses

`reproduced` · `fix-verified` · `fix-failed` · `not-reproduced` · `not-reproducible` · `invalid-poc` · `model-error` · `sandbox-error`

The reproduction runner **never falls back to host execution**. It fails closed with `sandbox-error` if OpenShell or Docker is unavailable, so a "no reproduction" result always means a real sandbox said so, not a missing tool.

## Models and configuration

Defaults use **Nemotron 3 Super** (fast, deep-hunting roles) and **Nemotron 3 Ultra** (high-precision roles) on Nebius Token Factory:

| Stage | Default model |
|---|---|
| Recon, hunter, reproduction | `nebius/nvidia/nemotron-3-super-120b-a12b` |
| Validator, judge, fix | `nebius/nvidia/Nemotron-3-Ultra-550b-a55b` |

Bugclaw only runs NVIDIA Nemotron models via Nebius; any other model id is rejected at startup.

| Variable | Purpose |
|---|---|
| `NEBIUS_API_KEY` | Required. Token Factory API key. |
| `NEBIUS_BASE_URL` | Override the Token Factory API base (default `https://api.tokenfactory.nebius.com/v1`). |
| `BUGCLAW_RECON_MODEL`, `BUGCLAW_HUNTER_MODEL`, `BUGCLAW_VALIDATOR_MODEL`, `BUGCLAW_REPRO_MODEL`, `BUGCLAW_JUDGE_MODEL`, `BUGCLAW_FIX_MODEL` | Per-stage model overrides. |
| `BUGCLAW_DATA` | Private data directory (default `./data`). |
| `BUGCLAW_ENGINE_DIR` | Source-discovery engine location (default `./engine`). |
| `BUGCLAW_MCP_TOKEN` | Bearer token for the MCP/private listeners. Required to bind a non-loopback host. |
| `TAVILY_API_KEY` | Optional. Enables live web evidence via the Tavily API during scans (see above). |

## Serving: dashboard, HTTP API, MCP

`npm start serve` starts two surfaces on one process:

- **HTTP API + dashboard** — JSON endpoints (`/api/health`, `/api/activity`, `/api/scans`, `/api/scans/:id`, `/api/candidates/:id`, `/api/scans/:id/report`, `/api/candidates/:id/report`, `/api/scans/:id/activity`) and the static dashboard in `web/`. The dashboard should be reached via `127.0.0.1` only; the private HTTPS listener serves **only** `/mcp`.
- **MCP Streamable HTTP at `/mcp`** — five tools: `bugclaw_scan`, `bugclaw_status`, `bugclaw_candidates`, `bugclaw_reproduce`, `bugclaw_evidence`. No signoff tool, by design.

Without `BUGCLAW_MCP_TOKEN`, `/mcp` is served to loopback Host headers only (spoofed external Hosts get a 403). With a token set, plain HTTP bearer auth is used everywhere — including non-loopback binds. For TLS:

```bash
npm start serve --host 127.0.0.1 --port 8443 --tls-cert cert.pem --tls-key key.pem
```

### NemoClaw

```bash
export BUGCLAW_MCP_TOKEN=$(openssl rand -hex 32)
npm start serve --host 172.16.255.2 --port 8443 --tls-cert cert.pem --tls-key key.pem
nemoclaw <sandbox> mcp add bugclaw --url https://172.16.255.2:8443/mcp --env BUGCLAW_MCP_TOKEN --trusted-private-host 172.16.255.2
```

The certificate must carry an **IP SAN** for `172.16.255.2`, and its CA must be supplied at onboarding via `NEMOCLAW_CORPORATE_CA_BUNDLE`.

## Data layout

Everything Bugclaw persists lives under the data directory (default `data/`, override with `BUGCLAW_DATA`):

```
data/
├── bugclaw.sqlite          # scans, candidates, reproduction attempts, human signoffs
└── scans/<scan-id>/
    ├── manifest.json       # SHA-256 manifest of the snapshot
    ├── snapshot/           # exact frozen source used for this scan
    ├── engine-output/      # engine state (state.sqlite) and rendered reports
    └── evidence/<candidate-id>/<run-id>/
        ├── poc-N/…         # sandboxed stdout, stderr, exit code, PoC files
        └── …               # one directory per attempt run
```

## Sandbox

Reproduction runs inside a Docker image built from `sandbox/Dockerfile` (Node 22, Python 3, Foundry) executed through the OpenShell CLI with `sandbox/policy.yaml`:

- `network_policies: {}` — networking is denied outright for PoC and fix replay.
- Landlock-enforced filesystem policy: the working tree is readable but the system tree is read-only, and writes are confined to whitelisted paths.
- Each attempt (PoC, judge reruns, fix verification) starts in a *fresh* sandbox so results cannot leak between runs.

## Tests

```bash
npm run test:engine   # engine's own suite (offline; no key needed)
npm test              # core suite + HTTP/server tests
```

The OpenShell integration test in `npm test` runs automatically when a local gateway is available and skips cleanly when it is not. One repository test additionally reads a locally persisted `data/` database produced by a real scan; it skips when that local data is absent.

## Repository layout

```
bin/bugclaw.ts        CLI entry point (scan, reproduce, serve)
src/                  Workflow: config, scan, repro, sandbox, evidence, store, report, server
engine/               Source-discovery engine (derived from secgin @ 01a3d97)
sandbox/              Dockerfile + Landlock/network policy for reproduction runs
web/                  Dashboard (single-page, no build step)
skills/               Bundled skill assets
tests/                Core test suite
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
