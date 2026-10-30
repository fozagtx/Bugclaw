# Pashov skills in this harness

Cloned from https://github.com/pashov/skills (see `ORIGIN`). MIT license in `LICENSE`.

| Skill | Harness mapping | Not executed |
| --- | --- | --- |
| `x-ray/` | VDH recon + `x-ray.md` | `enumerate.sh`, forge/hardhat coverage, git security script |
| `solidity-auditor/` | twelve `vdh.hunt` cells | shell `find`, live Agent spawn outside the orchestrator, `assemble.sh`, `.solidity-auditor/` runs/memory ledger, loop-mode pass picker |
| `fizz/` | `pashov.fizz` propose-only | Echidna, Medusa, Foundry, writes into the target |

solidity-auditor v4 loop mode maps to the Bugclaw engine's sequential hunt passes: each later pass receives an already-found list. Its report-language rules (`references/report-language.md`, Simplified Technical English) are folded into the hunt prompt for finding titles and rootCause.

The Bugclaw agent calls source-analysis tools. Vendored scripts in this reference material are never executed.

Evals/benchmarks from upstream were not copied (no canned targets).
