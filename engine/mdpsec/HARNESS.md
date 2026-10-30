# mdpsec prompt packs in this harness

Cloned from https://github.com/mdpsec/bug-bounty-hunting-prompts and https://github.com/mdpsec/should-i-submit (see each pack's `ORIGIN`). MIT license in each pack's `LICENSE`.

| Upstream piece | Harness mapping | Not executed |
| --- | --- | --- |
| `bug-bounty-hunting-prompts/phases/phase-05b-critical.md` | `vdh.hunt` — mechanism portfolio, So-What test, owned-test-account trap, hardening-miss gate (in `huntPrompt`) | every phase file, `hunt-phase-event`, `provenance.sh` |
| `bug-bounty-hunting-prompts/phases/phase-06-triage.md` | `vdh.validate` — So-What test, prerequisite gate → needs-context (in `verdictPrompt`) | any live target request |
| `bug-bounty-hunting-prompts/phases/phase-08-verify-escalate.md` | `vdh.validate` / `vvs.judgment` — counterevidence rule (in `verdictPrompt`, `judgmentPrompt`) | exploit execution, reproduction |
| `bug-bounty-hunting-prompts/phases/phase-10-self-duplicate-check.md` | `vvs.dedup` — duplicate standard (in `dedupPrompt`) | — |
| `should-i-submit/prompt.md` | `vvs.judgment` — hostile pre-submit reviewer, lead-versus-report gate, hard failures; deterministic `preSubmitGate` rendered as the "Pre-submit gate" section in the report | BOUNDED LIVE VALIDATION mode |

Also never executed: phases 00–04b (recon, access, sweep, closeout, scope, browser walk), browser leases, mitm/HAR capture, test accounts, email/SMS/CAPTCHA/OOB tooling, VPS, screenshots, and any request to a live target. The harness is source-only.

Pre-submit answers are NO, NOT YET, or CANNOT DECIDE SAFELY only. YES is unreachable: the harness never reproduces.

The host agent loads Skill `security-harness` (MCP tools `harness_plan` / `harness_run`). That Skill forbids running the vendored phase files. Original files stay as the upstream source of truth; the independently rewritten rubric constants live in `../mdpsec.ts`.
