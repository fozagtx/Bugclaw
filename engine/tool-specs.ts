/** Cloudflare VDH + VVS stages. Models declare these; they cannot execute them. */
export const HARNESS_TOOLS = {
	"vdh.recon": "Map architecture and write the threat model (three parallel recon passes, then a synthesis).",
	"vdh.hunt": "Per-class attack against one coverage cell, reasoning against the recon intent model. Passes run in sequence; each later pass is told what earlier passes already found. Stay on this cell; fork a sibling instead of wandering.",
	"vdh.validate": "Mechanical schema/path/quote/function checks, then an isolated agent tries to disprove the candidate.",
	"vdh.reverify": "Fresh agent, different from the hunter, checks every factual claim in a surviving candidate against source. Cannot file findings. Verified is not confirmed.",
	"vdh.gapfill": "Enqueue a fresh hunt for a shallow (area × attack-class) cell that returned zero findings. Repeat until cells stop being shallow or the call cap hits.",
	"vdh.dedup": "Cluster overlapping candidates by root cause using deterministic keys, then optional agent shortlist.",
	"vdh.trace": "Walk in-snapshot dependencies; in-snapshot consumers get a sibling hunt, missing repos go to the wishlist.",
	"vdh.feedback": "Rewrite queued hunt prompts from validation failures, shallow cells, and repeated misses.",
	"vdh.report": "Script-only human-readable report. Models must not write this file themselves.",
	"vdh.sibling": "Fork a sibling hunt with a structural seed when an interesting path is outside the current cell.",
	"vdh.wishlist": "Request a missing dependency (build, VM, prod config, consumer repo). Do not invent the result.",
	"vvs.dedup": "Inverted-index shortlist then agent check: reopen a stable key instead of filing a duplicate.",
	"vvs.judgment": "Source-only reachability/risk class. Not production MCP. Different model than the hunter.",
	"vvs.fixing": "Propose a patch and a local test against the original snapshot. Never apply, merge, or run tests.",
	"pashov.xray":
		"Pashov x-ray from https://github.com/pashov/skills: pre-audit threat model, invariants, entry points on scoped source. enumerate.sh / forge coverage / git scripts are not executed.",
	"pashov.auditor":
		"Pashov solidity-auditor from https://github.com/pashov/skills: twelve parallel hunt cells. The orchestrator runs them; models only declare this tool.",
	"pashov.fizz":
		"Pashov fizz from https://github.com/pashov/skills: propose Echidna/Medusa invariant properties. Never write test/fizz into the target. Never run a fuzzer.",
} as const;

export type HarnessToolName = keyof typeof HARNESS_TOOLS;

export const HARNESS_TOOL_NAMES = Object.keys(HARNESS_TOOLS) as HarnessToolName[];

export const OPTIONAL_TOOL_KEYS = ["seed", "lens", "need", "cell", "fromPath", "toPath", "rewrite"] as const;
