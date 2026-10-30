import assert from "node:assert/strict";
import { realpathSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { renderReport } from "./report.ts";
import { type ModelClient, type ModelRequest, type ModelResponse, runHarness } from "./runner.ts";
import type { HarnessConfig, Snapshot } from "./scope.ts";
import { loadSnapshot } from "./scope.ts";
import type { StageModelPrompt } from "./stage-models.ts";
import { RunStore } from "./store.ts";
import { promptStage } from "./tools.ts";

const source =
	"export function transfer(owner: string, amount: number) { return amount; }\n`````\n<img src=x onerror=alert(1)>\n`````\n";
const citation = { path: "target.ts", startLine: 1, endLine: 1, quote: source.split("\n")[0] };
const hostileCitation = {
	path: "target.ts",
	startLine: 2,
	endLine: 4,
	quote: source.split("\n").slice(1, 4).join("\n"),
};

function config(overrides: Partial<HarnessConfig> = {}): HarnessConfig {
	return {
		version: 1,
		name: "offline test",
		authorization: { reference: "authorized-test", expiresAt: "2099-01-01T00:00:00Z", allowRemoteModels: false },
		root: ".",
		files: ["target.ts"],
		domains: ["web2"],
		models: {
			recon: { provider: "fake", id: "recon" },
			hunter: { provider: "fake", id: "hunter" },
			validator: { provider: "fake", id: "validator" },
		},
		limits: {
			maxCalls: 50,
			maxInputChars: 20_000,
			maxOutputTokens: 1_000,
			timeoutMs: 100,
			concurrency: 4,
			passes: 1,
			maxFindingsPerTask: 3,
		},
		...overrides,
	};
}

async function fixture(): Promise<{ directory: string; snapshot: Snapshot }> {
	const directory = await mkdtemp(path.join(realpathSync(tmpdir()), "bugclaw-"));
	await writeFile(path.join(directory, "target.ts"), source);
	return { directory, snapshot: await loadSnapshot(config(), directory) };
}

function recon(overrides: Record<string, unknown> = {}): object {
	return {
		summary: "One local transfer entry point.",
		architecture: "A single transfer function in target.ts.",
		actors: ["untrusted caller"],
		entryPoints: ["target.ts:transfer and caller"],
		trustBoundaries: ["caller to transfer"],
		invariants: ["amount remains bounded"],
		attackClasses: [],
		missingContext: [],
		...overrides,
	};
}

function finding(rootCause = "Amount is not bounded before transfer."): object {
	return {
		title: "Unbounded argument",
		severity: "high",
		attacker: "An untrusted caller",
		intentBroken: "Transfer amounts stay bounded",
		attackClass: "state-and-business-logic",
		preconditions: ["Caller reaches transfer"],
		trustBoundary: "caller to transfer",
		rootCause,
		impact: "A caller can request an excessive amount",
		reproduction: ["Create a local unit test", "Call transfer with a large amount"],
		remediation: "Validate the amount",
		evidence: [citation],
	};
}

function verdict(verdictValue: "supported" | "rejected" | "needs-context"): object {
	return {
		verdict: verdictValue,
		reason: `${verdictValue} from source evidence`,
		evidence: [citation],
		missingContext: verdictValue === "needs-context" ? ["Call-site authorization configuration"] : [],
	};
}

function judgment(
	verdictValue: "exploitable-in-source" | "latent" | "wrong-component" | "not-a-risk" = "latent",
): object {
	return {
		verdict: verdictValue,
		reason: `${verdictValue} from source evidence`,
		evidence: [citation],
		missingContext: verdictValue === "latent" ? ["Production routing"] : [],
	};
}

function fixing(): object {
	return {
		patch: "function transfer(owner, amount) {\n  if (amount > 100) throw new Error('bounded');\n  return amount;\n}\n",
		test: "function testUnbounded() {\n  assert.throws(() => transfer('o', 1e12));\n}\n",
		notes: "Proposal only. Tests are not executed.",
		blocked: true,
		blockReason: "Human review required; tests are not executed",
	};
}

function response(value: object): ModelResponse {
	return { text: JSON.stringify(value), inputTokens: 11, outputTokens: 7 };
}

function reply(
	request: ModelRequest,
	parts: {
		recon?: object;
		hunt?: object;
		verdict?: object;
		feedback?: object;
		judgment?: object;
		fixing?: object;
		fizz?: object;
	} = {},
): ModelResponse {
	const stage = promptStage(request.prompt);
	if (stage === "vdh.recon") return response(parts.recon ?? recon());
	if (stage === "vdh.feedback") return response(parts.feedback ?? { notes: "retry shallow cells", sharperLenses: [] });
	if (stage === "vvs.judgment") return response(parts.judgment ?? judgment());
	if (stage === "vvs.fixing") return response(parts.fixing ?? fixing());
	if (stage === "vvs.dedup") return response({ merges: [] });
	if (stage === "pashov.fizz") {
		return response(
			parts.fizz ?? {
				properties: [],
				blockers: ["Harness does not execute Echidna or Medusa"],
			},
		);
	}
	if (stage === "vdh.reverify") {
		return response({
			verdict: "verified",
			reason: "Cited lines exist in source",
			evidence: [citation],
			missingContext: [],
		});
	}
	if (stage === "vdh.validate") return response(parts.verdict ?? verdict("rejected"));
	return response(parts.hunt ?? { coverage: "target.ts", findings: [] });
}

class FakeClient implements ModelClient {
	readonly requests: ModelRequest[] = [];
	private readonly respond: (request: ModelRequest, index: number) => Promise<ModelResponse> | ModelResponse;

	constructor(respond: (request: ModelRequest, index: number) => Promise<ModelResponse> | ModelResponse) {
		this.respond = respond;
	}

	complete(request: ModelRequest): Promise<ModelResponse> {
		this.requests.push(request);
		return Promise.resolve(this.respond(request, this.requests.length - 1));
	}
}

async function run(
	directory: string,
	snapshot: Snapshot,
	harnessConfig: HarnessConfig,
	client: ModelClient,
	prompt?: StageModelPrompt,
) {
	const store = new RunStore(path.join(directory, "state"), "test-identity");
	try {
		return await runHarness(harnessConfig, snapshot, store, client, { prompt });
	} finally {
		store.close();
	}
}

test("runs the complete offline Web2 and Web3 schedule", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const harnessConfig = config({ domains: ["web2", "web3"] });
		const client = new FakeClient((request) => reply(request));
		const report = await run(directory, snapshot, harnessConfig, client);
		assert.equal(report.status, "complete");
		assert.equal(report.reservedCalls, 46);
		assert.equal(client.requests.filter((request) => promptStage(request.prompt) === "vdh.recon").length, 4);
		assert.equal(client.requests.filter((request) => promptStage(request.prompt) === "pashov.fizz").length, 1);
		assert.equal(client.requests.filter((request) => promptStage(request.prompt) === "vdh.hunt" || promptStage(request.prompt) === "vdh.gapfill").length, 40);
		assert.ok(report.coverage.some((cell) => cell.task === "hunt:web2:identity-and-tenancy:0"));
		assert.ok(report.coverage.some((cell) => cell.task === "hunt:web3:flow-gap:0"));
		assert.ok(report.coverage.some((cell) => cell.task === "pashov.fizz"));
		assert.ok(report.coverage.some((cell) => cell.task === "gapfill:hunt:web2:identity-and-tenancy:0"));
		assert.ok(report.coverage.some((cell) => cell.task === "recon:architecture"));
		assert.ok(report.coverage.some((cell) => cell.task === "trace"));
		assert.ok(report.coverage.some((cell) => cell.task === "feedback"));
		assert.ok(report.coverage.some((cell) => cell.task === "vvs-dedup"));
		assert.equal(report.funnel.shallowHunts, 40);
		assert.equal(report.pashov.origin, "https://github.com/pashov/skills");
		assert.equal(report.pashov.skills.map((skill) => skill.name).join(","), "x-ray,solidity-auditor,fizz");
		assert.deepEqual(report.fizz?.blockers, ["Harness does not execute Echidna or Medusa"]);
		assert.equal(report.verifiedFindings, 0);
		assert.match(client.requests[0].system, /vdh\.hunt/);
		assert.match(client.requests[0].system, /vvs\.judgment/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("keeps supported candidates as unverified reproduction work and isolates validator context", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const client = new FakeClient((request) =>
			reply(request, {
				hunt: { coverage: "target.ts", findings: [finding()] },
				verdict: verdict("supported"),
				judgment: judgment("latent"),
			}),
		);
		const report = await run(directory, snapshot, config(), client);
		assert.equal(report.verifiedFindings, 0);
		assert.equal(report.candidates.length, 1);
		assert.equal(report.candidates[0].status, "needs-reproduction");
		assert.equal(report.candidates[0].clusterId.length, 24);
		assert.equal(report.funnel.needsReproduction, 1);
		assert.equal(report.clusters.length, 1);
		assert.equal(report.candidates[0].validation?.verdict, "supported");
		assert.equal(report.candidates[0].verification?.verdict, "verified");
		const validatorRequest = client.requests.find((request) => request.model.id === "validator")!;
		assert.match(validatorRequest.prompt, /CANDIDATE_DATA=/);
		assert.doesNotMatch(validatorRequest.prompt, /RECON_DATA=/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("retains rejected and context-dependent validation outcomes", async () => {
	const { directory, snapshot } = await fixture();
	try {
		let validations = 0;
		const client = new FakeClient((request) => {
			if (promptStage(request.prompt) === "vdh.validate") {
				return reply(request, { verdict: verdict(validations++ === 0 ? "rejected" : "needs-context") });
			}
			return reply(request, {
				hunt: { coverage: "target.ts", findings: [finding("first cause"), finding("second cause")] },
			});
		});
		const report = await run(directory, snapshot, config(), client);
		assert.deepEqual(
			new Set(report.candidates.map((candidate) => candidate.status)),
			new Set(["rejected", "needs-context"]),
		);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("fails malformed HTTP-success model bodies rather than calling the run clean", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const client = new FakeClient(() => ({
			text: JSON.stringify({ error: "upstream returned an error despite HTTP 200" }),
			inputTokens: 0,
			outputTokens: 0,
		}));
		const report = await run(directory, snapshot, config(), client);
		assert.equal(report.status, "incomplete");
		assert.deepEqual(
			report.coverage.find((cell) => cell.task === "recon:architecture"),
			{ task: "recon:architecture", status: "failed", details: null, error: "provider-error-in-body", shallow: false },
		);
		assert.equal(report.coverage.find((cell) => cell.task === "recon")?.error, "recon-subagents-failed");
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("rejects findings with nonexistent paths and inexact evidence quotes", async () => {
	const { directory, snapshot } = await fixture();
	try {
		for (const badCitation of [
			{ ...citation, path: "missing.ts" },
			{ ...citation, quote: "not the cited source" },
		]) {
			const state = await mkdtemp(path.join(directory, "case-"));
			const client = new FakeClient((request) =>
				reply(request, { hunt: { coverage: "target.ts", findings: [{ ...finding(), evidence: [badCitation] }] } }),
			);
			const report = await run(state, snapshot, config({ limits: { ...config().limits, maxCalls: 5 } }), client);
			assert.ok(report.coverage.some((cell) => cell.task.startsWith("hunt:") && cell.status === "failed"));
			assert.ok(report.coverage.some((cell) => cell.task.startsWith("hunt:") && cell.error === "invalid-model-output"));
		}
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("resumes completed tasks without additional model calls", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const client = new FakeClient((request) => reply(request, { hunt: { coverage: "target.ts", findings: [] } }));
		await run(directory, snapshot, config(), client);
		const calls = client.requests.length;
		const resumed = await run(directory, snapshot, config(), client);
		assert.equal(client.requests.length, calls);
		assert.equal(resumed.status, "complete");
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("hard-caps reservations under concurrent hunters and charges timed-out calls", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const client = new FakeClient((request) =>
			promptStage(request.prompt) === "vdh.recon" ? reply(request) : new Promise<ModelResponse>(() => {}),
		);
		const report = await run(
			directory,
			snapshot,
			config({ limits: { ...config().limits, maxCalls: 5, timeoutMs: 15 } }),
			client,
		);
		assert.equal(client.requests.length, 5);
		assert.equal(report.reservedCalls, 5);
		assert.equal(report.coverage.find((cell) => cell.task.startsWith("hunt:") && cell.status === "failed")?.error, "model-error-or-timeout");
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("deduplicates identical candidates without collapsing distinct root causes", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const client = new FakeClient((request) =>
			reply(request, {
				hunt: { coverage: "target.ts", findings: [finding("same root cause"), finding("different root cause")] },
			}),
		);
		const report = await run(directory, snapshot, config(), client);
		assert.equal(report.candidates.length, 2);
		assert.ok(report.candidates.every((candidate) => candidate.origins.length === 8));
		assert.deepEqual(
			new Set(report.candidates.map((candidate) => candidate.finding.rootCause)),
			new Set(["same root cause", "different root cause"]),
		);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("escapes hostile report fields so generated markdown contains no active HTML", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const client = new FakeClient((request) =>
			reply(request, {
				recon: { ...recon(), summary: "<img src=x onerror=alert(1)>" },
				hunt: {
					coverage: "<script>alert(1)</script>",
					findings: [{ ...finding("<b>root</b>"), title: "<svg onload=alert(1)>", evidence: [hostileCitation] }],
				},
			}),
		);
		const report = await run(directory, snapshot, config(), client);
		const markdown = renderReport(report);
		assert.ok(markdown.includes("&lt;img src=x onerror=alert\\(1\\)&gt;"));
		assert.ok(markdown.includes("&lt;script&gt;alert\\(1\\)&lt;/script&gt;"));
		assert.ok(markdown.includes("&lt;svg onload=alert\\(1\\)&gt;"));
		assert.ok(markdown.includes("&lt;b&gt;root&lt;/b&gt;"));
		assert.ok(markdown.includes("Pre-submit gate"));
		assert.ok(markdown.includes("## mdpsec prompt packs"));
		assert.doesNotMatch(markdown, /Should you submit[^\n]*YES/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("parses fenced JSON and hunts recon-invented attack classes", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const client = new FakeClient((request) => {
			if (promptStage(request.prompt) === "vdh.recon") {
				return {
					text: `\`\`\`json\n${JSON.stringify(
						recon({
							attackClasses: [
								{
									id: "callback-ordering",
									methodology: "Trace whether success callbacks can run twice on the same credit.",
								},
							],
						}),
					)}\n\`\`\``,
					inputTokens: 11,
					outputTokens: 7,
				};
			}
			return reply(request);
		});
		const report = await run(directory, snapshot, config(), client);
		assert.equal(report.status, "complete");
		assert.ok(report.coverage.some((cell) => cell.task === "hunt:dynamic:callback-ordering:0"));
		assert.ok(report.coverage.some((cell) => cell.task === "gapfill:hunt:dynamic:callback-ordering:0"));
		assert.equal(report.recon?.attackClasses[0]?.id, "callback-ordering");
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("prompts for a better model before each pending stage and uses the swapped hunter", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const stages: string[] = [];
		const prompt: StageModelPrompt = {
			async choose(request) {
				stages.push(`${request.stage}:${request.role}`);
				if (request.role === "hunter") return { provider: "fake", id: "hunter-better" };
				return request.current;
			},
		};
		const client = new FakeClient((request) =>
			reply(request, { hunt: { coverage: "target.ts", findings: [finding()] } }),
		);
		const report = await run(directory, snapshot, config(), client, prompt);
		assert.deepEqual(stages, ["recon:recon", "hunt:hunter", "validate:validator", "feedback:hunter"]);
		assert.ok(client.requests.some((request) => request.model.id === "hunter-better"));
		assert.equal(report.stageModels.find((entry) => entry.stage === "hunt")?.model.id, "hunter-better");
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("omits unrelated snapshot files from hunt context instead of stuffing the window", async () => {
	const directory = await mkdtemp(path.join(realpathSync(tmpdir()), "bugclaw-"));
	try {
		await writeFile(path.join(directory, "target.ts"), source);
		await writeFile(path.join(directory, "noise.ts"), `${"padding\n".repeat(900)}export const unused = 1;\n`);
		const harnessConfig = config({ files: ["target.ts", "noise.ts"] });
		const snapshot = await loadSnapshot(harnessConfig, directory);
		const client = new FakeClient((request) => reply(request));
		await run(directory, snapshot, harnessConfig, client);
		const hunt = client.requests.find((request) => promptStage(request.prompt) === "vdh.hunt");
		assert.ok(hunt);
		assert.match(hunt.prompt, /FILE: target\.ts/);
		assert.match(hunt.prompt, /OMITTED_FILES=.*noise\.ts/);
		assert.doesNotMatch(hunt.prompt, /FILE: noise\.ts/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("runs declared VDH sibling and wishlist tools, then VVS judgment on survivors", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const client = new FakeClient((request) =>
			reply(request, {
				hunt: {
					coverage: "target.ts",
					findings: [finding()],
					tools: [
						{
							tool: "vdh.sibling",
							reason: "Callback path is outside this cell",
							seed: "trace success callbacks after transfer",
							lens: "Walk the success callback after transfer and look for a second credit.",
						},
						{
							tool: "vdh.wishlist",
							reason: "Need the caller that wires transfer",
							need: "caller module that invokes transfer",
						},
					],
				},
				verdict: verdict("supported"),
				judgment: judgment("exploitable-in-source"),
			}),
		);
		const report = await run(directory, snapshot, config(), client);
		assert.ok(report.wishlist.some((item) => item.need.includes("caller module")));
		assert.ok(report.declaredTools.some((entry) => entry.tools.some((tool) => tool.tool === "vdh.sibling")));
		assert.ok(report.coverage.some((cell) => cell.task.startsWith("hunt:sibling:")));
		assert.equal(report.candidates[0]?.status, "needs-reproduction");
		assert.equal(report.candidates[0]?.verification?.verdict, "verified");
		assert.equal(report.candidates[0]?.judgment?.verdict, "exploitable-in-source");
		assert.equal(report.candidates[0]?.verification?.verdict, "verified");
		assert.equal(report.candidates[0]?.fixProposal?.blocked, true);
		assert.equal(report.verifiedFindings, 0);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("rejects vacuous findings in plain code before a validator ever sees them", async () => {
	const { directory, snapshot } = await fixture();
	try {
		const client = new FakeClient((request) =>
			reply(request, {
				hunt: {
					coverage: "target.ts",
					findings: [
						{
							...finding(),
							impact: "An attacker could theoretically cause an error",
							rootCause: " theoretically possible",
						},
					],
				},
			}),
		);
		const report = await run(directory, snapshot, config(), client);
		assert.ok(report.coverage.some((cell) => cell.task.startsWith("hunt:") && cell.error === "invalid-model-output"));
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test("trace walks in-snapshot imports into sibling hunts instead of inventing consumer repos", async () => {
	const directory = await mkdtemp(path.join(realpathSync(tmpdir()), "bugclaw-"));
	try {
		await writeFile(path.join(directory, "entry.ts"), 'import { ping } from "./util";\nexport function run() { return ping(); }\n');
		await writeFile(path.join(directory, "util.ts"), "export function ping() { return 1; }\n");
		const harnessConfig = config({ files: ["entry.ts", "util.ts"] });
		const snapshot = await loadSnapshot(harnessConfig, directory);
		const client = new FakeClient((request) => reply(request));
		const report = await run(directory, snapshot, harnessConfig, client);
		assert.ok(report.trace.edges.some((edge) => edge.fromPath === "entry.ts" && edge.toPath === "util.ts"));
		assert.ok(report.coverage.some((cell) => cell.task.startsWith("hunt:trace:")));
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});
