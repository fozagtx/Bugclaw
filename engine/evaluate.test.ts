import assert from "node:assert/strict";
import test from "node:test";
import { evaluate } from "./evaluate.ts";
import { NESTED_RUNTIME_ADVICE } from "./nested-runtime.ts";
import type { HarnessReport } from "./runner.ts";

function report(ids: string[]): HarnessReport {
	return {
		version: 1,
		name: "benchmark fixture",
		identity: "identity",
		snapshot: "snapshot",
		promptVersion: "prompt",
		models: {
			recon: { provider: "fixture", id: "recon" },
			hunter: { provider: "fixture", id: "hunter" },
			validator: { provider: "fixture", id: "validator" },
		},
		status: "complete",
		reservedCalls: 0,
		recordedTokens: { input: 0, output: 0 },
		verifiedFindings: 0,
		files: [],
		recon: null,
		coverage: [],
		funnel: {
			rawCandidates: ids.length,
			uniqueClusters: ids.length,
			shallowHunts: 0,
			rejected: ids.length,
			needsContext: 0,
			needsReproduction: 0,
			unvalidated: 0,
			vdhDuplicates: 0,
			vvsDuplicates: 0,
			judgedExploitableInSource: 0,
			judgedLatent: 0,
			judgedWrongComponent: 0,
			judgedNotARisk: 0,
			proposedFixes: 0,
		},
		clusters: [],
		wishlist: [],
		declaredTools: [],
		trace: { edges: [], missing: [] },
		architecture: null,
		pashov: {
			origin: "https://github.com/pashov/skills",
			commit: "0000000000000000000000000000000000000000",
			clonedAt: null,
			root: "pashov",
			skills: [],
		},
		fizz: null,
		nestedRuntime: {
			insideContainer: false,
			seccompFilter: false,
			apparmorConfined: false,
			silentFailureRisk: false,
			requiredDockerFlags: ["--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined"],
			advice: NESTED_RUNTIME_ADVICE,
		},
		stageModels: [],
		candidates: ids.map((id) => ({
			id,
			clusterId: id,
			finding: {
				title: "Candidate",
				severity: "low",
				attacker: "tester",
				intentBroken: "fixture guarantee",
				attackClass: "fixture",
				preconditions: ["local fixture"],
				trustBoundary: "fixture",
				rootCause: "fixture",
				impact: "fixture",
				reproduction: ["local test"],
				remediation: "fixture",
				evidence: [],
			},
			origins: [],
			validation: null,
			judgment: null,
			verification: null,
			fixProposal: null,
			status: "rejected",
		})),
	};
}

function labels(overrides: Record<string, unknown> = {}): unknown {
	return {
		reviewer: "security reviewer",
		groundTruth: [{ id: "truth-1" }, { id: "truth-2" }, { id: "truth-3" }],
		matches: [
			{ truthId: "truth-1", candidateId: "candidate-1", verdict: "exact", reason: "same root cause" },
			{ truthId: "truth-2", candidateId: "candidate-2", verdict: "partial", reason: "same issue family" },
		],
		classifications: [
			{ candidateId: "candidate-1", verdict: "true-positive", reason: "reproduced" },
			{ candidateId: "candidate-2", verdict: "true-positive", reason: "supported subset" },
			{ candidateId: "candidate-3", verdict: "false-positive", reason: "guard blocks it" },
			{ candidateId: "candidate-4", verdict: "unknown", reason: "requires environment evidence" },
		],
		...overrides,
	};
}

test("scores a fully classified candidate queue including retained rejected candidates", () => {
	const result = evaluate(report(["candidate-1", "candidate-2", "candidate-3", "candidate-4"]), labels());
	assert.deepEqual(result, {
		reviewer: "security reviewer",
		knownTruth: 3,
		exact: 1,
		partial: 1,
		missed: 1,
		truePositives: 2,
		falsePositives: 1,
		unknown: 1,
		weightedRecall: 0.5,
		precision: 2 / 3,
		warning:
			"Benchmark recall measures only this human-reviewed ground-truth set; it is not real-world recall or a security guarantee.",
	});
});

test("uses null metrics when no truth exists or no candidate was adjudicated", () => {
	const result = evaluate(
		report(["candidate-1"]),
		labels({
			groundTruth: [],
			matches: [],
			classifications: [{ candidateId: "candidate-1", verdict: "unknown", reason: "not reviewed" }],
		}),
	);
	assert.equal(result.weightedRecall, null);
	assert.equal(result.precision, null);
	assert.equal(result.knownTruth, 0);
	assert.equal(result.unknown, 1);
});

test("rejects malformed labels and invalid one-to-one adjudication", () => {
	const fixture = report(["candidate-1", "candidate-2", "candidate-3", "candidate-4"]);
	assert.throws(() => evaluate(fixture, labels({ extra: true })), /Unexpected or missing fields/);
	assert.throws(
		() => evaluate(fixture, labels({ groundTruth: [{ id: "truth-1" }, { id: "truth-1" }] })),
		/Duplicate ground-truth/,
	);
	assert.throws(
		() =>
			evaluate(
				fixture,
				labels({
					matches: [
						{ truthId: "truth-1", candidateId: "candidate-1", verdict: "exact", reason: "first" },
						{ truthId: "truth-1", candidateId: "candidate-2", verdict: "partial", reason: "duplicate" },
					],
				}),
			),
		/Duplicate match ground-truth/,
	);
	assert.throws(
		() =>
			evaluate(
				fixture,
				labels({
					matches: [
						{ truthId: "truth-1", candidateId: "candidate-1", verdict: "exact", reason: "first" },
						{ truthId: "truth-2", candidateId: "candidate-1", verdict: "partial", reason: "duplicate" },
					],
				}),
			),
		/Duplicate match candidate/,
	);
	assert.throws(
		() =>
			evaluate(
				fixture,
				labels({
					matches: [{ truthId: "truth-1", candidateId: "candidate-3", verdict: "exact", reason: "invalid" }],
				}),
			),
		/Matched candidate must be classified true-positive/,
	);
	assert.throws(
		() =>
			evaluate(
				fixture,
				labels({
					classifications: {},
				}),
			),
		/Invalid classifications list/,
	);
});

test("rejects missing candidate labels and unknown candidate references", () => {
	const fixture = report(["candidate-1", "candidate-2", "candidate-3", "candidate-4"]);
	assert.throws(
		() =>
			evaluate(
				fixture,
				labels({ classifications: [{ candidateId: "candidate-1", verdict: "true-positive", reason: "only one" }] }),
			),
		/cover every report candidate/,
	);
	assert.throws(
		() =>
			evaluate(
				fixture,
				labels({
					classifications: [
						{ candidateId: "candidate-1", verdict: "true-positive", reason: "reproduced" },
						{ candidateId: "candidate-2", verdict: "true-positive", reason: "supported" },
						{ candidateId: "candidate-3", verdict: "false-positive", reason: "blocked" },
						{ candidateId: "candidate-4", verdict: "unknown", reason: "unclear" },
						{ candidateId: "unknown", verdict: "unknown", reason: "invalid" },
					],
				}),
			),
		/Unknown candidate ID/,
	);
});

test("rejects malformed report candidates before scoring labels", () => {
	assert.throws(
		() =>
			evaluate({ ...report([]), candidates: [{ id: "duplicate" }, { id: "duplicate" }] } as HarnessReport, labels()),
		/Duplicate report candidate ID: duplicate/,
	);
	assert.throws(
		() => evaluate({ ...report([]), candidates: {} } as HarnessReport, labels()),
		/Invalid report candidates list/,
	);
	assert.throws(
		() => evaluate({ ...report([]), candidates: [{ id: " " }] } as HarnessReport, labels()),
		/Invalid report candidate ID/,
	);
});

test("bounds every reviewer label array", () => {
	const tooManyRows = Array.from({ length: 10_001 }, () => ({ id: "truth" }));
	assert.throws(
		() => evaluate(report([]), labels({ groundTruth: tooManyRows, matches: [], classifications: [] })),
		/Invalid groundTruth list/,
	);
	assert.throws(
		() => evaluate(report([]), labels({ groundTruth: [], matches: tooManyRows, classifications: [] })),
		/Invalid matches list/,
	);
	assert.throws(
		() => evaluate(report([]), labels({ groundTruth: [], matches: [], classifications: tooManyRows })),
		/Invalid classifications list/,
	);
});
