import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
	loadInstalledMdpsec,
	MDPSEC_ORIGINS,
	mdpsecVendorRoot,
	preSubmitGate,
} from "./mdpsec.ts";
import {
	dedupPrompt,
	feedbackPrompt,
	huntPrompt,
	judgmentPrompt,
	PROMPT_VERSION,
	verdictPrompt,
} from "./prompts.ts";
import type { Finding, Recon } from "./schema.ts";
import type { HarnessConfig } from "./scope.ts";

const repoRoot = dirname(fileURLToPath(import.meta.url));

test("mdpsec packs are installed from GitHub with ORIGIN and LICENSE", () => {
	const install = loadInstalledMdpsec();
	assert.equal(install.packs.length, 2);
	const byName = new Map(install.packs.map((pack) => [pack.name, pack]));
	for (const [name, origin] of Object.entries(MDPSEC_ORIGINS)) {
		const pack = byName.get(name as keyof typeof MDPSEC_ORIGINS);
		assert.ok(pack, `missing pack ${name}`);
		assert.equal(pack.origin, origin);
		assert.match(pack.commit, /^[0-9a-f]{40}$/);
		assert.equal(existsSync(join(pack.root, "LICENSE")), true);
		assert.equal(existsSync(join(pack.root, "ORIGIN")), true);
	}
	assert.equal(existsSync(join(mdpsecVendorRoot(), "HARNESS.md")), true);
});

test("preSubmitGate never returns YES", () => {
	const cases: { candidate: Parameters<typeof preSubmitGate>[0]; answer: string }[] = [
		{ candidate: { status: "rejected", validation: { verdict: "rejected" } }, answer: "NO" },
		{ candidate: { status: "needs-reproduction", judgment: { verdict: "not-a-risk" } }, answer: "NO" },
		{ candidate: { status: "needs-reproduction", judgment: { verdict: "wrong-component" } }, answer: "NO" },
		{
			candidate: { status: "rejected", validation: { verdict: "needs-context", missingContext: ["victim identifier"] } },
			answer: "CANNOT DECIDE SAFELY",
		},
		{ candidate: { status: "needs-reproduction", judgment: { verdict: "latent" } }, answer: "CANNOT DECIDE SAFELY" },
		{ candidate: { status: "unvalidated" }, answer: "CANNOT DECIDE SAFELY" },
		{ candidate: { status: "needs-reproduction", validation: { verdict: "supported" } }, answer: "NOT YET" },
		{ candidate: { status: "needs-reproduction", judgment: { verdict: "exploitable-in-source" } }, answer: "NOT YET" },
	];
	for (const { candidate, answer } of cases) {
		const gate = preSubmitGate(candidate);
		assert.equal(gate.answer, answer, JSON.stringify(candidate));
		assert.notEqual(gate.answer, "YES");
		assert.ok(gate.why.length > 0);
		assert.ok(gate.next.length > 0);
		assert.ok(gate.doNotRun.length > 0);
	}
	const missing = preSubmitGate({
		status: "rejected",
		validation: { verdict: "needs-context", missingContext: ["the literal missing fact"] },
	});
	assert.ok(missing.why.includes("the literal missing fact"));
});

const recon = { summary: "test", actors: [], invariants: [] } as Recon;
const finding = { title: "t", severity: "medium" } as Finding;
const config = { limits: { maxFindingsPerTask: 3 }, domains: ["web2"] } as HarnessConfig;

test("mdpsec rubrics are folded into stage prompts", () => {
	const hunt = huntPrompt("source", recon, "identity-and-tenancy", 0, config);
	assert.ok(hunt.includes("So-What test"));
	assert.ok(hunt.includes("Owned-test-account trap"));
	assert.ok(hunt.includes("Hardening-miss gate"));
	const verdict = verdictPrompt("source", finding);
	assert.ok(verdict.includes("5. Delivery"));
	assert.ok(verdict.includes("Counterevidence"));
	const judgment = judgmentPrompt("source", finding, []);
	assert.ok(judgment.includes("hostile pre-submit reviewer"));
	assert.ok(judgment.includes("Lead-versus-report gate"));
	assert.ok(dedupPrompt([]).includes("Duplicate standard"));
	assert.ok(feedbackPrompt("source", recon, "notes").includes("Search control"));
	assert.equal(PROMPT_VERSION, "secgin-15");
});
