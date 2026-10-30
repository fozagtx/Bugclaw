import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { huntPrompt, LENSES } from "./prompts.ts";
import type { Recon } from "./schema.ts";
import type { HarnessConfig } from "./scope.ts";
import {
	loadInstalledPashov,
	PASHOV_ORIGIN,
	pashovSlashPreview,
	pashovVendorRoot,
	SOLIDITY_AUDITOR_LENS_IDS,
} from "./pashov.ts";
import { plan } from "./runner.ts";

const repoRoot = dirname(fileURLToPath(import.meta.url));

test("pashov/skills is installed from GitHub with x-ray, solidity-auditor, and fizz", () => {
	const install = loadInstalledPashov();
	assert.equal(install.origin, PASHOV_ORIGIN);
	assert.match(install.commit, /^[0-9a-f]{40}$/);
	assert.deepEqual(
		install.skills.map((skill) => skill.name),
		["x-ray", "solidity-auditor", "fizz"],
	);
	assert.equal(SOLIDITY_AUDITOR_LENS_IDS.length, 12);
	assert.deepEqual(Object.keys(LENSES.web3), SOLIDITY_AUDITOR_LENS_IDS);
	for (const skill of install.skills) {
		assert.equal(existsSync(skill.skillMd), true);
		assert.equal(existsSync(join(pashovVendorRoot(), skill.name, "VERSION")), true);
	}
	assert.equal(existsSync(join(pashovVendorRoot(), "LICENSE")), true);
	assert.match(pashovSlashPreview("x-ray", install), /github.com\/pashov\/skills/);
	assert.match(pashovSlashPreview("fizz", install), /never writes test\/fizz/);
});

test("web3 plan is the twelve solidity-auditor agents plus web2 cells", () => {
	const hunts = plan({
		version: 1,
		name: "pashov-plan",
		authorization: { reference: "test", expiresAt: "2099-01-01T00:00:00Z", allowRemoteModels: false },
		root: ".",
		files: ["x.ts"],
		domains: ["web2", "web3"],
		models: {
			recon: { provider: "t", id: "r" },
			hunter: { provider: "t", id: "h" },
			validator: { provider: "t", id: "v" },
		},
		limits: {
			maxCalls: 80,
			maxInputChars: 1000,
			maxOutputTokens: 100,
			timeoutMs: 1,
			concurrency: 1,
			passes: 1,
			maxFindingsPerTask: 1,
		},
	});
	assert.equal(hunts.length, 20);
	assert.ok(hunts.some((hunt) => hunt.id === "hunt:web3:math-precision:0"));
	assert.ok(hunts.some((hunt) => hunt.id === "hunt:web3:flow-gap:0"));
	assert.equal(
		hunts.filter((hunt) => hunt.id.startsWith("hunt:web3:")).length,
		12,
	);
});

test("ai and web2 plans expose their built-in cells", () => {
	const aiConfig: HarnessConfig = {
		version: 1,
		name: "ai-plan",
		authorization: { reference: "test", expiresAt: "2099-01-01T00:00:00Z", allowRemoteModels: false },
		root: ".",
		files: ["x.ts"],
		domains: ["ai"],
		models: {
			recon: { provider: "t", id: "r" },
			hunter: { provider: "t", id: "h" },
			validator: { provider: "t", id: "v" },
		},
		limits: {
			maxCalls: 80,
			maxInputChars: 1000,
			maxOutputTokens: 100,
			timeoutMs: 1,
			concurrency: 1,
			passes: 1,
			maxFindingsPerTask: 1,
		},
	};
	const aiHunts = plan(aiConfig);
	assert.deepEqual(
		aiHunts.map((hunt) => hunt.id),
		Object.keys(LENSES.ai).map((cell) => `hunt:ai:${cell}:0`),
	);
	const web2Hunts = plan({ ...aiConfig, domains: ["web2"] });
	assert.equal(web2Hunts.length, 8);
	const prompt = huntPrompt(
		"",
		{} as Recon,
		LENSES.ai["agency-and-action-binding"],
		0,
		aiConfig,
		{ cell: "agency-and-action-binding", rejectedPatterns: [], alreadyFound: [] },
	);
	assert.match(prompt, /critical: attacker content or model output gains code execution/);
	assert.match(prompt, /action-binding/);
});
