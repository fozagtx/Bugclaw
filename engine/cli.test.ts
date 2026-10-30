import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { NESTED_RUNTIME_ADVICE } from "./nested-runtime.ts";
import type { HarnessReport } from "./runner.ts";

const cli = fileURLToPath(new URL("./cli.ts", import.meta.url));
const repoRoot = fileURLToPath(new URL(".", import.meta.url));

function invoke(...args: string[]) {
	return invokeWithEnv(process.env, ...args);
}

function invokeWithEnv(env: NodeJS.ProcessEnv, ...args: string[]) {
	return spawnSync(process.execPath, ["--experimental-strip-types", cli, ...args], {
		cwd: repoRoot,
		encoding: "utf8",
		env: { ...env },
		timeout: 30000,
	});
}

function writeAuthorizedScope(directory: string): string {
	writeFileSync(join(directory, "app.ts"), "export function ping(): string { return \"ok\"; }\n");
	const scope = join(directory, "scope.json");
	writeFileSync(
		scope,
		JSON.stringify({
			version: 1,
			name: "cli-plan-test",
			authorization: { reference: "test", expiresAt: "2099-01-01T00:00:00Z", allowRemoteModels: false },
			root: ".",
			files: ["app.ts"],
			domains: ["web2", "web3"],
			models: {
				recon: { provider: "test", id: "recon" },
				hunter: { provider: "test", id: "hunter" },
				validator: { provider: "test", id: "validator" },
			},
			limits: {
				maxCalls: 24,
				maxInputChars: 20000,
				maxOutputTokens: 1024,
				timeoutMs: 1000,
				concurrency: 2,
				passes: 1,
				maxFindingsPerTask: 3,
			},
		}),
	);
	return scope;
}

function writeRemoteScope(directory: string, maxCalls = 400): string {
	writeFileSync(join(directory, "a.ts"), "export function ping(): string { return \"ok\"; }\n");
	const scope = join(directory, "scope.json");
	writeFileSync(
		scope,
		JSON.stringify({
			version: 1,
			name: "cli-run-test",
			authorization: {
				reference: "test",
				expiresAt: "2099-01-01T00:00:00Z",
				allowRemoteModels: true,
			},
			root: ".",
			files: ["a.ts"],
			domains: ["web2"],
			models: {
				recon: { provider: "minimax", id: "MiniMax-M2.7-highspeed" },
				hunter: { provider: "minimax", id: "MiniMax-M3" },
				validator: { provider: "minimax", id: "MiniMax-M2.7" },
			},
			limits: {
				maxCalls,
				maxInputChars: 1500000,
				maxOutputTokens: 32000,
				timeoutMs: 1800000,
				concurrency: 4,
				passes: 2,
				maxFindingsPerTask: 10,
			},
		}),
	);
	return scope;
}

test("CLI plans the operator's scope and evaluates a report the operator supplies", () => {
	const temporary = mkdtempSync(join(realpathSync(tmpdir()), "security-cli-"));
	try {
		const scope = writeAuthorizedScope(temporary);
		const preview = invoke("plan", scope);
		assert.equal(preview.status, 0, preview.stderr);
		assert.equal(JSON.parse(preview.stdout).hunts.length, 20);
		assert.ok(JSON.parse(preview.stdout).tools["vdh.hunt"]);
		assert.ok(JSON.parse(preview.stdout).tools["pashov.fizz"]);
		assert.equal(JSON.parse(preview.stdout).pashov.origin, "https://github.com/pashov/skills");
		assert.equal(JSON.parse(preview.stdout).pashovMapped["solidity-auditor"].length, 12);
		assert.deepEqual(JSON.parse(preview.stdout).vvs, ["vvs.dedup", "vvs.judgment", "vvs.fixing"]);
		assert.doesNotMatch(preview.stdout, /demo|invoice|Vault/i);

		const report: HarnessReport = {
			version: 1,
			name: "cli-evaluate-test",
			identity: "identity",
			snapshot: "snapshot",
			promptVersion: "prompt",
			models: {
				recon: { provider: "test", id: "recon" },
				hunter: { provider: "test", id: "hunter" },
				validator: { provider: "test", id: "validator" },
			},
			status: "complete",
			reservedCalls: 0,
			recordedTokens: { input: 0, output: 0 },
			verifiedFindings: 0,
			files: [],
			recon: null,
			coverage: [],
			funnel: {
				rawCandidates: 1,
				uniqueClusters: 1,
				shallowHunts: 0,
				rejected: 1,
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
				requiredDockerFlags: [
					"--security-opt",
					"seccomp=unconfined",
					"--security-opt",
					"apparmor=unconfined",
				],
				advice: NESTED_RUNTIME_ADVICE,
			},
			stageModels: [],
			candidates: [
				{
					id: "candidate-1",
					clusterId: "cluster-1",
					finding: {
						title: "title",
						severity: "low",
						attacker: "tester",
						intentBroken: "none",
						attackClass: "test",
						preconditions: ["test"],
						trustBoundary: "test",
						rootCause: "test",
						impact: "test",
						reproduction: ["test"],
						remediation: "test",
						evidence: [],
					},
					origins: [],
					validation: null,
					judgment: null,
					verification: null,
					fixProposal: null,
					status: "rejected",
				},
			],
		};
		const reportPath = join(temporary, "report.json");
		writeFileSync(reportPath, JSON.stringify(report));
		const labels = join(temporary, "labels.json");
		writeFileSync(
			labels,
			JSON.stringify({
				reviewer: "cli-test",
				groundTruth: [],
				matches: [],
				classifications: [{ candidateId: "candidate-1", verdict: "unknown", reason: "not reproduced" }],
			}),
		);
		const score = invoke("evaluate", reportPath, labels);
		assert.equal(score.status, 0, score.stderr);
		assert.equal(JSON.parse(score.stdout).unknown, 1);
		writeFileSync(join(temporary, "report.json"), JSON.stringify(report));
		const status = invoke("status", temporary);
		assert.equal(status.status, 0, status.stderr);
		assert.equal(JSON.parse(status.stdout).candidates, 1);
		assert.equal(JSON.parse(status.stdout).verifiedFindings, 0);
	} finally {
		rmSync(temporary, { recursive: true, force: true });
	}
});

test("CLI refuses missing consent and never echoes a malformed config's private payload", () => {
	const temporary = mkdtempSync(join(realpathSync(tmpdir()), "security-cli-"));
	try {
		const sourceDir = join(temporary, "src");
		mkdirSync(sourceDir);
		const scope = writeAuthorizedScope(sourceDir);
		const output = join(temporary, "out");
		assert.equal(invoke("run", scope, output).status, 1);
		const forbidden = invoke("run", scope, output, "--allow-remote-models");
		assert.equal(forbidden.status, 1);
		assert.match(forbidden.stderr, /authorization/);
		const config = join(temporary, "malformed.json");
		writeFileSync(config, '{"private":"must-not-echo-this-secret"');
		const result = invoke("plan", config);
		assert.equal(result.status, 1);
		assert.doesNotMatch(result.stdout + result.stderr, /must-not-echo/);
		assert.match(result.stderr, /scope validation/);
		assert.equal(invoke("demo", join(temporary, "out")).status, 1);
	} finally {
		rmSync(temporary, { recursive: true, force: true });
	}
});

test("CLI surfaces invalid configuration reasons", () => {
	const temporary = mkdtempSync(join(realpathSync(tmpdir()), "security-cli-"));
	try {
		const scope = writeRemoteScope(temporary, 0);
		const result = invoke("plan", scope);
		assert.equal(result.status, 1);
		assert.match(result.stderr, /Reason: Invalid engine configuration: config\.limits\.maxCalls/);
	} finally {
		rmSync(temporary, { recursive: true, force: true });
	}
});

test("CLI surfaces missing model credentials", () => {
	const temporary = mkdtempSync(join(realpathSync(tmpdir()), "security-cli-"));
	const home = mkdtempSync(join(realpathSync(tmpdir()), "security-cli-home-"));
	const output = mkdtempSync(join(realpathSync(tmpdir()), "security-cli-output-"));
	try {
		const scope = writeRemoteScope(temporary);
		const env = { ...process.env };
		delete env.MINIMAX_API_KEY;
		delete env.MINIMAX_CN_API_KEY;
		env.HOME = home;
		const result = invokeWithEnv(
			env,
			"run",
			scope,
			output,
			"--allow-remote-models",
			"--keep-models",
		);
		assert.equal(result.status, 1);
		assert.match(result.stderr, /Reason: No credentials for provider minimax: set MINIMAX_API_KEY/);
	} finally {
		rmSync(temporary, { recursive: true, force: true });
		rmSync(home, { recursive: true, force: true });
		rmSync(output, { recursive: true, force: true });
	}
});

test("CLI surfaces missing scope files", () => {
	const temporary = mkdtempSync(join(realpathSync(tmpdir()), "security-cli-"));
	try {
		const missing = join(temporary, "missing-scope.json");
		const result = invoke("plan", missing);
		assert.equal(result.status, 1);
		assert.match(result.stderr, /Reason: file not found:/);
	} finally {
		rmSync(temporary, { recursive: true, force: true });
	}
});
