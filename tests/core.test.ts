import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { Sandbox } from "../src/sandbox.ts";
import { firstJson, NebiusClient, parseChatResponse } from "../src/nebius.ts";
import { OUTPUT_SCHEMAS } from "../src/prompts.ts";
import { makeSnapshot } from "../src/snapshot.ts";
import { classify, validateFixFiles, validatePoc } from "../src/repro.ts";
import { evidencePath, writeEvidence } from "../src/evidence.ts";
import { Store } from "../src/store.ts";
import { config } from "../src/config.ts";

test("Bugclaw defaults to public Nebius Token Factory models and supports overrides", () => {
	const defaults = config({});
	assert.equal(defaults.baseUrl, "https://api.tokenfactory.nebius.com/v1");
	assert.equal(defaults.models.recon, "nebius/nvidia/nemotron-3-super-120b-a12b");
	assert.equal(defaults.models.hunter, "nebius/nvidia/nemotron-3-super-120b-a12b");
	assert.equal(defaults.models.validator, "nebius/nvidia/Nemotron-3-Ultra-550b-a55b");
	assert.equal(defaults.models.repro, defaults.models.recon);
	assert.equal(defaults.models.judge, defaults.models.validator);
	assert.equal(defaults.models.fix, defaults.models.validator);
	assert.equal(config({ NEBIUS_BASE_URL: "https://example.invalid/v1/" }).baseUrl, "https://example.invalid/v1");
});

test("Nebius JSON parsing accepts leading newlines and null tool_calls", () => {
	const result = parseChatResponse({
		choices: [{ finish_reason: "stop", message: { content: "\n{\"ok\":true}", tool_calls: null, reasoning_content: "ignored" } }],
		usage: { prompt_tokens: 12, completion_tokens: 8 },
	});
	assert.deepEqual(result, { value: { ok: true }, inputTokens: 12, outputTokens: 8 });
	assert.deepEqual(firstJson("\n prose {\"first\":1} trailing {\"second\":2}"), { first: 1 });
});

test("Nebius rejects non-empty tool calls and truncated responses", () => {
	assert.throws(() => parseChatResponse({ choices: [{ finish_reason: "stop", message: { content: "{\"ok\":true}", tool_calls: [{ id: "call" }] } }] }), /tool-bearing/);
	assert.throws(() => parseChatResponse({ choices: [{ finish_reason: "length", message: { content: null, reasoning_content: "ignored" } }] }), /incomplete/);
});

test("Nebius PoC requests use strict JSON Schema response formatting", async () => {
	let requestBody: any;
	const client = new NebiusClient(
		{ NEBIUS_API_KEY: "unit-test-key", NEBIUS_BASE_URL: "https://example.invalid/v1" },
		async (_url, init) => {
			requestBody = JSON.parse(String(init?.body));
			return new Response(JSON.stringify({
				choices: [{ finish_reason: "stop", message: { content: JSON.stringify({ files: [{ path: ".bugclaw/poc/test.js", content: "console.log('ok')" }], command: ["node", ".bugclaw/poc/test.js"], rationale: "exercise cited code" }), tool_calls: null } }],
			}), { status: 200 });
		},
	);
	await client.complete("nebius/nvidia/nemotron-3-super-120b-a12b", "system", "prompt", OUTPUT_SCHEMAS.POC);
	assert.deepEqual(requestBody.response_format, {
		type: "json_schema",
		json_schema: { name: OUTPUT_SCHEMAS.POC.name, strict: true, schema: OUTPUT_SCHEMAS.POC.schema },
	});
});

test("POC classification requires both the marker and its specified exit code", () => {
	for (const [result, expected] of [
		[{ exitCode: 1, timedOut: false, stdout: "BUGCLAW_VULNERABLE" }, "vulnerable"],
		[{ exitCode: 0, timedOut: false, stdout: "BUGCLAW_SAFE" }, "safe"],
		[{ exitCode: 0, timedOut: false, stdout: "BUGCLAW_VULNERABLE" }, "inconclusive"],
		[{ exitCode: 1, timedOut: false, stdout: "BUGCLAW_SAFE" }, "inconclusive"],
		[{ exitCode: 1, timedOut: true, stdout: "BUGCLAW_VULNERABLE" }, "inconclusive"],
	] as const) assert.equal(classify(result), expected);
});

test("POC files stay under the reserved directory and cite source", () => {
	const cited = ["src/config.ts"];
	assert.doesNotThrow(() => validatePoc({ files: [{ path: ".bugclaw/poc/check.js", content: "require('../../src/config.ts')" }], command: ["node", ".bugclaw/poc/check.js"] }, cited));
	assert.throws(() => validatePoc({ files: [{ path: "../check.js", content: "require('src/config.ts')" }], command: ["node"] }, cited), /under .bugclaw\/poc/);
	assert.throws(() => validatePoc({ files: [{ path: "/tmp/check.js", content: "require('src/config.ts')" }], command: ["node"] }, cited), /under .bugclaw\/poc/);
	assert.throws(() => validatePoc({ files: [{ path: ".bugclaw/poc/check.js", content: "console.log('safe')" }], command: ["node"] }, cited), /does not exercise cited code/);
});

test("POC command requires a bare supported interpreter", () => {
	const validate = (command: string[]) => validatePoc({
		files: [{ path: ".bugclaw/poc/test.js", content: "require('../../src/config.ts')" }],
		command,
	}, ["src/config.ts"]);
	assert.throws(() => validate([".bugclaw/poc/test.js"]), /invalid PoC command/);
	assert.throws(() => validate(["./node_modules/.bin/node", ".bugclaw/poc/test.js"]), /invalid PoC command/);
	assert.doesNotThrow(() => validate(["node", ".bugclaw/poc/test.js"]));
	assert.throws(() => validate(["node", "./node_modules/.bin/node"]), /invalid PoC command/);
});

test("POC validation repairs escaped file text once and preserves files with real newlines", () => {
	const escaped = {
		files: [{ path: ".bugclaw/poc/check.js", content: "require('../../src/config.ts');\\nconsole.log(\\\"ok\\\");\\nconst tab = 'a\\tb';\\nconst slash = 'c\\\\d';" }],
		command: ["node", ".bugclaw/poc/check.js"],
	};
	assert.equal(validatePoc(escaped, ["src/config.ts"]), "unescaped-newlines");
	assert.equal(escaped.files[0].content, "require('../../src/config.ts');\nconsole.log(\"ok\");\nconst tab = 'a\tb';\nconst slash = 'c\\d';");

	const realNewlines = {
		files: [{ path: ".bugclaw/poc/check.js", content: "require('../../src/config.ts');\n// literal \\n stays" }],
		command: ["node", ".bugclaw/poc/check.js"],
	};
	const original = realNewlines.files[0].content;
	assert.equal(validatePoc(realNewlines, ["src/config.ts"]), undefined);
	assert.equal(realNewlines.files[0].content, original);
});

test("fix proposals are restricted to cited source files", () => {
	assert.deepEqual(validateFixFiles([{ path: "src/config.ts", content: "export {};" }], ["src/config.ts"]).files, [{ path: "src/config.ts", content: "export {};" }]);
	assert.throws(() => validateFixFiles([{ path: "src/other.ts", content: "export {};" }], ["src/config.ts"]), /outside cited source/);
});

test("fix validation repairs literal escaped newlines", () => {
	const result = validateFixFiles([{ path: "src/config.ts", content: "const value = 1;\\nexport { value };" }], ["src/config.ts"]);
	assert.equal(result.repaired, "unescaped-newlines");
	assert.deepEqual(result.files, [{ path: "src/config.ts", content: "const value = 1;\nexport { value };" }]);
});

test("evidence paths cannot escape the scans directory", () => {
	assert.throws(() => evidencePath("/private/data", "../../outside.txt"), /outside data\/scans/);
	assert.ok(evidencePath("/private/data", "scan/evidence/candidate/poc-1/stdout.txt").startsWith("/private/data/scans/"));
});

test("evidence for repeated runs of one candidate uses distinct paths", async () => {
	const root = await mkdtemp(join(tmpdir(), "bugclaw-evidence-"));
	const input = {
		dataDir: root, scanId: "scan", candidateId: "candidate", runId: "20260601T120000000Z-first",
		step: "poc", number: 1, files: [], argv: ["node"], run: { stdout: "", stderr: "", exitCode: 0, timedOut: false }, meta: {},
	};
	try {
		const first = await writeEvidence(input);
		const second = await writeEvidence({ ...input, runId: "20260601T120100000Z-second" });
		assert.notEqual(first, second);
		assert.match(first, /candidate\/20260601T120000000Z-first\/poc-1$/);
		assert.match(second, /candidate\/20260601T120100000Z-second\/poc-1$/);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

test("source snapshot manifests and hashes are deterministic", async () => {
	const root = await mkdtemp(join(tmpdir(), "bugclaw-snapshot-"));
	try {
		const source = resolve("src");
		const first = await makeSnapshot(source, join(root, "first"), ["config.ts"]);
		const second = await makeSnapshot(source, join(root, "second"), ["config.ts"]);
		assert.deepEqual(first.manifest, second.manifest);
		assert.equal(first.snapshotHash, second.snapshotHash);
	} finally { await rm(root, { recursive: true, force: true }); }
});

test("SQLite stores candidates, attempts, and human signoffs", async () => {
	const root = await mkdtemp(join(tmpdir(), "bugclaw-store-"));
	const store = new Store(join(root, "bugclaw.sqlite"));
	try {
		store.createScan({ id: "scan", source: "local", authorization: "local self-test" });
		store.putCandidate("scan", { id: "candidate", title: "source candidate", evidence: [] });
		store.attempt("candidate", "poc", { status: "inconclusive" });
		store.signoff("candidate", "rejected", "Human reviewed the evidence");
		assert.equal(store.attempts("candidate").length, 1);
		assert.equal(store.db.prepare("SELECT decision FROM signoffs").get()?.decision, "rejected");
	} finally { store.close(); await rm(root, { recursive: true, force: true }); }
});

test("OpenShell uploads snapshot and PoC at the work root and denies network access", { timeout: 900_000 }, async (t) => {
	let status: string;
	try {
		status = execFileSync("openshell", ["status"], { encoding: "utf8" });
	} catch (error) {
		t.skip(`OpenShell gateway is unavailable: ${error instanceof Error ? error.message : String(error)}`);
		return;
	}
	if (!status.includes("Connected")) {
		t.skip(`OpenShell gateway is unavailable: ${status.trim() || "status not connected"}`);
		return;
	}
	const root = await mkdtemp(join(tmpdir(), "bugclaw-sandbox-"));
	try {
		const sandbox = new Sandbox();
		const data = join(root, "data");
		const snapshot = join(data, "scans", "integration", "snapshot");
		await mkdir(snapshot, { recursive: true });
		await writeFile(join(snapshot, "lib.js"), "module.exports = () => 42;\n");
		const poc = {
			path: ".bugclaw/poc/t.js",
			content: "const value = require('../../lib.js')();\nif (value === 42) console.log('BUGCLAW_SAFE');\nelse process.exit(1);\n",
		};
		const argv = ["node", poc.path];
		const safe = await sandbox.run(snapshot, [poc], argv, 30);
		assert.equal(safe.exitCode, 0, safe.stderr);
		assert.match(safe.stdout, /BUGCLAW_SAFE/);
		const evidence = await writeEvidence({
			dataDir: data, scanId: "integration", candidateId: "layout", runId: "integration-run",
			step: "poc", number: 1, files: [poc], argv, run: safe,
			meta: { ...safe, classification: "safe" },
		});
		execFileSync("sh", [join(evidence, "replay.sh")], { encoding: "utf8", timeout: 120_000 });
		assert.match(await readFile(join(evidence, "replay.stdout.txt"), "utf8"), /BUGCLAW_SAFE/);
		const blocked = await sandbox.run(snapshot, [], ["node", "-e", "const c=new AbortController();setTimeout(()=>c.abort(),5000);fetch('https://example.com',{signal:c.signal}).then(()=>{console.error('EGRESS_ALLOWED');process.exitCode=1}).catch(()=>console.log('EGRESS_BLOCKED'))"], 15);
		assert.equal(blocked.exitCode, 0, blocked.stderr);
		assert.match(blocked.stdout, /EGRESS_BLOCKED/);
		assert.doesNotMatch(blocked.stderr, /EGRESS_ALLOWED/);
	} finally { await rm(root, { recursive: true, force: true }); }
});
