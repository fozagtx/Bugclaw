import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { Sandbox } from "../src/sandbox.ts";
import { firstJson, parseChatResponse } from "../src/nebius.ts";
import { makeSnapshot } from "../src/snapshot.ts";
import { classify, validateFixFiles, validatePoc } from "../src/repro.ts";
import { evidencePath } from "../src/evidence.ts";
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

test("fix proposals are restricted to cited source files", () => {
	assert.deepEqual(validateFixFiles([{ path: "src/config.ts", content: "export {};" }], ["src/config.ts"]), [{ path: "src/config.ts", content: "export {};" }]);
	assert.throws(() => validateFixFiles([{ path: "src/other.ts", content: "export {};" }], ["src/config.ts"]), /outside cited source/);
});

test("evidence paths cannot escape the scans directory", () => {
	assert.throws(() => evidencePath("/private/data", "../../outside.txt"), /outside data\/scans/);
	assert.ok(evidencePath("/private/data", "scan/evidence/candidate/poc-1/stdout.txt").startsWith("/private/data/scans/"));
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

test("OpenShell runs a safe command and denies network access", { timeout: 900_000 }, async (t) => {
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
		const safe = await sandbox.run(root, [], ["node", "-e", "console.log('BUGCLAW_SAFE')"], 30);
		assert.equal(safe.exitCode, 0, safe.stderr);
		assert.match(safe.stdout, /BUGCLAW_SAFE/);
		const blocked = await sandbox.run(root, [], ["node", "-e", "const c=new AbortController();setTimeout(()=>c.abort(),5000);fetch('https://example.com',{signal:c.signal}).then(()=>{console.error('EGRESS_ALLOWED');process.exitCode=1}).catch(()=>console.log('EGRESS_BLOCKED'))"], 15);
		assert.equal(blocked.exitCode, 0, blocked.stderr);
		assert.match(blocked.stdout, /EGRESS_BLOCKED/);
		assert.doesNotMatch(blocked.stderr, /EGRESS_ALLOWED/);
	} finally { await rm(root, { recursive: true, force: true }); }
});
