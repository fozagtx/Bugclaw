import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { Sandbox } from "../src/sandbox.ts";
import { firstJson, NebiusClient, parseChatResponse } from "../src/nebius.ts";
import { OUTPUT_SCHEMAS, renderPrompt } from "../src/prompts.ts";
import { makeSnapshot } from "../src/snapshot.ts";
import { classify, reproduce, validateFixFiles, validatePoc } from "../src/repro.ts";
import { evidencePath, writeEvidence } from "../src/evidence.ts";
import { Store } from "../src/store.ts";
import { config } from "../src/config.ts";
import { serve } from "../src/server.ts";

async function makeReproFixture() {
	const root = await mkdtemp(join(tmpdir(), "bugclaw-repro-"));
	const dataDir = join(root, "data");
	const scanId = "repro-fixture";
	const candidateId = "candidate-fixture";
	const previousData = process.env.BUGCLAW_DATA;
	const previousKey = process.env.NEBIUS_API_KEY;
	process.env.BUGCLAW_DATA = dataDir;
	process.env.NEBIUS_API_KEY = "unit-test-key";
	let store: Store | undefined;
	try {
		store = new Store(join(dataDir, "bugclaw.sqlite"));
		const scanDir = join(dataDir, "scans", scanId);
		const sourceDir = join(scanDir, "snapshot", "src");
		await mkdir(sourceDir, { recursive: true });
		await writeFile(join(sourceDir, "main.js"), "module.exports = {};\n");
		await writeFile(join(scanDir, "manifest.json"), JSON.stringify([{ path: "src/main.js" }]));
		store.createScan({ id: scanId, source: "fixture", authorization: "unit test" });
		store.setScan(scanId, "done", "fixture-hash", {});
		store.putCandidate(scanId, {
			id: candidateId,
			title: "fixture candidate",
			evidence: [{ path: "src/main.js", startLine: 1, endLine: 1, quote: "module.exports = {};" }],
		});
	} catch (error) {
		store?.close();
		if (previousData === undefined) delete process.env.BUGCLAW_DATA;
		else process.env.BUGCLAW_DATA = previousData;
		if (previousKey === undefined) delete process.env.NEBIUS_API_KEY;
		else process.env.NEBIUS_API_KEY = previousKey;
		await rm(root, { recursive: true, force: true });
		throw error;
	}
	return {
		root, dataDir, scanId, candidateId, store: store!,
		async cleanup() {
			store!.close();
			if (previousData === undefined) delete process.env.BUGCLAW_DATA;
			else process.env.BUGCLAW_DATA = previousData;
			if (previousKey === undefined) delete process.env.NEBIUS_API_KEY;
			else process.env.NEBIUS_API_KEY = previousKey;
			await rm(root, { recursive: true, force: true });
		},
	};
}

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
	assert.throws(
		() => config({ BUGCLAW_RECON_MODEL: "nebius/openai/gpt-oss-120b" }),
		/Bugclaw only runs NVIDIA Nemotron models on Nebius Token Factory: nebius\/openai\/gpt-oss-120b/,
	);
	assert.equal(
		config({ BUGCLAW_RECON_MODEL: "nebius/nvidia/nemotron-3-super-120b-a12b" }).models.recon,
		"nebius/nvidia/nemotron-3-super-120b-a12b",
	);
});

test("MCP bearer authentication and non-loopback binding require the configured token", async () => {
	const root = await mkdtemp(join(tmpdir(), "bugclaw-mcp-"));
	const previousData = process.env.BUGCLAW_DATA;
	const previousToken = process.env.BUGCLAW_MCP_TOKEN;
	let store: Store | undefined;
	let protectedService: Awaited<ReturnType<typeof serve>> | undefined;
	let privateService: Awaited<ReturnType<typeof serve>> | undefined;
	let unprotectedService: Awaited<ReturnType<typeof serve>> | undefined;
	const initializeBody = JSON.stringify({
		jsonrpc: "2.0",
		id: 1,
		method: "initialize",
		params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "Bugclaw test", version: "1.0.0" } },
	});
	try {
		process.env.BUGCLAW_DATA = join(root, "data");
		process.env.BUGCLAW_MCP_TOKEN = "expected-secret";
		store = new Store();
		protectedService = await serve(0, store);
		const protectedAddress = protectedService.server.address();
		assert.ok(protectedAddress && typeof protectedAddress !== "string");
		const postMcp = (port: number, body: string, authorization?: string) => fetch(`http://127.0.0.1:${port}/mcp`, {
			method: "POST",
			headers: {
				accept: "application/json, text/event-stream",
				"content-type": "application/json",
				...(authorization ? { authorization } : {}),
			},
			body,
		});
		const postInitialize = (port: number, authorization?: string) => postMcp(port, initializeBody, authorization);
		const readJsonRpc = async (response: any) => {
			const body = await response.text();
			if (response.headers.get("content-type")?.includes("text/event-stream")) {
				const dataLines = body.split(/\r?\n/).filter((line: string) => line.startsWith("data:"));
				return JSON.parse(dataLines.at(-1)!.slice(5).trim());
			}
			return JSON.parse(body);
		};
		const missing = await postInitialize(protectedAddress.port);
		assert.equal(missing.status, 401);
		assert.equal(missing.headers.get("www-authenticate"), "Bearer");
		assert.deepEqual(await missing.json(), { error: "unauthorized" });
		const wrong = await postInitialize(protectedAddress.port, "Bearer wrong-secret");
		assert.equal(wrong.status, 401);
		assert.equal(wrong.headers.get("www-authenticate"), "Bearer");
		assert.deepEqual(await wrong.json(), { error: "unauthorized" });
		for (let index = 0; index < 2; index++) {
			const initialized = await postInitialize(protectedAddress.port, "Bearer expected-secret");
			assert.equal(initialized.status, 200);
			const response = await readJsonRpc(initialized);
			assert.equal(response.result.serverInfo.name, "bugclaw");
		}
		const listed = await postMcp(
			protectedAddress.port,
			JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
			"Bearer expected-secret",
		);
		assert.equal(listed.status, 200);
		const listedResult = await readJsonRpc(listed);
		const toolNames = listedResult.result.tools.map((tool: { name: string }) => tool.name);
		assert.deepEqual(toolNames, [
			"bugclaw_scan",
			"bugclaw_status",
			"bugclaw_candidates",
			"bugclaw_reproduce",
			"bugclaw_evidence",
		]);
		assert.equal(toolNames.some((name: string) => /signoff/i.test(name)), false);

		privateService = await serve(0, store, { host: "0.0.0.0" });
		const privateAddress = privateService.server.address();
		assert.ok(privateAddress && typeof privateAddress !== "string");
		const privateHealth = await fetch(`http://127.0.0.1:${privateAddress.port}/api/health`);
		assert.equal(privateHealth.status, 404);
		assert.deepEqual(await privateHealth.json(), { error: "not found" });
		const privateSignoff = await fetch(`http://127.0.0.1:${privateAddress.port}/api/candidates/x/signoff`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ decision: "confirmed", note: "test" }),
		});
		assert.equal(privateSignoff.status, 404);
		assert.deepEqual(await privateSignoff.json(), { error: "not found" });
		const privateMcp = await postInitialize(privateAddress.port, "Bearer expected-secret");
		assert.equal(privateMcp.status, 200);
		assert.equal((await readJsonRpc(privateMcp)).result.serverInfo.name, "bugclaw");

		delete process.env.BUGCLAW_MCP_TOKEN;
		await assert.rejects(
			serve(0, store, { host: "0.0.0.0" }),
			/BUGCLAW_MCP_TOKEN is required to bind a non-loopback host/,
		);
		unprotectedService = await serve(0, store);
		const unprotectedAddress = unprotectedService.server.address();
		assert.ok(unprotectedAddress && typeof unprotectedAddress !== "string");
		const unauthenticated = await postInitialize(unprotectedAddress.port);
		assert.equal(unauthenticated.status, 200);
		assert.equal((await readJsonRpc(unauthenticated)).result.serverInfo.name, "bugclaw");
	} finally {
		if (unprotectedService) await unprotectedService.close();
		if (privateService) await privateService.close();
		if (protectedService) await protectedService.close();
		store?.close();
		if (previousData === undefined) delete process.env.BUGCLAW_DATA;
		else process.env.BUGCLAW_DATA = previousData;
		if (previousToken === undefined) delete process.env.BUGCLAW_MCP_TOKEN;
		else process.env.BUGCLAW_MCP_TOKEN = previousToken;
		await rm(root, { recursive: true, force: true });
	}
});

test("HTTPS serving uses the provided certificate and key", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "bugclaw-https-"));
	const previousData = process.env.BUGCLAW_DATA;
	const previousApiKey = process.env.NEBIUS_API_KEY;
	let store: Store | undefined;
	let service: Awaited<ReturnType<typeof serve>> | undefined;
	try {
		try {
			execFileSync("openssl", ["version"], { stdio: "ignore" });
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") {
				t.skip("openssl is unavailable");
				return;
			}
			throw error;
		}
		process.env.BUGCLAW_DATA = join(root, "data");
		delete process.env.NEBIUS_API_KEY;
		const certPath = join(root, "cert.pem");
		const keyPath = join(root, "key.pem");
		execFileSync("openssl", [
			"req", "-x509", "-newkey", "rsa:2048", "-nodes",
			"-keyout", keyPath, "-out", certPath, "-days", "1",
			"-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
		], { stdio: "ignore" });
		store = new Store();
		service = await serve(0, store, { host: "127.0.0.1", tlsCert: certPath, tlsKey: keyPath });
		const address = service.server.address();
		assert.ok(address && typeof address !== "string");
		const response = await new Promise<{ status: number | undefined; body: string }>((resolveResponse, reject) => {
			const request = httpsRequest({
				hostname: "127.0.0.1",
				port: address.port,
				path: "/api/health",
				rejectUnauthorized: false,
			}, (incoming) => {
				let body = "";
				incoming.setEncoding("utf8");
				incoming.on("data", (part: string) => { body += part; });
				incoming.on("end", () => resolveResponse({ status: incoming.statusCode, body }));
			});
			request.on("error", reject);
			request.end();
		});
		assert.equal(response.status, 200);
		assert.ok(response.body.length > 0);
	} finally {
		if (service) await service.close();
		store?.close();
		if (previousData === undefined) delete process.env.BUGCLAW_DATA;
		else process.env.BUGCLAW_DATA = previousData;
		if (previousApiKey === undefined) delete process.env.NEBIUS_API_KEY;
		else process.env.NEBIUS_API_KEY = previousApiKey;
		await rm(root, { recursive: true, force: true });
	}
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
	const schema = OUTPUT_SCHEMAS.POC.schema as any;
	assert.equal(schema.anyOf.length, 2);
	assert.deepEqual(schema.anyOf[1].required, ["cannotReproduce"]);
	assert.equal(schema.anyOf[1].additionalProperties, false);
	assert.deepEqual(OUTPUT_SCHEMAS.POC_RETRY.schema, OUTPUT_SCHEMAS.POC.schema);
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
	assert.doesNotThrow(() => validatePoc({ files: [{ path: ".bugclaw/poc/check.js", content: "require('../../src/config.ts')" }], command: ["node", ".bugclaw/poc/check.js"] }, cited, ["src/config.ts"]));
	assert.throws(() => validatePoc({ files: [{ path: "../check.js", content: "require('src/config.ts')" }], command: ["node"] }, cited, ["src/config.ts"]), /under .bugclaw\/poc/);
	assert.throws(() => validatePoc({ files: [{ path: "/tmp/check.js", content: "require('src/config.ts')" }], command: ["node"] }, cited, ["src/config.ts"]), /under .bugclaw\/poc/);
	assert.throws(() => validatePoc({ files: [{ path: ".bugclaw/poc/check.js", content: "console.log('safe')" }], command: ["node"] }, cited, ["src/config.ts"]), /does not exercise cited code/);
});

test("POC command requires a bare supported interpreter", () => {
	const validate = (command: string[]) => validatePoc({
		files: [{ path: ".bugclaw/poc/test.js", content: "require('../../src/config.ts')" }],
		command,
	}, ["src/config.ts"], ["src/config.ts"]);
	assert.throws(() => validate([".bugclaw/poc/test.js"]), /invalid PoC command/);
	assert.throws(() => validate(["./node_modules/.bin/node", ".bugclaw/poc/test.js"]), /invalid PoC command/);
	assert.doesNotThrow(() => validate(["node", ".bugclaw/poc/test.js"]));
	assert.throws(() => validate(["node", "./node_modules/.bin/node"]), /invalid PoC command/);
});

test("POC relative imports must resolve to a PoC or snapshot file", () => {
	const command = ["node", ".bugclaw/poc/test.js"];
	const invalid = {
		files: [{ path: ".bugclaw/poc/test.js", content: "require('../index.js')" }],
		command,
	};
	assert.throws(() => validatePoc(invalid, ["index.js"], ["index.js"]), /resolve\(process\.cwd\(\), "index\.js"\)/);

	const validSnapshotImport = {
		files: [{ path: ".bugclaw/poc/test.js", content: "require('../../index.js')" }],
		command,
	};
	assert.doesNotThrow(() => validatePoc(validSnapshotImport, ["index.js"], ["index.js"]));

	const validPocImport = {
		files: [
			{ path: ".bugclaw/poc/test.js", content: "require('./helper')" },
			{ path: ".bugclaw/poc/helper.js", content: "module.exports = 1" },
		],
		command,
	};
	assert.doesNotThrow(() => validatePoc(validPocImport, ["helper.js"], ["helper.js"]));

	const absoluteImport = {
		files: [{ path: ".bugclaw/poc/test.js", content: 'require(require("path").resolve(process.cwd(), "index.js"))' }],
		command,
	};
	assert.doesNotThrow(() => validatePoc(absoluteImport, ["index.js"], ["index.js"]));
});

test("POC_RETRY renders the previous contract error", () => {
	const prompt = renderPrompt("POC_RETRY", { CONTRACT_ERROR: "missing import", SANDBOX_RESULT: { notRun: true } }).prompt;
	assert.ok(prompt.includes('SANDBOX_RESULT={"notRun":true}\nCONTRACT_ERROR="missing import"'));
	assert.match(renderPrompt("POC", {}).prompt, /Never substitute a stub, mock, fake or hand-written replacement/);
	assert.match(renderPrompt("POC", {}).prompt, /Return \{"cannotReproduce":/);
});

test("POC validation repairs escaped file text once and preserves files with real newlines", () => {
	const escaped = {
		files: [{ path: ".bugclaw/poc/check.js", content: "require('../../src/config.ts');\\nconsole.log(\\\"ok\\\");\\nconst tab = 'a\\tb';\\nconst slash = 'c\\\\d';" }],
		command: ["node", ".bugclaw/poc/check.js"],
	};
	assert.equal(validatePoc(escaped, ["src/config.ts"], ["src/config.ts"]), "unescaped-newlines");
	assert.equal(escaped.files[0].content, "require('../../src/config.ts');\nconsole.log(\"ok\");\nconst tab = 'a\tb';\nconst slash = 'c\\d';");

	const realNewlines = {
		files: [{ path: ".bugclaw/poc/check.js", content: "require('../../src/config.ts');\n// literal \\n stays" }],
		command: ["node", ".bugclaw/poc/check.js"],
	};
	const original = realNewlines.files[0].content;
	assert.equal(validatePoc(realNewlines, ["src/config.ts"], ["src/config.ts"]), undefined);
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

test("HTTP dashboard and detail APIs use temporary data and serve SPA routes safely", async () => {
	const root = await mkdtemp(join(tmpdir(), "bugclaw-server-"));
	const previousCwd = process.cwd();
	const previousData = process.env.BUGCLAW_DATA;
	let store: Store | undefined;
	let service: Awaited<ReturnType<typeof serve>> | undefined;
	try {
		const web = join(root, "web");
		await mkdir(web, { recursive: true });
		await writeFile(join(web, "index.html"), "<!doctype html><title>Dashboard fixture</title>");
		await writeFile(join(web, "asset.json"), "{\"ready\":true}");
		await writeFile(join(web, "font.woff2"), Buffer.from([0, 1, 2]));
		process.chdir(root);
		process.env.BUGCLAW_DATA = join(root, "data");
		store = new Store();
		store.createScan({ id: "scan", source: "local", authorization: "local self-test" });
		store.setScan("scan", "done", "snapshot-hash", { summary: "complete" });
		store.createScan({ id: "empty", source: "local", authorization: "local self-test" });
		store.putCandidate("scan", { id: "candidate", title: "source candidate", status: "unvalidated", evidence: [] });
		store.attempt("candidate", "poc", { status: "not-reproduced" });
		store.attempt("candidate", "unparseable", { status: "temporary" });
		store.db.prepare("UPDATE attempts SET result=? WHERE step=?").run("not-json", "unparseable");
		const scanDir = join(process.env.BUGCLAW_DATA!, "scans", "scan");
		const engineOutput = join(scanDir, "engine-output");
		await mkdir(engineOutput, { recursive: true });
		await writeFile(join(scanDir, "manifest.json"), JSON.stringify([
			{ path: "src/app.js", sha256: "abc123" },
			{ path: "src/lib.js", sha256: "def456" },
		]));
		const engineDb = new DatabaseSync(join(engineOutput, "state.sqlite"));
		engineDb.exec("CREATE TABLE tasks (id TEXT, stage TEXT, attempts INTEGER, status TEXT, result TEXT, error TEXT)");
		const insertTask = engineDb.prepare("INSERT INTO tasks (id, stage, attempts, status, result, error) VALUES (?, ?, ?, ?, ?, ?)");
		insertTask.run("recon-1", "recon:architecture", 1, "done", JSON.stringify({ value: { summary: "r".repeat(650) }, tools: [], inputTokens: 11, outputTokens: 12 }), null);
		insertTask.run("hunt-1", "hunt:web2:identity:0", 2, "done", JSON.stringify({ value: { coverage: "identity and access checks", findings: [{}] }, tools: [], inputTokens: 21, outputTokens: 22 }), null);
		insertTask.run("validate-1", "validate:candidate-1", 1, "done", JSON.stringify({ value: { verdict: "genuine", reason: "The candidate is supported." }, tools: [], inputTokens: 31, outputTokens: 32 }), null);
		insertTask.run("failed-1", "hunt:web2:failed:0", 1, "failed", null, "model output failed");
		engineDb.close();

		service = await serve(0, store);
		const address = service.server.address();
		assert.ok(address && typeof address !== "string");
		const base = `http://127.0.0.1:${address.port}`;

		const spa = await fetch(`${base}/scans/abc`);
		assert.equal(spa.status, 200);
		assert.match(await spa.text(), /Dashboard fixture/);

		const asset = await fetch(`${base}/asset.json`);
		assert.equal(asset.headers.get("content-type"), "application/json");
		assert.deepEqual(await asset.json(), { ready: true });
		const font = await fetch(`${base}/font.woff2`);
		assert.equal(font.headers.get("content-type"), "font/woff2");

		const traversal = await new Promise<{ status: number | undefined; body: string }>((resolveResponse, reject) => {
			const request = httpRequest({ hostname: "127.0.0.1", port: address.port, path: "/web/../package.json", method: "GET" }, (response) => {
				let body = "";
				response.setEncoding("utf8");
				response.on("data", (part: string) => { body += part; });
				response.on("end", () => resolveResponse({ status: response.statusCode, body }));
			});
			request.on("error", reject);
			request.end();
		});
		assert.equal(traversal.status, 404);

		const signoff = await fetch(`${base}/api/candidates/candidate/signoff`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ decision: "confirmed", note: "Reviewed" }),
		});
		assert.equal(signoff.status, 201);

		const detailResponse = await fetch(`${base}/api/candidates/candidate`);
		assert.equal(detailResponse.status, 200);
		const detail = await detailResponse.json() as any;
		assert.deepEqual(detail.data, { id: "candidate", title: "source candidate", status: "unvalidated", evidence: [] });
		assert.deepEqual(detail.attempts.find((attempt: any) => attempt.step === "poc").result, { status: "not-reproduced" });
		assert.equal(detail.attempts.find((attempt: any) => attempt.step === "unparseable").result, "not-json");
		assert.equal(detail.signoffs.length, 1);
		assert.equal(detail.signoffs[0].decision, "confirmed");

		const scansResponse = await fetch(`${base}/api/scans`);
		const scans = await scansResponse.json() as any[];
		assert.equal(scans.find((scan) => scan.id === "scan").candidateCount, 1);
		assert.equal(scans.find((scan) => scan.id === "empty").candidateCount, 0);

		const scanResponse = await fetch(`${base}/api/scans/scan`);
		const scan = await scanResponse.json() as any;
		assert.deepEqual(scan.report, { summary: "complete" });
		assert.deepEqual(scan.candidates[0].data, { id: "candidate", title: "source candidate", status: "unvalidated", evidence: [] });

		const activityResponse = await fetch(`${base}/api/scans/scan/activity`);
		assert.equal(activityResponse.status, 200);
		const activity = await activityResponse.json() as any;
		assert.deepEqual(activity.files, [
			{ path: "src/app.js", sha256: "abc123" },
			{ path: "src/lib.js", sha256: "def456" },
		]);
		assert.deepEqual(activity.tasks.map((task: any) => task.id), ["recon-1", "hunt-1", "validate-1", "failed-1"]);
		assert.deepEqual(activity.tasks[0], {
			id: "recon-1", stage: "recon:architecture", status: "done", attempts: 1, error: null,
			summary: "r".repeat(600), findings: null, verdict: null, inputTokens: 11, outputTokens: 12,
		});
		assert.deepEqual(activity.tasks[1], {
			id: "hunt-1", stage: "hunt:web2:identity:0", status: "done", attempts: 2, error: null,
			summary: "identity and access checks", findings: 1, verdict: null, inputTokens: 21, outputTokens: 22,
		});
		assert.deepEqual(activity.tasks[2], {
			id: "validate-1", stage: "validate:candidate-1", status: "done", attempts: 1, error: null,
			summary: "The candidate is supported.", findings: null, verdict: "genuine", inputTokens: 31, outputTokens: 32,
		});
		assert.deepEqual(activity.tasks[3], {
			id: "failed-1", stage: "hunt:web2:failed:0", status: "failed", attempts: 1, error: "model output failed",
			summary: null, findings: null, verdict: null, inputTokens: null, outputTokens: null,
		});

		const unknownScan = await fetch(`${base}/api/scans/missing`);
		assert.equal(unknownScan.status, 404);
		assert.deepEqual(await unknownScan.json(), { error: "scan not found" });
		const unknownActivity = await fetch(`${base}/api/scans/missing/activity`);
		assert.equal(unknownActivity.status, 404);
		assert.deepEqual(await unknownActivity.json(), { error: "scan not found" });
	} finally {
		if (service) await service.close();
		store?.close();
		process.chdir(previousCwd);
		if (previousData === undefined) delete process.env.BUGCLAW_DATA;
		else process.env.BUGCLAW_DATA = previousData;
		await rm(root, { recursive: true, force: true });
	}
});

test("cannotReproduce ends without running a sandbox or writing evidence", async () => {
	const fixture = await makeReproFixture();
	const reason = "The snapshot does not include the mysql package.";
	let modelCalls = 0;
	let sandboxRuns = 0;
	const model = {
		async complete() {
			modelCalls++;
			return { value: { cannotReproduce: reason }, inputTokens: 5, outputTokens: 7 };
		},
	};
	const sandbox = {
		async run() {
			sandboxRuns++;
			return { exitCode: 0, stdout: "BUGCLAW_SAFE", stderr: "", timedOut: false };
		},
	};
	try {
		const output = await reproduce(fixture.scanId, fixture.candidateId, { store: fixture.store, model, sandbox } as any);
		assert.equal(output[0].status, "not-reproducible");
		assert.equal(output[0].reason, reason);
		assert.equal(modelCalls, 1);
		assert.equal(sandboxRuns, 0);
		const candidate = fixture.store.candidate(fixture.candidateId);
		assert.equal(candidate.status, "not-reproducible");
		assert.equal(JSON.parse(candidate.data).reproReason, reason);
		const attempts = fixture.store.attempts(fixture.candidateId) as any[];
		assert.equal(attempts.length, 1);
		assert.equal(attempts[0].step, "poc");
		assert.deepEqual(JSON.parse(attempts[0].result), { status: "not-reproducible", reason });
		await assert.rejects(access(join(fixture.dataDir, "scans", fixture.scanId, "evidence", fixture.candidateId)), { code: "ENOENT" });
	} finally { await fixture.cleanup(); }
});

test("model errors retry the same PoC attempt and terminate as model-error", async () => {
	const fixture = await makeReproFixture();
	const reason = "Nebius returned an incomplete or tool-bearing response";
	let modelCalls = 0;
	let sandboxRuns = 0;
	const model = {
		async complete() {
			modelCalls++;
			throw new Error(reason);
		},
	};
	const sandbox = {
		async run() {
			sandboxRuns++;
			return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
		},
	};
	try {
		const output = await reproduce(fixture.scanId, fixture.candidateId, { store: fixture.store, model, sandbox } as any);
		assert.equal(modelCalls, 3);
		assert.equal(sandboxRuns, 0);
		assert.equal(output[0].status, "model-error");
		assert.equal(output[0].reason, reason);
		const candidate = fixture.store.candidate(fixture.candidateId);
		assert.equal(candidate.status, "model-error");
		assert.equal(JSON.parse(candidate.data).reproReason, reason);
		const attempts = fixture.store.attempts(fixture.candidateId) as any[];
		assert.equal(attempts.length, 1);
		assert.deepEqual(JSON.parse(attempts[0].result), { status: "model-error", reason });
	} finally { await fixture.cleanup(); }
});

test("a final PoC validation failure terminates as invalid-poc with its contract error", async () => {
	const fixture = await makeReproFixture();
	let modelCalls = 0;
	let sandboxRuns = 0;
	const model = {
		async complete() {
			modelCalls++;
			return {
				value: {
					files: [{ path: ".bugclaw/poc/test.js", content: "require(require('path').resolve(process.cwd(), 'src/main.js'))" }],
					command: [".bugclaw/poc/test.js"],
					rationale: "exercise src/main.js",
				},
				inputTokens: 5,
				outputTokens: 7,
			};
		},
	};
	const sandbox = {
		async run() {
			sandboxRuns++;
			return { exitCode: 0, stdout: "BUGCLAW_SAFE", stderr: "", timedOut: false };
		},
	};
	try {
		const output = await reproduce(fixture.scanId, fixture.candidateId, { store: fixture.store, model, sandbox } as any);
		assert.equal(modelCalls, 3);
		assert.equal(sandboxRuns, 0);
		assert.equal(output[0].status, "invalid-poc");
		assert.equal(output[0].reason, "invalid PoC command");
		const candidate = fixture.store.candidate(fixture.candidateId);
		assert.equal(candidate.status, "invalid-poc");
		assert.equal(JSON.parse(candidate.data).reproReason, "invalid PoC command");
		const attempts = fixture.store.attempts(fixture.candidateId) as any[];
		assert.equal(attempts.length, 3);
		assert.deepEqual(JSON.parse(attempts.at(-1).result), { status: "invalid", reason: "invalid PoC command" });
	} finally { await fixture.cleanup(); }
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
