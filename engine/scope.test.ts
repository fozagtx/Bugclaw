import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { type HarnessConfig, loadSnapshot, parseConfig } from "./scope.ts";

const execFileAsync = promisify(execFile);

const standardLimits = {
	maxCalls: 10,
	maxInputChars: 1_000,
	maxOutputTokens: 100,
	timeoutMs: 1_000,
	concurrency: 1,
	passes: 1,
	maxFindingsPerTask: 10,
};

function config(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		version: 1,
		name: "authorized audit",
		authorization: { reference: "ticket-42", expiresAt: "2099-01-01T00:00:00Z", allowRemoteModels: false },
		root: ".",
		files: ["src/app.ts"],
		domains: ["web2", "web3"],
		models: {
			recon: { provider: "local", id: "recon" },
			hunter: { provider: "local", id: "hunter" },
			validator: { provider: "local", id: "validator" },
		},
		limits: standardLimits,
		...overrides,
	};
}

function configWithLimit(limit: keyof HarnessConfig["limits"], value: number): Record<string, unknown> {
	return config({ limits: { ...standardLimits, [limit]: value } });
}

async function fixture(): Promise<string> {
	const directory = await mkdtemp(path.join(await realpath(os.tmpdir()), "bugclaw-"));
	await mkdir(path.join(directory, "src"));
	await writeFile(path.join(directory, "src", "app.ts"), "export const answer = 42;\n");
	return directory;
}

function cleanupFixture(t: test.TestContext, directory: string): void {
	t.after(() => rm(directory, { recursive: true, force: true }));
}

test("parses only complete, explicit configuration", () => {
	assert.equal(parseConfig(config()).name, "authorized audit");
	const metadata = parseConfig(config({
		source: "https://github.com/owner/repo#2.0.0",
		ref: "2.0.0",
		commit: "0123456789abcdef",
	}));
	assert.deepEqual({ source: metadata.source, ref: metadata.ref, commit: metadata.commit }, {
		source: "https://github.com/owner/repo#2.0.0", ref: "2.0.0", commit: "0123456789abcdef",
	});
	for (const invalid of [
		config({ extra: true }),
		config({
			authorization: { reference: "x", expiresAt: "2099-01-01T00:00:00Z", allowRemoteModels: false, extra: true },
		}),
		config({ files: ["src/../secret.ts"] }),
		config({ files: ["src\\app.ts"] }),
		config({ files: ["src/*.ts"] }),
		config({ files: ["src/\u0000app.ts"] }),
		config({ files: ["src/app.ts", "src/app.ts"] }),
		config({ files: Array.from({ length: 501 }, (_, index) => `src/${index}.ts`) }),
		config({ domains: ["web2", "web2"] }),
		config({
			models: {
				recon: { provider: "x", id: "a" },
				hunter: { provider: "x", id: "same" },
				validator: { provider: "x", id: "same" },
			},
		}),
		configWithLimit("maxCalls", 0),
		configWithLimit("maxCalls", 1_001),
		configWithLimit("concurrency", 9),
		configWithLimit("passes", 4),
		configWithLimit("maxFindingsPerTask", 21),
		config({ name: " \t" }),
		config({ authorization: { reference: "\n", expiresAt: "2099-01-01T00:00:00Z", allowRemoteModels: false } }),
		config({ authorization: { reference: "x", expiresAt: "2025-02-30T00:00:00Z", allowRemoteModels: false } }),
	]) {
		assert.throws(() => parseConfig(invalid));
	}
});

test("accepts ai and reports the expanded domain validation message", () => {
	assert.deepEqual(parseConfig(config({ domains: ["ai"] })).domains, ["ai"]);
	assert.throws(
		() => parseConfig(config({ domains: ["foo"] })),
		/config\.domains must be a non-empty array of web2, web3, or ai/,
	);
});

test("loads a deterministic UTF-8 source snapshot", async (t) => {
	const directory = await fixture();
	cleanupFixture(t, directory);
	const snapshot = await loadSnapshot(parseConfig(config()), directory);
	assert.equal(snapshot.root, await realpath(directory));
	assert.deepEqual(snapshot.files[0], {
		path: "src/app.ts",
		content: "export const answer = 42;\n",
		sha256: "a2098bd92b10bf8b816d24b7556b1ce8c49a879d130489065ef1051c17e042f6",
		lines: 2,
	});
	assert.match(snapshot.digest, /^[a-f0-9]{64}$/);
	assert.deepEqual(snapshot, await loadSnapshot(parseConfig(config()), directory));
	await writeFile(path.join(directory, "src", "page.tsx"), "export const Page = () => <main />;\n");
	assert.equal((await loadSnapshot(parseConfig(config({ files: ["src/page.tsx"] })), directory)).files.length, 1);
	await writeFile(path.join(directory, "src", "bom.ts"), Buffer.from([0xef, 0xbb, 0xbf, 0x78]));
	const bom = await loadSnapshot(parseConfig(config({ files: ["src/bom.ts"] })), directory);
	await writeFile(path.join(directory, "src", "bom.ts"), "x");
	const plain = await loadSnapshot(parseConfig(config({ files: ["src/bom.ts"] })), directory);
	assert.equal(bom.files[0].content, plain.files[0].content);
	assert.notEqual(bom.digest, plain.digest);
});

test("fails closed for expiration, unsafe paths, secrets, links, oversized and invalid source", async (t) => {
	const directory = await fixture();
	cleanupFixture(t, directory);
	assert.throws(() =>
		parseConfig(
			config({ authorization: { reference: "x", expiresAt: "2000-01-01T00:00:00Z", allowRemoteModels: false } }),
		),
	);
	const expired = parseConfig(config());
	expired.authorization.expiresAt = "2000-01-01T00:00:00Z";
	await assert.rejects(loadSnapshot(expired, directory));
	await writeFile(path.join(directory, ".env"), "TOKEN=secret\n");
	await assert.rejects(loadSnapshot(parseConfig(config({ files: [".env"] })), directory));
	await mkdir(path.join(directory, ".git"));
	await writeFile(path.join(directory, ".git", "config.json"), "{}");
	await assert.rejects(loadSnapshot(parseConfig(config({ files: [".git/config.json"] })), directory));
	await mkdir(path.join(directory, "private-keys"));
	await writeFile(path.join(directory, "private-keys", "audit.json"), "{}");
	await assert.rejects(loadSnapshot(parseConfig(config({ files: ["private-keys/audit.json"] })), directory));
	await writeFile(path.join(directory, "service-account-prod.json"), "{}");
	await assert.rejects(loadSnapshot(parseConfig(config({ files: ["service-account-prod.json"] })), directory));
	await writeFile(path.join(directory, "src", "bad.ts"), Buffer.from([0xff, 0xfe]));
	await assert.rejects(loadSnapshot(parseConfig(config({ files: ["src/bad.ts"] })), directory));
	await writeFile(path.join(directory, "src", "large.ts"), "x".repeat(501));
	await assert.rejects(loadSnapshot(parseConfig(config({ files: ["src/large.ts"] })), directory));
	await symlink(path.join(directory, "src", "app.ts"), path.join(directory, "src", "linked.ts"));
	await assert.rejects(loadSnapshot(parseConfig(config({ files: ["src/linked.ts"] })), directory));
	await symlink(path.join(directory, "src"), path.join(directory, "linked-root"));
	await assert.rejects(loadSnapshot(parseConfig(config({ root: "linked-root" })), directory));
	await mkdir(path.join(directory, "real-root", "nested"), { recursive: true });
	await writeFile(path.join(directory, "real-root", "nested", "app.ts"), "export {};\n");
	await symlink(path.join(directory, "real-root"), path.join(directory, "alias"));
	await assert.rejects(loadSnapshot(parseConfig(config({ root: "alias/nested", files: ["app.ts"] })), directory));
	if (process.platform !== "win32") {
		const fifoPath = path.join(directory, "src", "stream.ts");
		await execFileAsync("mkfifo", [fifoPath]);
		await assert.rejects(loadSnapshot(parseConfig(config({ files: ["src/stream.ts"] })), directory));
	}
});
