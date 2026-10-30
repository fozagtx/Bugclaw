import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { config } from "./config.ts";
import { makeSnapshot } from "./snapshot.ts";
import { Store } from "./store.ts";

export async function scan(options: { source: string; authorization: string; files?: string[]; domains?: string[]; id?: string }, store = new Store(), progress: (event: unknown) => void = () => {}) {
	const id = options.id ?? randomUUID();
	if (/^(https?|git):\/\//.test(options.source)) {
		const url = new URL(options.source);
		if (url.username || url.password || url.search || url.hash) throw new Error("Git URL must not contain credentials or query parameters");
	}
	const cfg = config();
	const dir = join(cfg.dataDir, "scans", id);
	await mkdir(dir, { recursive: true, mode: 0o700 });
	store.createScan({ id, source: options.source, authorization: options.authorization });
	try {
		const snap = await makeSnapshot(options.source, dir, options.files);
		store.setScan(id, "running", snap.snapshotHash);
		const scopePath = join(dir, "scope.json");
		const out = join(dir, "engine-output");
		const scope = {
			version: 1, name: `bugclaw-${id}`,
			authorization: { reference: options.authorization, expiresAt: new Date(Date.now() + 7 * 86400000).toISOString().replace(/\.\d{3}Z$/, "Z"), allowRemoteModels: true },
			root: "snapshot", files: snap.files, domains: options.domains ?? ["web2"],
			models: {
				recon: { provider: "nebius", id: cfg.models.recon.replace(/^nebius\//, "") },
				hunter: { provider: "nebius", id: cfg.models.hunter.replace(/^nebius\//, "") },
				validator: { provider: "nebius", id: cfg.models.validator.replace(/^nebius\//, "") },
			},
			limits: { maxCalls: 200, maxInputChars: 400000, maxOutputTokens: 16000, timeoutMs: 1500000, concurrency: 6, passes: 1, maxFindingsPerTask: 5 },
		};
		await writeFile(scopePath, `${JSON.stringify(scope, null, 2)}\n`, { mode: 0o600 });
		let exitCode = await runEngine(cfg.engineDir, scopePath, out, progress);
		if (exitCode === 2) {
			progress({ type: "log", message: "resuming incomplete engine run" });
			exitCode = await runEngine(cfg.engineDir, scopePath, out, progress);
		}
		const [report, findings] = await Promise.all([
			readFile(join(out, "report.json"), "utf8").then(JSON.parse),
			readFile(join(out, "findings.json"), "utf8").then(JSON.parse),
		]);
		for (const candidate of findings.candidates ?? []) store.putCandidate(id, candidate);
		store.setScan(id, exitCode === 0 ? "complete" : "incomplete", snap.snapshotHash, report);
		return { id, status: exitCode === 0 ? "complete" : "incomplete", snapshot: snap, report, findings, outDir: dir };
	} catch (error) {
		store.setScan(id, "failed");
		throw error;
	}
}

async function runEngine(engineDir: string, scope: string, out: string, progress: (event: unknown) => void): Promise<number> {
	const cli = resolve(engineDir, "cli.ts");
	const child = spawn(process.execPath, ["--experimental-strip-types", cli, "run", scope, out, "--allow-remote-models", "--keep-models"], {
		env: Object.fromEntries(Object.entries({
			PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR,
			LANG: process.env.LANG, LC_ALL: process.env.LC_ALL, NEBIUS_API_KEY: process.env.NEBIUS_API_KEY,
			NEBIUS_BASE_URL: process.env.NEBIUS_BASE_URL,
		}).filter((entry): entry is [string, string] => typeof entry[1] === "string")),
		stdio: ["ignore", "pipe", "pipe"],
	});
	child.stdout.on("data", (chunk) => progress({ type: "output", stream: "stdout", text: String(chunk) }));
	child.stderr.on("data", (chunk) => progress({ type: "output", stream: "stderr", text: String(chunk) }));
	const timer = setInterval(() => {
		try {
			const db = new DatabaseSync(join(out, "state.sqlite"), { readOnly: true });
			progress({ type: "tasks", tasks: db.prepare("select id,stage,attempts,status,error from tasks").all() });
			db.close();
		} catch {}
	}, 2000);
	const result = await new Promise<{ code: number | null; error?: Error }>((resolvePromise) => {
		child.once("error", (error) => resolvePromise({ code: null, error }));
		child.once("close", (code) => resolvePromise({ code }));
	});
	clearInterval(timer);
	if (result.error) throw result.error;
	return result.code ?? 1;
}
