import { copyFile, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { resolve, join, dirname, extname, basename, sep, posix } from "node:path";
import { config } from "./config.ts";
import { NebiusClient } from "./nebius.ts";
import { Sandbox, SandboxError } from "./sandbox.ts";
import { writeEvidence } from "./evidence.ts";
import { OUTPUT_SCHEMAS, renderPrompt, type PromptName } from "./prompts.ts";
import { Store } from "./store.ts";

const exec = promisify(execFile);
const tail = (text: string) => text.slice(-12000);
const cited = (data: any): string[] => [...new Set((data.finding?.evidence ?? data.evidence ?? []).map((item: any) => item.path).filter((item: unknown) => typeof item === "string"))];
const JS_SOURCE_EXTENSIONS = new Set([".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx"]);
const IMPORT_EXTENSIONS = [".js", ".cjs", ".mjs", ".ts", ".json"];

export function classify(result: { exitCode: number; timedOut: boolean; stdout: string }): "vulnerable" | "safe" | "inconclusive" {
	if (!result.timedOut && result.exitCode === 1 && result.stdout.includes("BUGCLAW_VULNERABLE")) return "vulnerable";
	if (!result.timedOut && result.exitCode === 0 && result.stdout.includes("BUGCLAW_SAFE")) return "safe";
	return "inconclusive";
}

function repairEscapedContent(content: string): { content: string; repaired?: "unescaped-newlines" } {
	if (content.includes("\n") || !content.includes("\\n")) return { content };
	return {
		content: content.replace(/\\n|\\t|\\"|\\\\/g, (escape) => {
			switch (escape) {
				case "\\n": return "\n";
				case "\\t": return "\t";
				case '\\"': return '"';
				case "\\\\": return "\\";
				default: return escape;
			}
		}),
		repaired: "unescaped-newlines",
	};
}

export function validatePoc(poc: any, citedFiles: string[], snapshotFiles: string[]) {
	if (!poc || !Array.isArray(poc.files) || poc.files.length < 1 || poc.files.length > 3 || !Array.isArray(poc.command) || !poc.command.length || poc.command.some((part: unknown) => typeof part !== "string")) throw new Error("invalid PoC shape");
	if (!["node", "python3", "forge", "anvil"].includes(poc.command[0]) || poc.command.some((part: string) => /node_modules/.test(part))) {
		throw new Error("invalid PoC command");
	}
	let repaired: "unescaped-newlines" | undefined;
	for (const file of poc.files) {
		if (typeof file.path !== "string" || typeof file.content !== "string") throw new Error("invalid PoC file");
		const parts = file.path.replaceAll("\\", "/").split("/");
		if (file.path.startsWith("/") || parts.some((part: string) => part === "..") || parts[0] !== ".bugclaw" || parts[1] !== "poc") throw new Error("PoC paths must be under .bugclaw/poc/");
		const normalized = repairEscapedContent(file.content);
		file.content = normalized.content;
		repaired ??= normalized.repaired;
		if (file.content.split("\n").length > 120) throw new Error("PoC exceeds 120 lines");
	}
	const availablePaths = new Set([...poc.files.map((file: any) => file.path.replaceAll("\\", "/")), ...snapshotFiles]);
	for (const file of poc.files) {
		const filePath = file.path.replaceAll("\\", "/");
		if (!JS_SOURCE_EXTENSIONS.has(posix.extname(filePath).toLowerCase())) continue;
		for (const match of file.content.matchAll(/(?:require\s*\(\s*|from\s+|import\s*\(\s*)["'](\.{1,2}\/[^"']+)["']/g)) {
			const spec = match[1];
			const resolved = posix.normalize(posix.join(posix.dirname(filePath), spec));
			if (availablePaths.has(resolved) || IMPORT_EXTENSIONS.some((extension) => availablePaths.has(`${resolved}${extension}`)) || availablePaths.has(`${resolved}/index.js`)) continue;
			const specBasename = posix.basename(spec);
			const guess = snapshotFiles.find((candidate) => posix.basename(candidate) === specBasename) ?? citedFiles[0] ?? "";
			throw new Error(`${file.path} imports "${spec}", which resolves to ${resolved} and does not exist. Load snapshot files by absolute path, e.g. require(require("path").resolve(process.cwd(), "${guess}"))`);
		}
	}
	const references = [...poc.files.map((file: any) => file.content), ...poc.command].join("\n");
	if (!citedFiles.some((file) => references.includes(file) || references.includes(basename(file, extname(file)))) ) throw new Error("does not exercise cited code");
	return repaired;
}

export function validateFixFiles(value: unknown, citedFiles: string[]) {
	if (!Array.isArray(value) || !value.length || value.some((file: any) => !file || !citedFiles.includes(file.path) || typeof file.content !== "string")) {
		throw new Error("fix changes files outside cited source");
	}
	let repaired: "unescaped-newlines" | undefined;
	const files = (value as Array<{ path: string; content: string }>).map((file) => {
		const normalized = repairEscapedContent(file.content);
		repaired ??= normalized.repaired;
		return { ...file, content: normalized.content };
	});
	return { files, repaired };
}

export async function reproduce(scanId: string, candidateId?: string, services: { store?: Store; model?: NebiusClient; sandbox?: Sandbox } = {}) {
	const store = services.store ?? new Store();
	const model = services.model ?? new NebiusClient();
	const sandbox = services.sandbox ?? new Sandbox();
	const cfg = config();
	const runId = `${new Date().toISOString().replace(/[-:.]/g, "")}-${randomUUID().slice(0, 8)}`;
	if (!process.env.NEBIUS_API_KEY) throw new Error("NEBIUS_API_KEY is required");
	const candidates = store.candidates(scanId) as Array<{id:string; data:string}>;
	const rows = candidates.filter((row) => !candidateId || row.id === candidateId);
	if (!rows.length) throw new Error("No matching candidate");
	const manifest = JSON.parse(await readFile(join(cfg.dataDir, "scans", scanId, "manifest.json"), "utf8")) as Array<{ path: string }>;
	const snapshotFiles = manifest.map((item) => item.path);
	const output = [];
	for (const row of rows) {
		const raw = JSON.parse(row.data);
		const files = cited(raw);
		if (!files.length) {
			const reason = "candidate has no cited source files";
			store.attempt(row.id, "poc", { status: "not-reproducible", reason });
			const stored = { ...raw, reproStatus: "not-reproducible", reproReason: reason };
			store.setCandidateStatus(row.id, "not-reproducible", stored);
			output.push({ candidateId: row.id, status: "not-reproducible", attempts: store.attempts(row.id).length, reason });
			continue;
		}
		const snapshot = join(cfg.dataDir, "scans", scanId, "snapshot");
		const sourceData = await Promise.all(files.map(async (file) => ({ path: file, content: await readFile(resolve(snapshot, file), "utf8") })));
		const citedFilesWithLines = sourceData.map((file) => `${file.path}\n${file.content.split("\n").map((line, index) => `${index + 1}: ${line}`).join("\n")}`);
		let poc: any = null;
		let pocRepair: "unescaped-newlines" | undefined;
		let vulnerableRun: any = null;
		let contractError = "none";
		let retrySandboxResult: unknown = { notRun: true };
		let status = "not-reproducible";
		let terminalReason: string | undefined;
		for (let n = 1; n <= 3; n++) {
			const started = new Date().toISOString();
			try {
				const promptName: PromptName = n === 1 ? "POC" : "POC_RETRY";
				const prompt = renderPrompt(promptName, {
					RUNTIMES: "node 22, python 3.11, forge/anvil (Foundry)",
					CANDIDATE_JSON: raw,
					CITED_FILES_WITH_LINE_NUMBERS: citedFilesWithLines,
					PREVIOUS_POC_JSON: poc,
					SANDBOX_RESULT: retrySandboxResult,
					CONTRACT_ERROR: contractError,
				});
				let generated: any;
				let modelCallSucceeded = false;
				let modelCallError: unknown;
				for (let retry = 0; retry < 3; retry++) {
					try {
						generated = await model.complete(cfg.models.repro, prompt.system, prompt.prompt, OUTPUT_SCHEMAS[promptName]);
						modelCallSucceeded = true;
						break;
					} catch (error) {
						modelCallError = error;
					}
				}
				if (!modelCallSucceeded) {
					terminalReason = modelCallError instanceof Error ? modelCallError.message : String(modelCallError);
					status = "model-error";
					store.attempt(row.id, "poc", { status, reason: terminalReason });
					break;
				}
				terminalReason = undefined;
				poc = generated.value;
				if (poc && typeof poc === "object" && !Array.isArray(poc) && Object.keys(poc).length === 1 && typeof poc.cannotReproduce === "string" && poc.cannotReproduce.trim()) {
					terminalReason = poc.cannotReproduce;
					status = "not-reproducible";
					store.attempt(row.id, "poc", { status, reason: terminalReason });
					break;
				}
				try {
					pocRepair = validatePoc(poc, files, snapshotFiles);
				} catch (error) {
					contractError = error instanceof Error ? error.message : String(error);
					retrySandboxResult = { notRun: true };
					store.attempt(row.id, "poc", { status: "invalid", reason: contractError });
					if (n === 3) {
						status = "invalid-poc";
						terminalReason = contractError;
						break;
					}
					continue;
				}
				const result = await sandbox.run(snapshot, poc.files, poc.command, 120);
				contractError = "none";
				retrySandboxResult = { exitCode: result.exitCode, stdoutTail: tail(result.stdout), stderrTail: tail(result.stderr), timedOut: result.timedOut };
				const classification = classify(result);
				const evidence = await writeEvidence({
					dataDir: cfg.dataDir, scanId, candidateId: row.id, runId, step: "poc", number: n, files: poc.files, argv: poc.command, run: result,
					meta: { snapshotHash: (store.scan(scanId) as any)?.snapshot_hash, ...result, modelId: cfg.models.repro, tokens: { input: generated.inputTokens, output: generated.outputTokens }, classification, ...(pocRepair ? { repaired: pocRepair } : {}), startedAt: started, endedAt: new Date().toISOString() },
				});
				store.attempt(row.id, "poc", { status: classification, evidence });
				if (classification === "safe") { status = "not-reproduced"; terminalReason = undefined; break; }
				if (classification === "vulnerable") { vulnerableRun = result; break; }
				terminalReason = "PoC execution did not produce a decisive vulnerability or safe marker";
				vulnerableRun = result;
			} catch (error) {
				if (error instanceof SandboxError) {
					store.attempt(row.id, "poc", { status: "sandbox-error", reason: error.message });
					status = "sandbox-error";
					terminalReason = error.message;
					break;
				}
				terminalReason = error instanceof Error ? error.message : String(error);
				store.attempt(row.id, "poc", { status: "inconclusive", reason: terminalReason });
			}
		}
		if (vulnerableRun && classify(vulnerableRun) === "vulnerable") {
			const judgePrompt = renderPrompt("JUDGE", {
				CANDIDATE_JSON: raw, POC_JSON: poc,
				SANDBOX_RESULT: { exitCode: vulnerableRun.exitCode, stdoutTail: tail(vulnerableRun.stdout), stderrTail: tail(vulnerableRun.stderr) },
				CITED_FILES_WITH_LINE_NUMBERS: citedFilesWithLines,
			});
			const judgment = await model.complete(cfg.models.judge, judgePrompt.system, judgePrompt.prompt, OUTPUT_SCHEMAS.JUDGE);
			store.attempt(row.id, "judge", {
				status: judgment.value.verdict,
				verdict: judgment.value.verdict,
				reason: judgment.value.reason,
				modelId: cfg.models.judge,
				tokens: { input: judgment.inputTokens, output: judgment.outputTokens },
			});
			if (judgment.value.verdict !== "genuine") {
				status = "not-reproducible";
				terminalReason = judgment.value.reason;
			}
			else {
				status = "reproduced";
				terminalReason = undefined;
				let fixed = false;
				let previousFix: unknown = null;
				for (let attempt = 0; attempt < 2; attempt++) {
					const fixStarted = new Date().toISOString();
					const prompt = renderPrompt(attempt ? "FIX_RETRY" : "FIX", {
						CANDIDATE_JSON: raw, POC_JSON: poc, PREVIOUS_FIX_JSON: previousFix,
						SANDBOX_RESULT: vulnerableRun, CITED_FILES_FULL: sourceData,
					});
					const proposal = await model.complete(cfg.models.fix, prompt.system, prompt.prompt, OUTPUT_SCHEMAS[attempt ? "FIX_RETRY" : "FIX"]);
					previousFix = proposal.value;
					const fixDetails = {
						summary: proposal.value.summary,
						modelId: cfg.models.fix,
						tokens: { input: proposal.inputTokens, output: proposal.outputTokens },
					};
					let fixFiles: Array<{ path: string; content: string }>;
					let fixRepair: "unescaped-newlines" | undefined;
					try {
						const validated = validateFixFiles(proposal.value.files, files);
						fixFiles = validated.files;
						fixRepair = validated.repaired;
					}
					catch {
						store.attempt(row.id, "fix", { status: "fix-failed", reason: "fix changes files outside cited source", ...fixDetails });
						break;
					}
					const patched = await mkdtempForFix();
					try {
						await copySnapshot(snapshot, patched);
						for (const file of fixFiles) {
							const target = resolve(patched, file.path);
							if (!target.startsWith(`${patched}${sep}`)) throw new Error("Unsafe fix path");
							await mkdir(dirname(target), { recursive: true });
							await writeFile(target, file.content);
						}
						let result: Awaited<ReturnType<Sandbox["run"]>>;
						try {
							result = await sandbox.run(patched, poc.files, poc.command, 120);
						} catch (error) {
							if (!(error instanceof SandboxError)) throw error;
							store.attempt(row.id, "fix", { status: "sandbox-error", reason: error.message, ...fixDetails });
							status = "sandbox-error";
							break;
						}
						const diff = await getDiff(snapshot, patched);
						const classification = classify(result);
						await writeEvidence({
							dataDir: cfg.dataDir, scanId, candidateId: row.id, runId, step: "fix", number: attempt + 1, files: [...poc.files, ...fixFiles], argv: poc.command, run: result,
							meta: { snapshotHash: (store.scan(scanId) as any)?.snapshot_hash, ...result, modelId: cfg.models.fix, tokens: { input: proposal.inputTokens, output: proposal.outputTokens }, classification, ...(pocRepair || fixRepair ? { repaired: "unescaped-newlines" } : {}), startedAt: fixStarted, endedAt: new Date().toISOString() },
							fixDiff: diff,
						});
						fixed = classification === "safe";
						store.attempt(row.id, "fix", { status: fixed ? "fix-verified" : "fix-failed", ...fixDetails });
						if (fixed) break;
						vulnerableRun = result;
					} finally { await rm(patched, { recursive: true, force: true }); }
				}
				if (status !== "sandbox-error") status = fixed ? "fix-verified" : "fix-failed";
			}
		}
		const stored = JSON.parse(row.data);
		stored.reproStatus = status;
		if (terminalReason) stored.reproReason = terminalReason;
		else delete stored.reproReason;
		store.setCandidateStatus(row.id, status, stored);
		output.push({ candidateId: row.id, status, attempts: store.attempts(row.id).length, ...(terminalReason ? { reason: terminalReason } : {}) });
	}
	return output;
}

async function mkdtempForFix() {
	const dir = join(config().dataDir, "fix-work", randomUUID());
	await mkdir(dir, { recursive: true, mode: 0o700 });
	return dir;
}
async function copySnapshot(from: string, to: string) {
	for (const item of await readdir(from, { withFileTypes: true })) {
		const src = join(from, item.name), dst = join(to, item.name);
		if (item.isDirectory()) { await mkdir(dst, { recursive: true }); await copySnapshot(src,dst); }
		else if (item.isFile()) await copyFile(src,dst);
	}
}
async function getDiff(before: string, after: string) {
	try { return (await exec("git",["diff","--no-index","--",before,after],{maxBuffer:4_000_000})).stdout; }
	catch (error: any) { if (error.code === 1) return error.stdout ?? ""; throw error; }
}
