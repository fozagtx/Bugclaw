import { createHash } from "node:crypto";
import { copyFile, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";

const run = promisify(execFile);
const EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".go", ".rs", ".sol", ".java", ".rb", ".php"]);
const SKIP = new Set(["node_modules", "vendor", "dist", "build", ".git"]);
const GIT_URL = /^(https?|git|file):\/\//i;
const GIT_REF = /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,99}$/;
const sha = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");

export function parseGitSource(source: string) {
	if (!GIT_URL.test(source)) return { url: source, ref: null as string | null, isGitUrl: false };
	const hash = source.lastIndexOf("#");
	const url = hash === -1 ? source : source.slice(0, hash);
	const ref = hash === -1 ? null : source.slice(hash + 1);
	if (ref !== null && (!GIT_REF.test(ref) || ref.includes(".."))) throw new Error("Invalid Git ref");
	const parsed = new URL(url);
	if (parsed.username || parsed.password || parsed.search || parsed.hash) {
		throw new Error("Git URL must not contain credentials or query parameters");
	}
	return { url, ref, isGitUrl: true };
}

export async function makeSnapshot(source: string, scanDir: string, explicit?: string[]) {
	const src = path.join(scanDir, "src");
	await mkdir(scanDir, { recursive: true });
	const gitSource = parseGitSource(source);
	let commit: string | null = null;
	if (gitSource.isGitUrl) {
		const args = gitSource.ref === null
			? ["clone", "--depth", "1", "--", gitSource.url, src]
			: ["clone", "--depth", "1", "--branch", gitSource.ref, "--", gitSource.url, src];
		await run("git", args, { timeout: 120000 });
		commit = (await run("git", ["-C", src, "rev-parse", "HEAD"], { timeout: 120000 })).stdout.trim();
	}
	else await copyTree(path.resolve(source), src);
	const snapshot = path.join(scanDir, "snapshot");
	await mkdir(snapshot, { recursive: true });
	const paths = explicit ? explicit.map(safeRelative) : await selectFiles(src);
	if (!paths.length || paths.length > 200) throw new Error("Snapshot requires 1-200 source files");
	const manifest: Array<{ path: string; sha256: string }> = [];
	for (const relative of [...new Set(paths)].sort()) {
		const from = path.resolve(src, relative);
		if (!from.startsWith(`${src}${path.sep}`)) throw new Error("Unsafe snapshot path");
		const content = await readFile(from);
		const to = path.resolve(snapshot, relative);
		await mkdir(path.dirname(to), { recursive: true });
		await copyFile(from, to);
		manifest.push({ path: relative, sha256: sha(content) });
	}
	const serialized = JSON.stringify(manifest);
	await writeFile(path.join(scanDir, "manifest.json"), `${serialized}\n`, { mode: 0o600 });
	return { src, snapshot, files: manifest.map((item) => item.path), manifest, snapshotHash: sha(serialized), ref: gitSource.ref, commit };
}

function safeRelative(input: string) {
	const normalized = input.replaceAll("\\", "/");
	if (!normalized || normalized.startsWith("/") || /^[A-Za-z]:/.test(normalized) || normalized.split("/").some((part) => part === ".." || part === ".")) throw new Error("Unsafe explicit file path");
	return normalized;
}

async function copyTree(from: string, to: string) {
	await mkdir(to, { recursive: true });
	for (const item of await readdir(from, { withFileTypes: true })) {
		if (SKIP.has(item.name)) continue;
		const src = path.join(from, item.name);
		const dst = path.join(to, item.name);
		if (item.isSymbolicLink()) continue;
		if (item.isDirectory()) await copyTree(src, dst);
		else if (item.isFile()) {
			await mkdir(path.dirname(dst), { recursive: true });
			await copyFile(src, dst);
		}
	}
}

async function selectFiles(root: string): Promise<string[]> {
	const selected: string[] = [];
	async function walk(dir: string, rel = ""): Promise<void> {
		for (const item of await readdir(dir, { withFileTypes: true })) {
			if (SKIP.has(item.name)) continue;
			const child = path.join(rel, item.name);
			if (/(^|\/)(test|tests|__tests__)(\/|$)|\.(test|spec)\.[^.]+$/i.test(child)) continue;
			const absolute = path.join(root, child);
			if (item.isSymbolicLink()) continue;
			if (item.isDirectory()) await walk(absolute, child);
			else if (item.isFile() && EXT.has(path.extname(item.name))) {
				selected.push(child.replaceAll(path.sep, "/"));
				if (selected.length > 200) throw new Error("Source selection exceeds 200 files");
			}
		}
	}
	await walk(root);
	return selected;
}
