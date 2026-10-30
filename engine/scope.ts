import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";

export interface ModelRef {
	provider: string;
	id: string;
}

export type Domain = "web2" | "web3" | "ai";

export interface HarnessConfig {
	version: 1;
	name: string;
	authorization: {
		reference: string;
		expiresAt: string;
		allowRemoteModels: boolean;
	};
	root: string;
	files: string[];
	domains: Domain[];
	models: {
		recon: ModelRef;
		hunter: ModelRef;
		validator: ModelRef;
	};
	limits: {
		maxCalls: number;
		maxInputChars: number;
		maxOutputTokens: number;
		timeoutMs: number;
		concurrency: number;
		passes: number;
		maxFindingsPerTask: number;
	};
}

export interface SourceFile {
	path: string;
	content: string;
	sha256: string;
	lines: number;
}

export interface Snapshot {
	root: string;
	digest: string;
	files: SourceFile[];
}

const LIMITS = {
	maxCalls: 1_000,
	maxInputChars: 2_000_000,
	maxOutputTokens: 100_000,
	timeoutMs: 3_600_000,
	concurrency: 8,
	passes: 3,
	maxFindingsPerTask: 20,
} as const;

const MAX_FILES = 500;

const SOURCE_EXTENSIONS = new Set([
	".ts",
	".tsx",
	".mts",
	".cts",
	".js",
	".jsx",
	".mjs",
	".cjs",
	".vue",
	".svelte",
	".py",
	".go",
	".rs",
	".java",
	".c",
	".cpp",
	".h",
	".hpp",
	".cs",
	".rb",
	".php",
	".sol",
	".vy",
	".yul",
	".json",
	".yaml",
	".yml",
	".toml",
	".md",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

function fail(message: string): never {
	throw new Error(`Invalid engine configuration: ${message}`);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], location: string): void {
	const expected = new Set(keys);
	for (const key of Object.keys(value)) {
		if (!expected.has(key)) fail(`${location} contains unknown key ${JSON.stringify(key)}`);
	}
	for (const key of keys) {
		if (!(key in value)) fail(`${location}.${key} is required`);
	}
}

function object(value: unknown, location: string, keys: readonly string[]): Record<string, unknown> {
	if (!isRecord(value)) fail(`${location} must be an object`);
	exactKeys(value, keys, location);
	return value;
}

function text(value: unknown, location: string, maxLength = 2_000): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.trim().length === 0 ||
		value.length > maxLength ||
		/[\u0000-\u001f\u007f-\u009f]/.test(value)
	) {
		fail(`${location} must be a non-empty string no longer than ${maxLength} characters`);
	}
	return value;
}

function positiveInteger(value: unknown, location: string, maximum: number): number {
	if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
		fail(`${location} must be a positive integer no greater than ${maximum}`);
	}
	return value as number;
}

function validateExpiry(value: unknown, location: string): string {
	const expiry = text(value, location, 64);
	const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?Z$/.exec(expiry);
	if (!match) fail(`${location} must be an ISO-8601 UTC timestamp`);
	const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
	const date = new Date(0);
	date.setUTCFullYear(year, month - 1, day);
	date.setUTCHours(hour, minute, second, 0);
	if (
		month < 1 ||
		month > 12 ||
		day < 1 ||
		day > 31 ||
		hour > 23 ||
		minute > 59 ||
		second > 59 ||
		date.getUTCFullYear() !== year ||
		date.getUTCMonth() !== month - 1 ||
		date.getUTCDate() !== day
	) {
		fail(`${location} is not a valid timestamp`);
	}
	if (Date.parse(expiry) <= Date.now()) fail(`${location} has expired`);
	return expiry;
}

function relativePath(value: unknown, location: string, allowDot: boolean): string {
	const candidate = text(value, location, 1_024);
	if (candidate === "." && allowDot) return candidate;
	if (
		candidate.includes("\\") ||
		path.isAbsolute(candidate) ||
		/^[A-Za-z]:/.test(candidate) ||
		/[*?[\]{}!]/.test(candidate) ||
		path.posix.normalize(candidate) !== candidate ||
		candidate.split("/").some((part) => part === "" || part === "." || part === "..")
	) {
		fail(`${location} must be a normalized relative path without traversal or globs`);
	}
	if (candidate === ".") fail(`${location} must name a file`);
	return candidate;
}

function model(value: unknown, location: string): ModelRef {
	const result = object(value, location, ["provider", "id"]);
	return { provider: text(result.provider, `${location}.provider`, 200), id: text(result.id, `${location}.id`, 500) };
}

export function parseConfig(value: unknown): HarnessConfig {
	const config = object(value, "config", [
		"version",
		"name",
		"authorization",
		"root",
		"files",
		"domains",
		"models",
		"limits",
	]);
	if (config.version !== 1) fail("config.version must be 1");
	const authorization = object(config.authorization, "config.authorization", [
		"reference",
		"expiresAt",
		"allowRemoteModels",
	]);
	if (typeof authorization.allowRemoteModels !== "boolean")
		fail("config.authorization.allowRemoteModels must be a boolean");
	const filesValue = config.files;
	if (!Array.isArray(filesValue) || filesValue.length === 0 || filesValue.length > MAX_FILES) {
		fail(`config.files must be a non-empty array with at most ${MAX_FILES} entries`);
	}
	const files = filesValue.map((entry, index) => relativePath(entry, `config.files[${index}]`, false));
	if (new Set(files).size !== files.length) fail("config.files must not contain duplicates");
	const domainsValue = config.domains;
	if (
		!Array.isArray(domainsValue) ||
		domainsValue.length === 0 ||
		domainsValue.some((domain) => domain !== "web2" && domain !== "web3" && domain !== "ai")
	) {
		fail("config.domains must be a non-empty array of web2, web3, or ai");
	}
	const domains = domainsValue as Domain[];
	if (new Set(domains).size !== domains.length) fail("config.domains must not contain duplicates");
	const modelsValue = object(config.models, "config.models", ["recon", "hunter", "validator"]);
	const models = {
		recon: model(modelsValue.recon, "config.models.recon"),
		hunter: model(modelsValue.hunter, "config.models.hunter"),
		validator: model(modelsValue.validator, "config.models.validator"),
	};
	if (models.hunter.provider === models.validator.provider && models.hunter.id === models.validator.id) {
		fail("config.models.hunter and config.models.validator must differ");
	}
	const limitsValue = object(config.limits, "config.limits", Object.keys(LIMITS));
	const limits = {
		maxCalls: positiveInteger(limitsValue.maxCalls, "config.limits.maxCalls", LIMITS.maxCalls),
		maxInputChars: positiveInteger(limitsValue.maxInputChars, "config.limits.maxInputChars", LIMITS.maxInputChars),
		maxOutputTokens: positiveInteger(
			limitsValue.maxOutputTokens,
			"config.limits.maxOutputTokens",
			LIMITS.maxOutputTokens,
		),
		timeoutMs: positiveInteger(limitsValue.timeoutMs, "config.limits.timeoutMs", LIMITS.timeoutMs),
		concurrency: positiveInteger(limitsValue.concurrency, "config.limits.concurrency", LIMITS.concurrency),
		passes: positiveInteger(limitsValue.passes, "config.limits.passes", LIMITS.passes),
		maxFindingsPerTask: positiveInteger(
			limitsValue.maxFindingsPerTask,
			"config.limits.maxFindingsPerTask",
			LIMITS.maxFindingsPerTask,
		),
	};
	return {
		version: 1,
		name: text(config.name, "config.name", 200),
		authorization: {
			reference: text(authorization.reference, "config.authorization.reference"),
			expiresAt: validateExpiry(authorization.expiresAt, "config.authorization.expiresAt"),
			allowRemoteModels: authorization.allowRemoteModels,
		},
		root: relativePath(config.root, "config.root", true),
		files,
		domains,
		models,
		limits,
	};
}

function isSensitiveBasename(filePath: string): boolean {
	const name = path.posix.basename(filePath).toLowerCase();
	return (
		filePath
			.toLowerCase()
			.split("/")
			.some(
				(component) =>
					component === ".git" ||
					component === ".ssh" ||
					component === "private-keys" ||
					component === "private_keys",
			) ||
		name === ".env" ||
		name.startsWith(".env.") ||
		/^(?:id_(?:rsa|dsa|ecdsa|ed25519)|private[_-]?key|credentials?|secrets?)(?:\.[^.]+)?$/.test(name) ||
		/^service-account[^/]*\.(?:json|ya?ml|toml)$/i.test(name) ||
		/\.(?:pem|key|p12|pfx)$/i.test(name)
	);
}

async function assertDirectoryTree(root: string, relative = ""): Promise<void> {
	const target = relative === "" ? root : path.join(root, relative);
	const info = await lstat(target);
	if (info.isSymbolicLink() || !info.isDirectory())
		throw new Error(`Unsafe snapshot root component: ${relative || root}`);
}

async function assertFileParents(root: string, sourcePath: string): Promise<void> {
	await assertDirectoryTree(root);
	let current = "";
	for (const component of sourcePath.split("/").slice(0, -1)) {
		current = current === "" ? component : path.join(current, component);
		await assertDirectoryTree(root, current);
	}
}

async function readSourceFile(
	root: string,
	sourcePath: string,
	maximumBytes: number,
): Promise<{ file: SourceFile; byteLength: number }> {
	if (!SOURCE_EXTENSIONS.has(path.posix.extname(sourcePath)) || isSensitiveBasename(sourcePath)) {
		throw new Error(`Unsafe snapshot file: ${sourcePath}`);
	}
	await assertFileParents(root, sourcePath);
	const absolutePath = path.join(root, ...sourcePath.split("/"));
	const initial = await lstat(absolutePath);
	if (initial.isSymbolicLink() || !initial.isFile()) throw new Error(`Unsafe snapshot file: ${sourcePath}`);
	const handle = await open(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
	try {
		const before = await handle.stat();
		if (!before.isFile() || before.size > maximumBytes)
			throw new Error(`Snapshot file exceeds its size limit: ${sourcePath}`);
		const buffer = Buffer.alloc(before.size + 1);
		let offset = 0;
		while (offset < buffer.length) {
			const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
			if (bytesRead === 0) break;
			offset += bytesRead;
		}
		const after = await handle.stat();
		// This detects ordinary concurrent changes; a hostile filesystem is not a sandbox boundary.
		if (
			!after.isFile() ||
			after.dev !== before.dev ||
			after.ino !== before.ino ||
			after.size !== before.size ||
			after.mtimeMs !== before.mtimeMs ||
			after.ctimeMs !== before.ctimeMs ||
			offset !== before.size
		) {
			throw new Error(`Snapshot file changed while being read: ${sourcePath}`);
		}
		const bytes = buffer.subarray(0, offset);
		if (bytes.includes(0)) throw new Error(`Snapshot file is binary: ${sourcePath}`);
		let content: string;
		try {
			content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
		} catch {
			throw new Error(`Snapshot file is not valid UTF-8: ${sourcePath}`);
		}
		return {
			file: {
				path: sourcePath,
				content,
				sha256: createHash("sha256").update(bytes).digest("hex"),
				lines: content === "" ? 0 : content.split("\n").length,
			},
			byteLength: bytes.length,
		};
	} finally {
		await handle.close();
	}
}

export async function loadSnapshot(config: HarnessConfig, configDirectory: string): Promise<Snapshot> {
	validateExpiry(config.authorization.expiresAt, "config.authorization.expiresAt");
	const configRoot = await realpath(configDirectory);
	await assertDirectoryTree(configRoot);
	const configuredRoot = relativePath(config.root, "config.root", true);
	let root = configRoot;
	if (configuredRoot !== ".") {
		for (const component of configuredRoot.split("/")) {
			root = path.join(root, component);
			await assertDirectoryTree(root);
		}
	}
	const totalLimit = Math.floor(config.limits.maxInputChars / 2);
	let totalBytes = 0;
	const files: SourceFile[] = [];
	for (const sourcePath of config.files) {
		const remaining = totalLimit - totalBytes;
		if (remaining <= 0) throw new Error("Snapshot exceeds half of maxInputChars");
		const { file, byteLength } = await readSourceFile(root, sourcePath, remaining);
		totalBytes += byteLength;
		if (totalBytes > totalLimit) throw new Error("Snapshot exceeds half of maxInputChars");
		files.push(file);
	}
	const digest = createHash("sha256");
	for (const file of files) {
		const pathBytes = Buffer.from(file.path, "utf8");
		digest
			.update(Buffer.from(`${pathBytes.length}:`, "ascii"))
			.update(pathBytes)
			.update(Buffer.from(`${file.sha256.length}:`, "ascii"))
			.update(file.sha256, "ascii");
	}
	return { root, digest: digest.digest("hex"), files };
}
