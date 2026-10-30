import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

export class EngineStateBusyError extends Error {
	constructor() {
		super("engine state busy, retry");
		this.name = "EngineStateBusyError";
	}
}

export function scanActivity(dataDir: string, scanId: string) {
	const scanDir = join(dataDir, "scans", scanId);
	const tasks = readTasks(join(scanDir, "engine-output", "state.sqlite"));
	const files = readFiles(join(scanDir, "manifest.json"));
	return { tasks, files };
}

function readTasks(statePath: string) {
	if (!existsSync(statePath)) return [];
	let db: DatabaseSync | undefined;
	try {
		db = new DatabaseSync(statePath, { readOnly: true, timeout: 1000 });
		return db.prepare("SELECT id, stage, attempts, status, result, error FROM tasks ORDER BY rowid").all().map(mapTask);
	} catch (error) {
		if (isBusy(error)) throw new EngineStateBusyError();
		if (!existsSync(statePath) && isDatabaseOpenError(error)) return [];
		throw error;
	} finally {
		db?.close();
	}
}

function mapTask(row: Record<string, unknown>) {
	const result = parseResult(row.result);
	const value = result?.value && typeof result.value === "object" ? result.value as Record<string, unknown> : null;
	const stage = typeof row.stage === "string" ? row.stage : "";
	let summary: string | null = null;
	let findings: number | null = null;
	let verdict: string | null = null;

	if (value) {
		if (stage.startsWith("recon")) summary = toSummary(value.summary);
		else if (stage.startsWith("hunt") || stage.startsWith("gapfill")) {
			summary = toSummary(value.coverage);
			findings = Array.isArray(value.findings) ? value.findings.length : null;
		} else if (stage.startsWith("validate")) {
			verdict = typeof value.verdict === "string" ? value.verdict : null;
			summary = toSummary(value.reason);
		} else if (stage === "feedback") summary = toSummary(value.notes);
		else if (stage.startsWith("wishlist")) summary = `${value.need} — ${value.reason}`;
		else if (stage === "trace" && Array.isArray(value.edges)) summary = `${value.edges.length} call edges traced`;
	}

	return {
		id: row.id,
		stage: row.stage,
		status: row.status,
		attempts: row.attempts,
		error: typeof row.error === "string" ? row.error : null,
		summary: summary === null ? null : summary.slice(0, 600),
		findings,
		verdict,
		inputTokens: numeric(result?.inputTokens),
		outputTokens: numeric(result?.outputTokens),
	};
}

function parseResult(value: unknown): Record<string, unknown> | null {
	if (typeof value !== "string") return null;
	try {
		const parsed = JSON.parse(value);
		return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
	} catch {
		return null;
	}
}

function toSummary(value: unknown): string | null {
	if (typeof value === "string") return value;
	if (value === null || value === undefined) return null;
	try {
		return JSON.stringify(value) ?? null;
	} catch {
		return null;
	}
}

function numeric(value: unknown): number | null {
	return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function readFiles(manifestPath: string) {
	try {
		const value = JSON.parse(readFileSync(manifestPath, "utf8"));
		if (!Array.isArray(value)) return [];
		return value
			.filter((file): file is { path: string; sha256: string } =>
				file !== null && typeof file === "object" && typeof file.path === "string" && typeof file.sha256 === "string")
			.map(({ path, sha256 }) => ({ path, sha256 }));
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
		throw error;
	}
}

function isBusy(error: unknown) {
	const details = error as { code?: string; message?: string };
	return details.code === "SQLITE_BUSY" || details.code === "SQLITE_LOCKED" || /database (?:table )?is locked|SQLITE_BUSY|SQLITE_LOCKED/i.test(details.message ?? "");
}

function isDatabaseOpenError(error: unknown) {
	const details = error as { code?: string; message?: string };
	return details.code === "ENOENT" || /unable to open database file/i.test(details.message ?? "");
}
