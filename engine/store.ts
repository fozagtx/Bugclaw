import { closeSync, lstatSync, mkdirSync, openSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export interface TaskRecord {
	id: string;
	stage: string;
	attempts: number;
	status: "pending" | "running" | "done" | "failed";
	result: unknown;
	error: string | null;
}

function fail(message: string): never {
	throw new Error(`engine run store: ${message}`);
}

function isMissing(error: unknown): boolean {
	return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function rejectSymbolicLinkAncestors(directory: string): void {
	const resolved = path.resolve(directory);
	const root = path.parse(resolved).root;
	const components: string[] = [];
	for (let current = resolved; current !== root; current = path.dirname(current)) components.push(current);

	for (const component of components.reverse()) {
		try {
			if (lstatSync(component).isSymbolicLink()) fail("state directory must not contain symbolic links");
		} catch (error) {
			if (isMissing(error)) return;
			throw error;
		}
	}
}

function ensurePrivateDirectory(directory: string): void {
	rejectSymbolicLinkAncestors(directory);
	try {
		const stat = lstatSync(directory);
		if (stat.isSymbolicLink() || !stat.isDirectory()) fail("state directory must be a real directory");
		if ((stat.mode & 0o077) !== 0) fail("state directory must not be accessible by group or others");
	} catch (error) {
		if (!isMissing(error)) throw error;
		mkdirSync(directory, { mode: 0o700 });
		const stat = lstatSync(directory);
		if (stat.isSymbolicLink() || !stat.isDirectory()) fail("state directory must be a real directory");
	}
}

function ensurePrivateDatabaseFile(file: string): void {
	try {
		const stat = lstatSync(file);
		if (stat.isSymbolicLink() || !stat.isFile()) fail("state database must be a regular file");
		if ((stat.mode & 0o077) !== 0) fail("state database must not be accessible by group or others");
		if (stat.nlink !== 1) fail("state database must not be hardlinked");
		return;
	} catch (error) {
		if (!isMissing(error)) throw error;
	}

	const descriptor = openSync(file, "wx", 0o600);
	closeSync(descriptor);
}

function ensureSafeRecoverySidecars(file: string): void {
	for (const suffix of ["-journal", "-wal", "-shm"]) {
		try {
			const stat = lstatSync(`${file}${suffix}`);
			if (stat.isSymbolicLink() || !stat.isFile()) fail("state recovery sidecar must be a regular file");
			if ((stat.mode & 0o077) !== 0) fail("state recovery sidecar must not be accessible by group or others");
			if (stat.nlink !== 1) fail("state recovery sidecar must not be hardlinked");
		} catch (error) {
			if (!isMissing(error)) throw error;
		}
	}
}

function changes(result: { changes: number | bigint }): number {
	return typeof result.changes === "bigint" ? Number(result.changes) : result.changes;
}

function rowToTask(row: Record<string, unknown>): TaskRecord {
	const { id, stage, attempts, status, result: encodedResult, error } = row;
	if (
		typeof id !== "string" ||
		typeof stage !== "string" ||
		typeof attempts !== "number" ||
		(status !== "pending" && status !== "running" && status !== "done" && status !== "failed") ||
		(encodedResult !== null && typeof encodedResult !== "string") ||
		(error !== null && typeof error !== "string")
	) {
		fail("stored task has an invalid shape");
	}

	let result: unknown = null;
	if (encodedResult !== null) {
		try {
			result = JSON.parse(encodedResult);
		} catch {
			fail("stored task result is invalid JSON");
		}
	}
	return { id, stage, attempts, status, result, error };
}

export class RunStore {
	private state: DatabaseSync;
	private lock: DatabaseSync;
	private closed = false;

	constructor(directory: string, identity: string) {
		let lock: DatabaseSync | undefined;
		let state: DatabaseSync | undefined;
		try {
			ensurePrivateDirectory(directory);
			const lockPath = path.join(directory, "lock.sqlite");
			const statePath = path.join(directory, "state.sqlite");
			ensurePrivateDatabaseFile(lockPath);
			ensurePrivateDatabaseFile(statePath);
			ensureSafeRecoverySidecars(lockPath);
			ensureSafeRecoverySidecars(statePath);

			lock = new DatabaseSync(lockPath);
			lock.exec("PRAGMA busy_timeout = 0; BEGIN EXCLUSIVE;");

			state = new DatabaseSync(statePath);
			state.exec(`
				PRAGMA journal_mode = DELETE;
				PRAGMA synchronous = FULL;
				CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
				CREATE TABLE IF NOT EXISTS tasks (
					id TEXT PRIMARY KEY,
					stage TEXT NOT NULL,
					attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 2),
					status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'done', 'failed')),
					result TEXT,
					error TEXT
				) STRICT;
			`);

			const existing = state.prepare("SELECT value FROM meta WHERE key = 'identity'").get();
			if (existing === undefined) {
				state.prepare("INSERT INTO meta (key, value) VALUES ('identity', ?)").run(identity);
			} else if (existing.value !== identity) {
				fail("identity does not match this run");
			}

			state
				.prepare(
					"UPDATE tasks SET status = 'failed', error = 'Interrupted; reserved call remains charged' WHERE status = 'running'",
				)
				.run();
			this.lock = lock;
			this.state = state;
		} catch (error) {
			try {
				state?.close();
			} finally {
				lock?.close();
			}
			throw error;
		}
	}

	ensure(id: string, stage: string): void {
		this.requireOpen();
		const task = this.state.prepare("SELECT stage FROM tasks WHERE id = ?").get(id);
		if (task === undefined) {
			this.state
				.prepare("INSERT INTO tasks (id, stage, attempts, status) VALUES (?, ?, 0, 'pending')")
				.run(id, stage);
			return;
		}
		if (task.stage !== stage) fail("task stage does not match its existing record");
	}

	get(id: string): TaskRecord | undefined {
		this.requireOpen();
		const row = this.state
			.prepare("SELECT id, stage, attempts, status, result, error FROM tasks WHERE id = ?")
			.get(id);
		return row === undefined ? undefined : rowToTask(row);
	}

	list(): TaskRecord[] {
		this.requireOpen();
		return this.state
			.prepare("SELECT id, stage, attempts, status, result, error FROM tasks ORDER BY id")
			.all()
			.map(rowToTask);
	}

	reserve(id: string, maxCalls: number): boolean {
		this.requireOpen();
		if (!Number.isSafeInteger(maxCalls) || maxCalls < 0) fail("maxCalls must be a non-negative safe integer");
		const result = this.state
			.prepare(`
			UPDATE tasks
			SET status = 'running', attempts = attempts + 1, result = NULL, error = NULL
			WHERE id = ?
				AND status IN ('pending', 'failed')
				AND attempts < 2
				AND (SELECT COALESCE(SUM(attempts), 0) FROM tasks) < ?
		`)
			.run(id, maxCalls);
		return changes(result) === 1;
	}

	complete(id: string, result: unknown): void {
		this.requireOpen();
		let encoded: string | undefined;
		try {
			encoded = JSON.stringify(result);
		} catch {
			fail("task result must be JSON-serializable");
		}
		if (encoded === undefined) fail("task result must be JSON-serializable");
		if (
			changes(
				this.state
					.prepare(
						"UPDATE tasks SET status = 'done', result = ?, error = NULL WHERE id = ? AND status = 'running'",
					)
					.run(encoded, id),
			) !== 1
		) {
			fail("only a running task can be completed");
		}
	}

	/** Persist a deterministic stage (trace, index, wishlist) without charging a model call. */
	completeLocal(id: string, result: unknown): void {
		this.requireOpen();
		let encoded: string | undefined;
		try {
			encoded = JSON.stringify(result);
		} catch {
			fail("task result must be JSON-serializable");
		}
		if (encoded === undefined) fail("task result must be JSON-serializable");
		if (
			changes(
				this.state
					.prepare(
						"UPDATE tasks SET status = 'done', result = ?, error = NULL WHERE id = ? AND status = 'pending' AND attempts = 0",
					)
					.run(encoded, id),
			) !== 1
		) {
			fail("only a pending unused task can be completed locally");
		}
	}

	fail(id: string, reason: string): void {
		this.requireOpen();
		if (
			changes(
				this.state
					.prepare(
						"UPDATE tasks SET status = 'failed', error = ?, result = NULL WHERE id = ? AND status = 'running'",
					)
					.run(reason, id),
			) !== 1
		) {
			fail("only a running task can be failed");
		}
	}

	close(): void {
		if (this.closed) return;
		this.closed = true;
		try {
			this.state.close();
		} finally {
			this.lock.close();
		}
	}

	private requireOpen(): void {
		if (this.closed) fail("store is closed");
	}
}
