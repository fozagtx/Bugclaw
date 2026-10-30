import assert from "node:assert/strict";
import { chmod, link, lstat, mkdir, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { RunStore } from "./store.ts";

const temporaryDirectories: string[] = [];

after(async () => {
	await Promise.all(
		temporaryDirectories.map((temporaryDirectory) => rm(temporaryDirectory, { recursive: true, force: true })),
	);
});

async function directory(): Promise<string> {
	const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "bugclaw-store-"));
	temporaryDirectories.push(temporaryDirectory);
	return temporaryDirectory;
}

test("persists task records and permits a failed task to resume", async () => {
	const stateDirectory = path.join(await directory(), "state");
	const first = new RunStore(stateDirectory, "source-config-prompt-v1");
	first.ensure("recon", "reconnaissance");
	assert.equal(first.reserve("recon", 10), true);
	first.fail("recon", "Model call failed");
	first.close();

	const resumed = new RunStore(stateDirectory, "source-config-prompt-v1");
	assert.deepEqual(resumed.get("recon"), {
		id: "recon",
		stage: "reconnaissance",
		attempts: 1,
		status: "failed",
		result: null,
		error: "Model call failed",
	});
	assert.equal(resumed.reserve("recon", 10), true);
	resumed.complete("recon", { finding: "validated" });
	assert.deepEqual(resumed.list(), [
		{
			id: "recon",
			stage: "reconnaissance",
			attempts: 2,
			status: "done",
			result: { finding: "validated" },
			error: null,
		},
	]);
	resumed.close();
});

test("enforces global call caps and never refunds task reservations", async () => {
	const store = new RunStore(path.join(await directory(), "state"), "identity");
	store.ensure("one", "scan");
	store.ensure("two", "scan");
	assert.equal(store.reserve("one", 1), true);
	store.fail("one", "Timed out");
	assert.equal(store.reserve("two", 1), false);
	assert.equal(store.reserve("one", 5), true);
	store.fail("one", "Timed out again");
	assert.equal(store.reserve("one", 5), false);
	store.close();
});

test("holds an exclusive lock and releases it after constructor failure", async () => {
	const stateDirectory = path.join(await directory(), "state");
	const store = new RunStore(stateDirectory, "identity-a");
	assert.throws(() => new RunStore(stateDirectory, "identity-a"), /database is locked|locked/i);
	store.close();
	assert.throws(() => new RunStore(stateDirectory, "identity-b"), /identity does not match/i);
	const reopened = new RunStore(stateDirectory, "identity-a");
	reopened.close();
});

test("marks interrupted running tasks as failed without refunding the call", async () => {
	const stateDirectory = path.join(await directory(), "state");
	const first = new RunStore(stateDirectory, "identity");
	first.ensure("validate", "validation");
	assert.equal(first.reserve("validate", 10), true);
	first.close();

	const resumed = new RunStore(stateDirectory, "identity");
	assert.deepEqual(resumed.get("validate"), {
		id: "validate",
		stage: "validation",
		attempts: 1,
		status: "failed",
		result: null,
		error: "Interrupted; reserved call remains charged",
	});
	resumed.close();
});

test("writes completion and failure only for running tasks", async () => {
	const store = new RunStore(path.join(await directory(), "state"), "identity");
	store.ensure("task", "scan");
	assert.throws(() => store.complete("task", { invalid: true }), /only a running task/i);
	assert.throws(() => store.fail("task", "invalid"), /only a running task/i);
	assert.equal(store.get("task")?.status, "pending");
	assert.equal(store.reserve("task", 10), true);
	store.complete("task", { okay: true });
	assert.throws(() => store.fail("task", "invalid"), /only a running task/i);
	assert.deepEqual(store.get("task")?.result, { okay: true });
	store.close();
});

test("creates private files and rejects links or unsafe existing paths", async () => {
	const root = await directory();
	const stateDirectory = path.join(root, "state");
	const store = new RunStore(stateDirectory, "identity");
	assert.equal((await stat(stateDirectory)).mode & 0o777, 0o700);
	assert.equal((await stat(path.join(stateDirectory, "state.sqlite"))).mode & 0o777, 0o600);
	assert.equal((await stat(path.join(stateDirectory, "lock.sqlite"))).mode & 0o777, 0o600);
	store.close();

	const target = path.join(root, "target");
	await mkdir(target, { mode: 0o700 });
	const linkedDirectory = path.join(root, "linked-directory");
	await symlink(target, linkedDirectory);
	assert.throws(() => new RunStore(linkedDirectory, "identity"), /symbolic links/i);
	const linkedAncestor = path.join(root, "linked-ancestor");
	await symlink(target, linkedAncestor);
	assert.throws(
		() => new RunStore(path.join(linkedAncestor, "state"), "identity"),
		/must not contain symbolic links/i,
	);

	const unsafeDirectory = path.join(root, "unsafe");
	await mkdir(unsafeDirectory, { mode: 0o700 });
	await chmod(unsafeDirectory, 0o755);
	assert.throws(() => new RunStore(unsafeDirectory, "identity"), /must not be accessible/i);

	const fileDirectory = path.join(root, "file");
	await mkdir(fileDirectory, { mode: 0o700 });
	await writeFile(path.join(fileDirectory, "state.sqlite"), "not sqlite", { mode: 0o600 });
	await symlink(path.join(fileDirectory, "state.sqlite"), path.join(fileDirectory, "lock.sqlite"));
	assert.equal((await lstat(path.join(fileDirectory, "lock.sqlite"))).isSymbolicLink(), true);
	assert.throws(() => new RunStore(fileDirectory, "identity"), /regular file/i);

	const hardlinkedDirectory = path.join(root, "hardlinked");
	const hardlinked = new RunStore(hardlinkedDirectory, "identity");
	hardlinked.close();
	await link(path.join(hardlinkedDirectory, "state.sqlite"), path.join(hardlinkedDirectory, "state-copy.sqlite"));
	assert.throws(() => new RunStore(hardlinkedDirectory, "identity"), /must not be hardlinked/i);

	const sidecarDirectory = path.join(root, "sidecars");
	await mkdir(sidecarDirectory, { mode: 0o700 });
	await writeFile(path.join(sidecarDirectory, "state.sqlite-wal"), "unsafe", { mode: 0o644 });
	await chmod(path.join(sidecarDirectory, "state.sqlite-wal"), 0o644);
	assert.throws(() => new RunStore(sidecarDirectory, "identity"), /sidecar must not be accessible/i);
	await chmod(path.join(sidecarDirectory, "state.sqlite-wal"), 0o600);
	await symlink(path.join(sidecarDirectory, "state.sqlite-wal"), path.join(sidecarDirectory, "state.sqlite-shm"));
	assert.throws(() => new RunStore(sidecarDirectory, "identity"), /sidecar must be a regular file/i);
});
