import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

export function evidencePath(root: string, relative: string) {
	const base = resolve(root, "scans");
	const target = resolve(base, relative);
	if (!target.startsWith(`${base}${sep}`)) throw new Error("Evidence path is outside data/scans");
	return target;
}

export async function writeEvidence(input: {
	dataDir: string; scanId: string; candidateId: string; step: string; number: number;
	files: Array<{path:string;content:string}>; argv: string[]; run: {stdout:string;stderr:string;exitCode:number;timedOut:boolean};
	meta: Record<string, unknown>; fixDiff?: string;
}) {
	const relative = `${input.scanId}/evidence/${encodeURIComponent(input.candidateId)}/${input.step}-${input.number}`;
	const directory = evidencePath(input.dataDir, relative);
	await mkdir(directory, { recursive: true, mode: 0o700 });
	const policy = await readFile(resolve("sandbox/policy.yaml"), "utf8");
	for (const file of input.files) {
		const full = resolve(directory, file.path);
		if (!full.startsWith(`${directory}${sep}`)) throw new Error("Unsafe evidence file path");
		await mkdir(resolve(full, ".."), { recursive: true });
		await writeFile(full, file.content, { mode: 0o600 });
	}
	await Promise.all([
		writeFile(resolve(directory, "command.json"), JSON.stringify(input.argv, null, 2), { mode: 0o600 }),
		writeFile(resolve(directory, "stdout.txt"), input.run.stdout, { mode: 0o600 }),
		writeFile(resolve(directory, "stderr.txt"), input.run.stderr, { mode: 0o600 }),
		writeFile(resolve(directory, "result.json"), JSON.stringify({ exitCode: input.run.exitCode, timedOut: input.run.timedOut, classification: input.meta.classification }, null, 2), { mode: 0o600 }),
		writeFile(resolve(directory, "meta.json"), JSON.stringify(input.meta, null, 2), { mode: 0o600 }),
		writeFile(resolve(directory, "policy.yaml"), policy, { mode: 0o600 }),
		input.fixDiff === undefined ? Promise.resolve() : writeFile(resolve(directory, "fix.diff"), input.fixDiff, { mode: 0o600 }),
	]);
	await writeFile(resolve(directory, "replay.sh"), `#!/bin/sh\nset -eu\nname="bugclaw-replay-$$"\nstep_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nscan_dir=$(CDPATH= cd -- "$step_dir/../../.." && pwd)\ntrap 'openshell sandbox delete "$name" --force >/dev/null 2>&1 || true' EXIT\nopenshell sandbox create --name "$name" --from '${String(input.meta.imageTag ?? "").replaceAll("'", "")}' --policy "$step_dir/policy.yaml"\nopenshell sandbox upload "$name" "$scan_dir/snapshot" /sandbox/work\nopenshell sandbox upload "$name" "$step_dir" /sandbox/work\nopenshell sandbox exec -n "$name" --no-login-shell -- sh -c 'cd /sandbox/work && exec "$@"' bugclaw ${input.argv.map((arg) => `'${arg.replaceAll("'", "'\\''")}'`).join(" ")} >"$step_dir/replay.stdout.txt" 2>"$step_dir/replay.stderr.txt"\n`, { mode: 0o700 });
	return directory;
}
