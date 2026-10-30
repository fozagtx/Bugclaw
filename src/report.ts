import { readdir, readFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { config } from "./config.ts";
import { Store } from "./store.ts";

type Attempt = { step: string; result: unknown; created_at: string };

function parse(value: unknown): any {
	if (typeof value !== "string") return value;
	try { return JSON.parse(value); } catch { return value; }
}

async function optional(file: string) {
	try { return await readFile(file, "utf8"); }
	catch (error) {
		if ((error as { code?: string }).code === "ENOENT") return null;
		throw error;
	}
}

async function filesIn(directory: string, prefix = ""): Promise<string[]> {
	const entries = await readdir(directory, { withFileTypes: true });
	const files: string[] = [];
	for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
		const path = prefix ? `${prefix}/${entry.name}` : entry.name;
		if (entry.isDirectory()) files.push(...await filesIn(join(directory, entry.name), path));
		else if (entry.isFile()) files.push(path);
	}
	return files;
}

function evidenceDirectory(recorded: unknown) {
	if (typeof recorded !== "string" || !recorded) return null;
	const root = resolve(config().dataDir, "scans");
	const directory = resolve(recorded);
	if (!directory.startsWith(`${root}${sep}`)) throw new Error("Evidence path is outside data/scans");
	return directory;
}

async function evidence(directory: string) {
	const names = await filesIn(directory);
	const read = async (name: string) => optional(join(directory, name));
	const poc = names.filter((name) => name.startsWith(".bugclaw/poc/"));
	return {
		directory,
		names,
		poc: await Promise.all(poc.map(async (name) => ({ path: name, content: await read(name) ?? "" }))),
		command: parse(await read("command.json")),
		stdout: await read("stdout.txt"),
		stderr: await read("stderr.txt"),
		result: parse(await read("result.json")),
		meta: parse(await read("meta.json")),
		policy: await read("policy.yaml"),
		replay: await read("replay.sh"),
		fixDiff: await read("fix.diff"),
	};
}

function block(path: string, content: unknown, language = "") {
	return [`### \`${path}\``, "", `\`\`\`${language}`, String(content ?? ""), "```", ""];
}

function value(data: Record<string, any>, key: string) {
	const item = data[key];
	return item === undefined || item === null || item === "" ? "—" : String(item);
}

function evidencePathLabel(directory: string) {
	return directory;
}

function attemptDetails(attempt: Attempt, result: any, meta: any) {
	const modelId = result?.modelId ?? meta?.modelId;
	const tokensValue = result?.tokens ?? meta?.tokens;
	const model = modelId ? `model \`${modelId}\`` : "model not recorded";
	const tokens = tokensValue ? `, ${tokensValue.input ?? "?"} input / ${tokensValue.output ?? "?"} output tokens` : "";
	const timing = meta?.startedAt ? `; started at ${meta.startedAt}, ended at ${meta.endedAt ?? "—"}` : "";
	return `- ${attempt.step}: ${result?.status ?? result?.verdict ?? "—"}; ${model}${tokens}; recorded at ${attempt.created_at}${timing}`;
}

export async function findingReport(store: Store, candidateId: string): Promise<string> {
	const row = store.candidate(candidateId) as any;
	if (!row) throw new Error("candidate not found");
	const data = parse(row.data) as Record<string, any>;
	const scan = store.scan(row.scan_id) as any;
	if (!scan) throw new Error("scan not found");
	const scanReport = parse(scan.report) as Record<string, any> | null;
	const attempts = (store.attempts(candidateId) as any[]).map((attempt) => ({
		...attempt,
		result: parse(attempt.result),
	})) as Attempt[];
	const signoffs = store.signoffs(candidateId) as any[];
	const bundles = new Map<Attempt, Awaited<ReturnType<typeof evidence>>>();
	for (const attempt of attempts) {
		const directory = evidenceDirectory((attempt.result as any)?.evidence);
		if (directory) bundles.set(attempt, await evidence(directory));
	}
	const pocAttempt = [...attempts].reverse().find((attempt) => attempt.step === "poc" && bundles.has(attempt));
	const pocEvidence = pocAttempt ? bundles.get(pocAttempt) : undefined;
	const fixAttempt = [...attempts].reverse().find((attempt) => attempt.step === "fix");
	const fixEvidence = fixAttempt ? bundles.get(fixAttempt) : undefined;
	const citations = Array.isArray(data.evidence) ? data.evidence : [];
	const lines: string[] = [`# ${value(data, "title")}`, "",
		"- Severity: " + value(data, "severity"),
		"- Scan source: " + value(scan, "source"),
		"- Scan id: " + value(scan, "id"),
		"- Candidate id: " + value(row, "id"),
		"- Snapshot hash: " + value(scan, "snapshot_hash"),
	];
	if (scanReport?.commit) lines.push(`- Resolved commit: ${scanReport.commit}`);
	if (citations.length) lines.push(`- Cited locations: ${citations.map((item: any) => `${item.path}:${item.startLine}-${item.endLine}`).join(", ")}`);
	else lines.push("- Cited locations: —");
	lines.push("", "## What's wrong", "",
		`- Root cause: ${value(data, "rootCause")}`,
		`- Attacker: ${value(data, "attacker")}`,
		`- Trust boundary: ${value(data, "trustBoundary")}`,
		`- Intent broken: ${value(data, "intentBroken")}`,
		`- Impact: ${value(data, "impact")}`,
		`- Attack class: ${value(data, "attackClass")}`,
		"", "## Cited source", "");
	if (citations.length) {
		for (const item of citations) lines.push(...block(`${item.path}:${item.startLine}-${item.endLine}`, item.quote));
	} else lines.push("No cited source is recorded.", "");
	lines.push("## Proof of concept", "");
	if (!pocEvidence) lines.push("No PoC has been run.", "");
	else {
		for (const file of pocEvidence.poc) lines.push(...block(file.path, file.content, "javascript"));
		lines.push(...block("command.json", JSON.stringify(pocEvidence.command, null, 2), "json"));
	}
	lines.push("## Reproduction", "");
	if (!pocEvidence || !pocAttempt) {
		lines.push("No sandbox run is recorded for this finding.", "");
	} else {
		const meta = pocEvidence.meta ?? {};
		lines.push("1. Use the recorded runner image tag:", "", "```sh", `openshell sandbox create --from '${String(meta.imageTag ?? "")}'`, "```", "");
		lines.push("2. Apply the attached policy. Outbound network is denied by the attached policy.", "");
		lines.push("3. Upload the snapshot and PoC overlay to `/sandbox/work/`, then extract both archives.", "");
		lines.push("4. Execute the exact recorded argv:", "", ...block("command.json", JSON.stringify(pocEvidence.command, null, 2), "json"));
		lines.push("5. Compare the stored result:", "",
			...block("stdout.txt", pocEvidence.stdout),
			...block("stderr.txt", pocEvidence.stderr),
			`- Exit code: ${String(pocEvidence.result?.exitCode ?? "—")}`,
			`- timedOut: ${String(pocEvidence.result?.timedOut ?? "—")}`,
			`- Mechanical classification: ${String(pocEvidence.result?.classification ?? "—")}`,
			"");
	}
	lines.push("## Evidence", "");
	if (!pocEvidence && !fixEvidence) {
		lines.push("No evidence directory is recorded.", "- Files: none", "");
	} else {
		const allEvidence = [...new Set([pocEvidence, fixEvidence].filter(Boolean).flatMap((item: any) => item.names))].sort();
		const directory = pocEvidence?.directory ?? fixEvidence?.directory;
		lines.push(`- Evidence directory: ${evidencePathLabel(directory!)}`, `- Files: ${allEvidence.join(", ") || "none"}`, "", "Replay:", "", "```sh", "sh replay.sh", "```", "", "The replay script creates a fresh sandbox, uploads the recorded snapshot and overlay, extracts them, executes the recorded argv, captures output, and deletes the sandbox.", "");
		if (pocEvidence?.policy) lines.push(...block("policy.yaml", pocEvidence.policy, "yaml"));
		else if (fixEvidence?.policy) lines.push(...block("policy.yaml", fixEvidence.policy, "yaml"));
	}
	lines.push("## Verdicts", "");
	const validator = data.validation ?? data.validator?.verdict ?? data.validator?.status ?? "not recorded";
	lines.push(`- Validator outcome: ${validator}`);
	const judgeAttempts = attempts.filter((attempt) => attempt.step === "judge");
	if (judgeAttempts.length) {
		for (const attempt of judgeAttempts) {
			const result = attempt.result as any;
			lines.push(`- Judge verdict: ${result.verdict ?? result.status ?? "—"} — ${result.reason ?? "—"}`);
		}
	} else lines.push("- Judge verdict: not recorded");
	if (attempts.length) lines.push(...attempts.map((attempt) => attemptDetails(attempt, attempt.result, bundles.get(attempt)?.meta)));
	else lines.push("- No validator, judge, or sandbox attempts are recorded.");
	if (signoffs.length) lines.push(`- Human signoff: ${signoffs.map((signoff: any) => `${signoff.decision} (${signoff.at})${signoff.note ? ` — ${signoff.note}` : ""}`).join("; ")}`);
	else lines.push("- Human signoff: none recorded.");
	if (!signoffs.some((signoff: any) => signoff.decision === "confirmed")) lines.push("This is a proven claim awaiting human confirmation. No human confirmation is recorded; model and sandbox outcomes are not human confirmation.");
	lines.push("", "## Suggested fix", "");
	if (fixAttempt) {
		const result = fixAttempt.result as any;
		lines.push(`- Summary: ${result.summary ?? "—"}`);
		if (fixEvidence?.fixDiff !== null && fixEvidence?.fixDiff !== undefined) lines.push(...block("fix.diff", fixEvidence.fixDiff, "diff"));
		else lines.push("- No fix.diff is available in the evidence path recorded for this attempt.");
		const fixResult = fixEvidence?.result?.classification ?? result.status;
		lines.push(`- Same PoC passed afterward: ${fixResult === "safe" || result.status === "fix-verified" ? "yes" : "no"}`, "");
	} else lines.push("Bugclaw does not fix the code and this report is the handoff for your own fixing agent.", "");
	const locations = citations.length ? citations.map((item: any) => `${item.path}:${item.startLine}-${item.endLine}`).join(", ") : "the cited source lines are not recorded";
	lines.push("## Handoff", "",
		`- Change: review ${locations}.`,
		`- Invariant: ${value(data, "intentBroken")}.`,
		`- Re-run: use the exact argv in \`command.json\` inside a fresh network-denied sandbox; \`sh replay.sh\` reproduces the recorded run, then rerun the same command against the patched snapshot to confirm the fix.`,
		"");
	return lines.join("\n");
}
