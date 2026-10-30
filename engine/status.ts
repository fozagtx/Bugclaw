import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { HarnessReport } from "./runner.ts";

export interface RunStatus {
	status: HarnessReport["status"] | "missing-report";
	identity: string | null;
	snapshot: string | null;
	promptVersion: string | null;
	verifiedFindings: 0;
	candidates: number;
	funnel: HarnessReport["funnel"] | null;
	coverage: { task: string; status: string; shallow: boolean; error: string | null }[];
	wishlist: number;
	stageModels: HarnessReport["stageModels"];
}

export async function readRunStatus(output: string): Promise<RunStatus> {
	let report: HarnessReport;
	try {
		report = JSON.parse(await readFile(join(output, "report.json"), "utf8")) as HarnessReport;
	} catch {
		return {
			status: "missing-report",
			identity: null,
			snapshot: null,
			promptVersion: null,
			verifiedFindings: 0,
			candidates: 0,
			funnel: null,
			coverage: [],
			wishlist: 0,
			stageModels: [],
		};
	}
	return {
		status: report.status,
		identity: report.identity ?? null,
		snapshot: report.snapshot ?? null,
		promptVersion: report.promptVersion ?? null,
		verifiedFindings: 0,
		candidates: report.candidates?.length ?? 0,
		funnel: report.funnel ?? null,
		coverage: (report.coverage ?? []).map((cell) => ({
			task: cell.task,
			status: cell.status,
			shallow: Boolean(cell.shallow),
			error: cell.error,
		})),
		wishlist: report.wishlist?.length ?? 0,
		stageModels: report.stageModels ?? [],
	};
}
