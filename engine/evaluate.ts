import type { HarnessReport } from "./runner.ts";
import { object, text } from "./schema.ts";

/** Human review labels for an offline benchmark evaluation. */
export interface EvaluationLabels {
	reviewer: string;
	groundTruth: { id: string }[];
	matches: { truthId: string; candidateId: string; verdict: "exact" | "partial"; reason: string }[];
	classifications: { candidateId: string; verdict: "true-positive" | "false-positive" | "unknown"; reason: string }[];
}

export interface Evaluation {
	reviewer: string;
	knownTruth: number;
	exact: number;
	partial: number;
	missed: number;
	truePositives: number;
	falsePositives: number;
	unknown: number;
	weightedRecall: number | null;
	precision: number | null;
	warning: string;
}

const WARNING =
	"Benchmark recall measures only this human-reviewed ground-truth set; it is not real-world recall or a security guarantee.";
const MAX_LABEL_ROWS = 10_000;

function rows(value: unknown, name: string): unknown[] {
	if (!Array.isArray(value) || value.length > MAX_LABEL_ROWS) throw new Error(`Invalid ${name} list`);
	return value;
}

function reportCandidateIds(report: HarnessReport): Set<string> {
	const candidates = (report as { candidates?: unknown } | null)?.candidates;
	if (!Array.isArray(candidates)) throw new Error("Invalid report candidates list");

	const ids = new Set<string>();
	for (const candidate of candidates) {
		if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
			throw new Error("Invalid report candidate");
		}
		const id = (candidate as { id?: unknown }).id;
		if (typeof id !== "string" || !id.trim() || id.length > 8000) {
			throw new Error("Invalid report candidate ID");
		}
		if (ids.has(id)) throw new Error(`Duplicate report candidate ID: ${id}`);
		ids.add(id);
	}
	return ids;
}

function exactOrPartial(value: unknown): "exact" | "partial" {
	if (value !== "exact" && value !== "partial") throw new Error("Invalid match verdict");
	return value;
}

function classificationVerdict(value: unknown): "true-positive" | "false-positive" | "unknown" {
	if (value !== "true-positive" && value !== "false-positive" && value !== "unknown") {
		throw new Error("Invalid classification verdict");
	}
	return value;
}

/**
 * Scores a fixed candidate queue against labels supplied by a human reviewer.
 * This intentionally does not call a model: benchmark verdicts must be auditable.
 */
export function evaluate(report: HarnessReport, labels: unknown): Evaluation {
	const candidateIds = reportCandidateIds(report);
	const input = object(labels, ["reviewer", "groundTruth", "matches", "classifications"]);
	const groundTruth = rows(input.groundTruth, "groundTruth").map((value) => {
		const row = object(value, ["id"]);
		return { id: text(row.id) };
	});
	const matches = rows(input.matches, "matches").map((value) => {
		const row = object(value, ["truthId", "candidateId", "verdict", "reason"]);
		return {
			truthId: text(row.truthId),
			candidateId: text(row.candidateId),
			verdict: exactOrPartial(row.verdict),
			reason: text(row.reason),
		};
	});
	const classifications = rows(input.classifications, "classifications").map((value) => {
		const row = object(value, ["candidateId", "verdict", "reason"]);
		return {
			candidateId: text(row.candidateId),
			verdict: classificationVerdict(row.verdict),
			reason: text(row.reason),
		};
	});

	const truthIds = new Set<string>();
	for (const truth of groundTruth) {
		if (truthIds.has(truth.id)) throw new Error(`Duplicate ground-truth ID: ${truth.id}`);
		truthIds.add(truth.id);
	}

	const classificationsByCandidate = new Map<string, EvaluationLabels["classifications"][number]>();
	for (const classification of classifications) {
		if (!candidateIds.has(classification.candidateId))
			throw new Error(`Unknown candidate ID: ${classification.candidateId}`);
		if (classificationsByCandidate.has(classification.candidateId)) {
			throw new Error(`Duplicate classification candidate ID: ${classification.candidateId}`);
		}
		classificationsByCandidate.set(classification.candidateId, classification);
	}
	if (classificationsByCandidate.size !== candidateIds.size)
		throw new Error("Classifications must cover every report candidate");

	const matchedTruthIds = new Set<string>();
	const matchedCandidateIds = new Set<string>();
	let exact = 0;
	let partial = 0;
	for (const match of matches) {
		if (!truthIds.has(match.truthId)) throw new Error(`Unknown ground-truth ID: ${match.truthId}`);
		if (!candidateIds.has(match.candidateId)) throw new Error(`Unknown candidate ID: ${match.candidateId}`);
		if (matchedTruthIds.has(match.truthId)) throw new Error(`Duplicate match ground-truth ID: ${match.truthId}`);
		if (matchedCandidateIds.has(match.candidateId))
			throw new Error(`Duplicate match candidate ID: ${match.candidateId}`);
		if (classificationsByCandidate.get(match.candidateId)?.verdict !== "true-positive") {
			throw new Error(`Matched candidate must be classified true-positive: ${match.candidateId}`);
		}
		matchedTruthIds.add(match.truthId);
		matchedCandidateIds.add(match.candidateId);
		if (match.verdict === "exact") exact++;
		else partial++;
	}

	let truePositives = 0;
	let falsePositives = 0;
	let unknown = 0;
	for (const classification of classificationsByCandidate.values()) {
		if (classification.verdict === "true-positive") truePositives++;
		else if (classification.verdict === "false-positive") falsePositives++;
		else unknown++;
	}
	const knownTruth = groundTruth.length;
	return {
		reviewer: text(input.reviewer),
		knownTruth,
		exact,
		partial,
		missed: knownTruth - matches.length,
		truePositives,
		falsePositives,
		unknown,
		weightedRecall: knownTruth ? (exact + 0.5 * partial) / knownTruth : null,
		precision: truePositives + falsePositives ? truePositives / (truePositives + falsePositives) : null,
		warning: WARNING,
	};
}
