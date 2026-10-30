import { createHash } from "node:crypto";
import { text } from "./schema.ts";
import { HARNESS_TOOL_NAMES, HARNESS_TOOLS, OPTIONAL_TOOL_KEYS } from "./tool-specs.ts";

export { HARNESS_TOOL_NAMES, HARNESS_TOOLS, OPTIONAL_TOOL_KEYS } from "./tool-specs.ts";
export type { HarnessToolName } from "./tool-specs.ts";

export interface DeclaredTool {
	tool: HarnessToolName;
	reason: string;
	seed?: string;
	lens?: string;
	need?: string;
	cell?: string;
	fromPath?: string;
	toPath?: string;
	rewrite?: string;
}

export function toolCatalogText(): string {
	return HARNESS_TOOL_NAMES.map((name) => `- ${name}: ${HARNESS_TOOLS[name]}`).join("\n");
}

export function peelTools(value: unknown): { body: unknown; tools: DeclaredTool[] } {
	if (!value || typeof value !== "object" || Array.isArray(value)) return { body: value, tools: [] };
	const record = value as Record<string, unknown>;
	if (!("tools" in record)) return { body: value, tools: [] };
	const { tools: raw, ...rest } = record;
	return { body: rest, tools: parseDeclaredTools(raw) };
}

export function parseDeclaredTools(value: unknown): DeclaredTool[] {
	if (!Array.isArray(value) || value.length > 8) throw new Error("Invalid tools list");
	return value.map((item) => {
		if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("Invalid tool declaration");
		const record = item as Record<string, unknown>;
		const keys = Object.keys(record);
		if (!keys.includes("tool") || !keys.includes("reason") || keys.some((key) => key !== "tool" && key !== "reason" && !OPTIONAL_TOOL_KEYS.includes(key as (typeof OPTIONAL_TOOL_KEYS)[number]))) {
			throw new Error("Invalid tool declaration");
		}
		const name = text(record.tool);
		if (!HARNESS_TOOL_NAMES.includes(name as HarnessToolName)) throw new Error("Unknown harness tool");
		const declared: DeclaredTool = { tool: name as HarnessToolName, reason: text(record.reason) };
		for (const key of OPTIONAL_TOOL_KEYS) {
			if (record[key] !== undefined) declared[key] = text(record[key]);
		}
		return declared;
	});
}

export function siblingTaskId(seed: string): string {
	return `hunt:sibling:${createHash("sha256").update(seed).digest("hex").slice(0, 12)}:0`;
}

export function wishlistTaskId(need: string): string {
	return `wishlist:${createHash("sha256").update(need).digest("hex").slice(0, 16)}`;
}

export function stageLine(tool: HarnessToolName): string {
	return `STAGE=${tool}`;
}

export function promptStage(prompt: string): HarnessToolName | null {
	const match = /^STAGE=(\S+)/m.exec(prompt);
	if (!match || !HARNESS_TOOL_NAMES.includes(match[1] as HarnessToolName)) return null;
	return match[1] as HarnessToolName;
}

/** Deterministic import/require edges used by vdh.trace. Out-of-snapshot specs become wishlist needs. */
export function traceDependencies(files: { path: string; content: string }[]): {
	edges: { fromPath: string; toPath: string }[];
	missing: string[];
} {
	const indexed = new Map(files.map((file) => [file.path, file]));
	const edges: { fromPath: string; toPath: string }[] = [];
	const missing: string[] = [];
	const seenMissing = new Set<string>();
	for (const file of files) {
		const pattern = /(?:import|from|require)\s*(?:\(\s*)?['"]([^'"]+)['"]/g;
		for (const match of file.content.matchAll(pattern)) {
			const spec = match[1];
			if (!spec || spec.startsWith("node:") || spec.startsWith("http:") || spec.startsWith("https:")) continue;
			if (spec.startsWith(".")) {
				const resolved = resolveRelative(file.path, spec);
				const hit = [...indexed.keys()].find((path) => path === resolved || path.startsWith(`${resolved}.`) || path === `${resolved}.ts` || path === `${resolved}.js`);
				if (hit) edges.push({ fromPath: file.path, toPath: hit });
				else if (!seenMissing.has(spec) && seenMissing.size < 12) {
					seenMissing.add(spec);
					missing.push(`in-snapshot path not listed in scope: ${spec} (from ${file.path})`);
				}
				continue;
			}
			if (!seenMissing.has(spec) && seenMissing.size < 12) {
				seenMissing.add(spec);
				missing.push(`dependency or consumer repo not in this snapshot: ${spec} (from ${file.path})`);
			}
		}
	}
	return { edges, missing };
}

function resolveRelative(fromPath: string, spec: string): string {
	const fromDir = fromPath.includes("/") ? fromPath.slice(0, fromPath.lastIndexOf("/")) : "";
	const parts = [...(fromDir ? fromDir.split("/") : []), ...spec.split("/")];
	const resolved: string[] = [];
	for (const part of parts) {
		if (part === "" || part === ".") continue;
		if (part === "..") resolved.pop();
		else resolved.push(part);
	}
	return resolved.join("/");
}

export function invertedIndexShortlist(
	candidate: { id: string; clusterId: string; finding: { trustBoundary: string; rootCause: string; evidence: { path: string }[] } },
	pool: { id: string; clusterId: string; finding: { trustBoundary: string; rootCause: string; evidence: { path: string }[] } }[],
): string[] {
	const files = new Set(candidate.finding.evidence.map((cite) => cite.path));
	const tokens = rareTokens(candidate.finding.rootCause);
	const scored = pool
		.filter((other) => other.id !== candidate.id)
		.map((other) => {
			let score = 0;
			if (other.clusterId === candidate.clusterId) score += 3;
			if (other.finding.trustBoundary === candidate.finding.trustBoundary) score += 2;
			if (other.finding.evidence.some((cite) => files.has(cite.path))) score += 2;
			score += rareTokens(other.finding.rootCause).filter((token) => tokens.includes(token)).length;
			return { id: other.id, score };
		})
		.filter((row) => row.score >= 2)
		.sort((left, right) => right.score - left.score || left.id.localeCompare(right.id));
	return scored.slice(0, 8).map((row) => row.id);
}

function rareTokens(value: string): string[] {
	return [...new Set(value.toLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length >= 5))].slice(0, 12);
}
