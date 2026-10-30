import type { Citation, Finding } from "./schema.ts";
import type { Snapshot, SourceFile } from "./scope.ts";

const COMMENT_OR_BLANK = /^\s*(?:\/\/|#|\/\*|\*|$)/;
const SCOPE_DECL =
	/\b(?:export\s+)?(?:async\s+)?(?:function|class|interface|type|enum|const|let|var|fn|func|def|mod|impl|struct|trait|contract|library|abstract\s+contract)\s+([A-Za-z_][\w]*)/;

/** Nearest enclosing declaration name above the cited line, if the source has one. */
export function enclosingScope(file: SourceFile, startLine: number): string | null {
	const lines = file.content.split("\n");
	for (let i = Math.min(startLine, lines.length) - 1; i >= 0; i--) {
		const match = SCOPE_DECL.exec(lines[i] ?? "");
		if (match) return match[1];
	}
	return null;
}

export function citedLinesAreCode(file: SourceFile, startLine: number, endLine: number): boolean {
	const lines = file.content.split("\n").slice(startLine - 1, endLine);
	return lines.some((line) => line.length > 0 && !COMMENT_OR_BLANK.test(line));
}

export function mechanicalCitationCheck(snapshot: Snapshot, citations: Citation[]): void {
	for (const cite of citations) {
		const file = snapshot.files.find((item) => item.path === cite.path);
		if (!file) throw new Error("Evidence path is not in the snapshot");
		if (!citedLinesAreCode(file, cite.startLine, cite.endLine)) {
			throw new Error("Evidence cites only blank or comment lines");
		}
	}
}

const VACUOUS =
	/\b(?:theoretically|potentially|could theoretically|might be possible)\b|learn field names|cause an error(?:\s|$)/i;

/** Plain-code junk filter: tautologies and "potential" claims are not findings. */
export function vacuousFinding(finding: Finding): string | null {
	const attacker = finding.attacker.trim().toLowerCase();
	const intent = finding.intentBroken.trim().toLowerCase();
	const impact = finding.impact.trim().toLowerCase();
	const root = finding.rootCause.trim().toLowerCase();
	if (VACUOUS.test(impact) || VACUOUS.test(root)) return "vacuous-potential";
	if (root === impact || root === intent) return "vacuous-repeated-field";
	const can = /can ([a-z0-9][a-z0-9 -]{2,40})/.exec(attacker);
	if (can && impact.includes(`can ${can[1]}`) && impact.replace(`can ${can[1]}`, "").trim().length < 8) {
		return "vacuous-tautology";
	}
	if (intent.length < 8 || impact.length < 12 || finding.reproduction.length < 2) return "vacuous-thin-claim";
	return null;
}

function balanced(source: string): boolean {
	const pairs: Record<string, string> = { "(": ")", "[": "]", "{": "}" };
	const stack: string[] = [];
	let inString: string | null = null;
	for (let i = 0; i < source.length; i++) {
		const char = source[i];
		if (inString) {
			if (char === "\\" ) {
				i++;
				continue;
			}
			if (char === inString) inString = null;
			continue;
		}
		if (char === '"' || char === "'" || char === "`") {
			inString = char;
			continue;
		}
		if (pairs[char]) stack.push(pairs[char]);
		else if (char === ")" || char === "]" || char === "}") {
			if (stack.pop() !== char) return false;
		}
	}
	return stack.length === 0;
}

export function proposalLooksLikeCode(value: string): boolean {
	const trimmed = value.trim();
	if (trimmed.length < 12) return false;
	if (/exec\(\)\s*executes|therefore critical/i.test(trimmed)) return false;
	return /(?:diff --git|@@ |function |contract |def |fn |class |assert|expect\(|=>|\{)/.test(trimmed) && balanced(trimmed);
}

export function mechanicalFixCheck(patch: string, test: string): void {
	if (!proposalLooksLikeCode(patch)) throw new Error("Fix patch does not parse as code or a diff");
	if (!proposalLooksLikeCode(test)) throw new Error("Fix test does not parse as a local unit test");
}

export function huntLooksCrashed(outputTokens: number, findingCount: number, spawned: boolean): boolean {
	return findingCount === 0 && !spawned && outputTokens < 4;
}
