import type { Finding, Recon } from "./schema.ts";
import type { Snapshot, SourceFile } from "./scope.ts";

export interface SourceSlice {
	files: SourceFile[];
	included: string[];
	omitted: string[];
	source: string;
}

export function formatSourceFiles(files: SourceFile[]): string {
	return files
		.map((file) => {
			const body = file.content
				.split("\n")
				.map((line, i) => `${i + 1}: ${line}`)
				.join("\n");
			return `// FILE: ${file.path}\n// SHA256: ${file.sha256}\n${body}`;
		})
		.join("\n\n");
}

function mentionsPath(text: string, file: SourceFile): boolean {
	const haystack = text.toLowerCase();
	const path = file.path.toLowerCase();
	const base = path.includes("/") ? path.slice(path.lastIndexOf("/") + 1) : path;
	return haystack.includes(path) || (base.length > 3 && haystack.includes(base));
}

function lensScore(file: SourceFile, lens: string): number {
	const words = lens
		.toLowerCase()
		.split(/[^a-z0-9]+/)
		.filter((word) => word.length >= 5)
		.slice(0, 16);
	if (!words.length) return 0;
	const haystack = `${file.path}\n${file.content}`.toLowerCase();
	return words.reduce((score, word) => score + (haystack.includes(word) ? 1 : 0), 0);
}

function formattedSize(file: SourceFile): number {
	return formatSourceFiles([file]).length;
}

/** Send only the files this stage needs. Other snapshot files are omitted, not stuffed into context. */
export function sliceSource(
	snapshot: Snapshot,
	options: {
		prefer?: string[];
		lens?: string;
		recon?: Recon | null;
		finding?: Finding | null;
		maxChars: number;
	},
): SourceSlice {
	const budget = Math.max(1, options.maxChars);
	const byPath = new Map(snapshot.files.map((file) => [file.path, file]));
	const preferred = new Set<string>();
	for (const path of options.prefer ?? []) if (byPath.has(path)) preferred.add(path);
	for (const cite of options.finding?.evidence ?? []) if (byPath.has(cite.path)) preferred.add(cite.path);
	if (options.recon) {
		const notes = [
			options.recon.architecture,
			options.recon.summary,
			...options.recon.entryPoints,
			...options.recon.trustBoundaries,
			...options.recon.missingContext,
		].join("\n");
		for (const file of snapshot.files) if (mentionsPath(notes, file)) preferred.add(file.path);
	}
	const ranked = snapshot.files
		.filter((file) => !preferred.has(file.path))
		.map((file) => ({ file, score: options.lens ? lensScore(file, options.lens) : 0 }))
		.sort(
			(left, right) =>
				right.score - left.score || formattedSize(left.file) - formattedSize(right.file) || left.file.path.localeCompare(right.file.path),
		);
	const chosen: SourceFile[] = [];
	let used = 0;
	const take = (file: SourceFile, force: boolean): boolean => {
		const size = formattedSize(file);
		if (used + size > budget && !(force && !chosen.length)) return false;
		chosen.push(file);
		used += size + (chosen.length > 1 ? 2 : 0);
		return true;
	};
	for (const path of [...preferred].sort()) {
		const file = byPath.get(path);
		if (file) take(file, true);
	}
	for (const row of ranked) take(row.file, false);
	if (!chosen.length) {
		const smallest = [...snapshot.files].sort(
			(left, right) => formattedSize(left) - formattedSize(right) || left.path.localeCompare(right.path),
		)[0];
		if (smallest) chosen.push(smallest);
	}
	const included = chosen.map((file) => file.path);
	const omitted = snapshot.files.map((file) => file.path).filter((path) => !included.includes(path));
	return { files: chosen, included, omitted, source: formatSourceFiles(chosen) };
}

export function sliceBudget(maxInputChars: number, contextWindow?: number): number {
	const fromLimit = Math.floor(maxInputChars / 2);
	if (!contextWindow) return fromLimit;
	return Math.min(fromLimit, Math.max(1, Math.floor(contextWindow * 0.25 * 4) - 8_000));
}
