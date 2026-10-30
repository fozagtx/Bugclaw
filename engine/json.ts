/** Extract a single JSON object from a model body, including fenced replies. */
export function extractJsonObject(text: string): unknown {
	const trimmed = text.trim();
	if (!trimmed) throw new Error("Empty model body");
	const fenced = /^```(?:json)?\s*\n?([\s\S]*?)\n?```$/i.exec(trimmed);
	const candidate = (fenced ? fenced[1] : trimmed).trim();
	const start = candidate.indexOf("{");
	const end = candidate.lastIndexOf("}");
	if (start === -1 || end < start) throw new Error("Model body is not a JSON object");
	return JSON.parse(candidate.slice(start, end + 1));
}

/** Cloudflare: HTTP 200 bodies can still be provider errors, not completed work. */
export function isProviderErrorPayload(value: unknown): boolean {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const keys = Object.keys(value);
	return keys.includes("error") && !keys.some((key) => ["summary", "findings", "verdict", "coverage", "architecture", "sharperLenses", "patch"].includes(key));
}
