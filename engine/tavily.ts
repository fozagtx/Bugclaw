/**
 * Tavily web search client (https://tavily.com) — live web evidence for hunt cells.
 *
 * Calls happen only in the orchestrating host process at scan time. Reproduction
 * sandboxes stay fully offline: no Tavily code or key ever enters a sandbox, and
 * queries are built from the hunt lens only, never from source code content, so
 * the operator's source is never transmitted to the search API.
 *
 * Like everything else in this harness, web evidence is untrusted reference
 * data: it can point the hunter at bug classes worth checking, but it is never
 * evidence that any specific code is vulnerable.
 */

export const TAVILY_ENDPOINT = "https://api.tavily.com/search";
const SNIPPET_CHARS = 400;
const TITLE_CHARS = 200;
const DEFAULT_MAX_RESULTS = 5;
const DEFAULT_TIMEOUT_MS = 15_000;

export interface WebEvidenceLink {
	title: string;
	url: string;
	snippet: string;
	score: number;
}

export interface WebEvidenceResult {
	query: string;
	links: WebEvidenceLink[];
}

export interface TavilySearchOptions {
	apiKey: string;
	fetchFn?: typeof fetch;
	maxResults?: number;
	timeoutMs?: number;
	endpoint?: string;
}

export interface TavilyRequestBody {
	query: string;
	max_results: number;
	search_depth: "basic";
	include_answer: false;
}

function truncate(text: unknown, limit: number): string {
	return typeof text === "string" ? text.trim().slice(0, limit) : "";
}

/** Build a search query for a hunt lens. Technique-level terms only; never source content. */
export function lensEvidenceQuery(lens: string): string {
	return `common vulnerabilities and exploitation techniques: ${lens}`;
}

export async function tavilySearch(query: string, options: TavilySearchOptions): Promise<WebEvidenceResult> {
	if (typeof query !== "string" || query.trim().length === 0) throw new Error("tavily: query must be a non-empty string");
	if (!options.apiKey) throw new Error("tavily: API key is required");
	const doFetch = options.fetchFn ?? fetch;
	const maxResults = options.maxResults ?? DEFAULT_MAX_RESULTS;
	const endpoint = options.endpoint ?? TAVILY_ENDPOINT;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const body: TavilyRequestBody = {
		query: query.trim(),
		max_results: maxResults,
		search_depth: "basic",
		include_answer: false,
	};
	const response = await doFetch(endpoint, {
		method: "POST",
		headers: {
			authorization: `Bearer ${options.apiKey}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body),
		signal: AbortSignal.timeout(timeoutMs),
	});
	if (!response.ok) {
		throw new Error(`tavily: search request failed with HTTP ${response.status}`);
	}
	const parsed = (await response.json()) as { results?: unknown };
	const rows = Array.isArray(parsed.results) ? parsed.results : [];
	const links: WebEvidenceLink[] = [];
	for (const row of rows) {
		if (typeof row !== "object" || row === null) continue;
		const record = row as { title?: unknown; url?: unknown; content?: unknown; score?: unknown };
		const url = truncate(record.url, TITLE_CHARS);
		const title = truncate(record.title, TITLE_CHARS) || url;
		const snippet = truncate(record.content, SNIPPET_CHARS);
		if (!url || !snippet) continue;
		const score = typeof record.score === "number" && Number.isFinite(record.score) ? record.score : 0;
		links.push({ title, url, snippet, score });
		if (links.length >= maxResults) break;
	}
	return { query: body.query, links };
}
