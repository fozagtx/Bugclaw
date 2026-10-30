import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createGunzip } from "node:zlib";
import type { Finding } from "./schema.ts";
import type { Snapshot } from "./scope.ts";

/** Web3 Audit Database (https://web3-audits.dicksonwu.xyz/): public smart-contract audit findings used as reference data. */
export const CORPUS_SITE = "https://web3-audits.dicksonwu.xyz/";
export const CORPUS_ORIGIN = "https://github.com/DicksonWu654/web3-audit-corpus";
export const CORPUS_RELEASE = "v1.3.0";
export const CORPUS_FILES = ["findings.jsonl.gz", "taxonomy.yaml", "CHECKSUMS.sha256"] as const;

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const EXCERPT_CHARS = 500;

export interface PriorFinding {
	uid: string;
	reportId: string;
	title: string;
	severity: string;
	status: string;
	leaf: string | null;
	firm: string;
	project: string;
	year: number | null;
	languages: string[];
	url: string | null;
	excerpt: string | null;
	attribution: string | null;
	license: string | null;
}

export interface CorpusQuery {
	text?: string;
	leaves?: string[];
	severities?: string[];
	languages?: string[];
	project?: string;
	limit?: number;
}

export interface CorpusStatus {
	installed: boolean;
	release: string;
	dir: string;
	site: string;
	origin: string;
	files: { name: string; bytes: number }[];
	classes: { id: string; leaves: string[] }[];
	note: string;
}

/** Pashov web3 hunt cell -> taxonomy leaves (or whole groups) whose past findings the cell receives. */
export const LENS_CLASSES: Record<string, string[]> = {
	"math-precision": ["arithmetic", "oracle_price.conversion"],
	"access-control": ["access_control", "upgradeability.initialization", "upgradeability.proxy_upgrade"],
	"economic-security": ["oracle_price.manipulable_price", "oracle_price.stale_invalid_price", "mev", "input_validation.token_semantics"],
	"execution-trace": ["logic_accounting.state_transition", "logic_accounting.integration", "input_validation.serialization", "reentrancy"],
	invariant: ["logic_accounting.balance_shares", "logic_accounting.liquidation_solvency", "bridge.asset_conservation"],
	periphery: ["input_validation.bounds", "input_validation.address_parameter", "input_validation.serialization"],
	"first-principles": ["logic_accounting.state_transition", "signature_replay", "reentrancy", "cryptography.proof_validation"],
	asymmetry: ["logic_accounting.balance_shares", "logic_accounting.reward_fee"],
	boundary: ["input_validation", "dos.revert_griefing", "dos.funds_liveness"],
	"numerical-gap": ["arithmetic.rounding_dust", "arithmetic.precision_scaling", "logic_accounting.balance_shares"],
	"trust-gap": ["mev.front_running", "oracle_price.manipulable_price", "access_control.capability_scope"],
	"flow-gap": ["input_validation.token_semantics", "logic_accounting.integration", "reentrancy.callback", "bridge.message_lifecycle"],
};

/** Source pattern -> lexical terms that past findings about that mechanism use. */
const MECHANISMS: { source: RegExp; terms: string[] }[] = [
	{ source: /ERC4626|convertToShares|previewDeposit|totalAssets\(/, terms: ["first depositor", "inflation", "donation", "share price", "converttoshares"] },
	{ source: /latestRoundData|AggregatorV3|priceFeed/i, terms: ["latestrounddata", "stale price", "chainlink", "sequencer"] },
	{ source: /slot0|\.observe\(|consult\(|twap/i, terms: ["slot0", "twap", "spot price", "manipulat"] },
	{ source: /ecrecover|ECDSA|SignatureChecker|EIP712|permit\(/, terms: ["signature", "replay", "nonce", "eip712", "permit"] },
	{ source: /delegatecall|initializer|UUPS|upgradeTo|_disableInitializers/, terms: ["initializ", "proxy", "storage collision", "upgrade"] },
	{ source: /flashLoan|IERC3156|flashloan/i, terms: ["flash loan", "flashloan"] },
	{ source: /safeTransferFrom|transferFrom\(/, terms: ["fee-on-transfer", "fee on transfer", "rebasing", "return value"] },
	{ source: /liquidat/i, terms: ["liquidation", "bad debt", "health factor"] },
	{ source: /amountOutMin|minAmountOut|slippage|deadline/i, terms: ["slippage", "deadline", "sandwich"] },
	{ source: /lzReceive|ccipReceive|crossChain|wormhole|bridge/i, terms: ["cross-chain", "bridge", "message", "replay"] },
	{ source: /onERC721Received|onERC1155Received|_safeMint|\.call\{value/, terms: ["reentran", "callback"] },
	{ source: /rewardPerToken|accRewardPerShare|rewardRate|earned\(/, terms: ["reward", "accrual", "rewardpertoken"] },
	{ source: /governor|quorum|proposal|getVotes/i, terms: ["governance", "voting power", "proposal", "quorum"] },
	{ source: /invoke_signed|anchor_lang|AccountInfo|Pubkey/, terms: ["pda", "account validation", "signer", "owner check"] },
	{ source: /unchecked\s*\{|SafeCast|uint\d+\(\s*int|int\d+\(\s*uint/, terms: ["overflow", "downcast", "unsafe cast", "truncat"] },
	{ source: /mulDiv|FullMath|\bWAD\b|\bRAY\b|1e18/, terms: ["rounding", "precision", "muldiv"] },
	{ source: /MerkleProof|merkleRoot/i, terms: ["merkle", "proof"] },
	{ source: /\bunstake|\bstake\(|staking/i, terms: ["stake", "unstake", "staking"] },
	{ source: /getAmountOut|IUniswapV|ISwapRouter|\bswap\(/, terms: ["swap", "router", "price impact"] },
];

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
	sol: "Solidity",
	vy: "Vyper",
	rs: "Rust",
	cairo: "Cairo",
	move: "Move",
	clar: "Clarity",
	fc: "FunC",
	func: "FunC",
	tact: "Tact",
	yul: "Yul",
};

const STOPWORDS = new Set(
	"about above after again against allow allows because before being below between could does doing during either every functions function other their there these those through under until using where which while would should within without contract contracts value values token tokens attacker victim users user called calling caller state amount amounts check checks missing".split(
		" ",
	),
);

export function corpusDir(): string {
	return process.env.BUGCLAW_CORPUS_DIR?.trim() || join(homedir(), ".cache", "bugclaw-corpus", CORPUS_RELEASE);
}

export function corpusEnabled(): boolean {
	return process.env.BUGCLAW_CORPUS?.trim().toLowerCase() !== "off";
}

export function corpusInstalled(dir: string): boolean {
	return existsSync(join(dir, "findings.jsonl.gz")) && existsSync(join(dir, "SYNCED"));
}

export function corpusStatus(dir: string): CorpusStatus {
	const installed = corpusInstalled(dir);
	const files = CORPUS_FILES.filter((name) => existsSync(join(dir, name))).map((name) => ({
		name,
		bytes: statSync(join(dir, name)).size,
	}));
	let classes: CorpusStatus["classes"] = [];
	if (existsSync(join(dir, "taxonomy.yaml"))) {
		const taxonomy = JSON.parse(readFileSync(join(dir, "taxonomy.yaml"), "utf8")) as {
			classes: { id: string; leaves: { id: string }[] }[];
		};
		classes = taxonomy.classes.map((entry) => ({ id: entry.id, leaves: entry.leaves.map((leaf) => leaf.id) }));
	}
	return {
		installed,
		release: CORPUS_RELEASE,
		dir,
		site: CORPUS_SITE,
		origin: CORPUS_ORIGIN,
		files,
		classes,
		note: installed
			? "Reference data only: AI-assisted extraction, check the original report before relying on a finding. Quoted text keeps its publisher's rights."
			: "Not installed. Call harness_corpus with action=sync (downloads ~106 MB from the corpus GitHub release, checksum-verified).",
	};
}

function sha256File(file: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const hash = createHash("sha256");
		createReadStream(file)
			.on("data", (chunk) => hash.update(chunk))
			.on("error", reject)
			.on("end", () => resolve(hash.digest("hex")));
	});
}

/** Download the pinned release files and verify each against the release CHECKSUMS.sha256. */
export async function syncCorpus(dir: string, fetchImpl: typeof fetch = fetch): Promise<CorpusStatus> {
	mkdirSync(dir, { recursive: true });
	const base = `${CORPUS_ORIGIN}/releases/download/${CORPUS_RELEASE}/`;
	const sums = await fetchImpl(`${base}CHECKSUMS.sha256`);
	if (!sums.ok) throw new Error(`Corpus sync failed: CHECKSUMS.sha256 HTTP ${sums.status}`);
	const checksumText = await sums.text();
	const expected = new Map(
		checksumText
			.split("\n")
			.map((line) => line.trim().split(/\s+\*?/))
			.filter((parts) => parts.length === 2 && /^[0-9a-f]{64}$/.test(parts[0]!))
			.map((parts) => [parts[1]!, parts[0]!]),
	);
	for (const name of CORPUS_FILES.filter((file) => file !== "CHECKSUMS.sha256")) {
		const digest = expected.get(name);
		if (!digest) throw new Error(`Corpus sync failed: ${name} missing from CHECKSUMS.sha256`);
		const destination = join(dir, name);
		if (existsSync(destination) && (await sha256File(destination)) === digest) continue;
		const response = await fetchImpl(`${base}${name}`);
		if (!response.ok || !response.body) throw new Error(`Corpus sync failed: ${name} HTTP ${response.status}`);
		const temporary = `${destination}.part`;
		writeFileSync(temporary, Buffer.from(await response.arrayBuffer()));
		const actual = await sha256File(temporary);
		if (actual !== digest) {
			rmSync(temporary, { force: true });
			throw new Error(`Corpus sync failed: ${name} checksum mismatch`);
		}
		renameSync(temporary, destination);
	}
	writeFileSync(join(dir, "CHECKSUMS.sha256"), checksumText);
	writeFileSync(join(dir, "SYNCED"), `${CORPUS_RELEASE}\n`);
	return corpusStatus(dir);
}

/** Stream JSON Lines. Splits on \n only: body text contains U+2028, which readline treats as a line break. */
export async function* corpusRows(dir: string): AsyncGenerator<Record<string, unknown>> {
	let rest = "";
	const stream = createReadStream(join(dir, "findings.jsonl.gz")).pipe(createGunzip()).setEncoding("utf8");
	for await (const chunk of stream) {
		rest += chunk as string;
		let index = rest.indexOf("\n");
		while (index >= 0) {
			const line = rest.slice(0, index);
			rest = rest.slice(index + 1);
			if (line.trim()) yield JSON.parse(line) as Record<string, unknown>;
			index = rest.indexOf("\n");
		}
	}
	if (rest.trim()) yield JSON.parse(rest) as Record<string, unknown>;
}

function str(value: unknown): string | null {
	return typeof value === "string" && value.trim() ? value : null;
}

function bodyOf(row: Record<string, unknown>): string | null {
	if (row.body_text_status !== "present" || row.text_withheld) return null;
	return str(row.body_text);
}

export function toPrior(row: Record<string, unknown>): PriorFinding {
	const body = bodyOf(row);
	const excerpt = body ? body.replace(/\s+/g, " ").trim().slice(0, EXCERPT_CHARS) : null;
	return {
		uid: String(row.finding_uid),
		reportId: String(row.report_id ?? ""),
		title: String(row.title ?? "").slice(0, 300),
		severity: String(row.severity ?? "unknown"),
		status: String(row.status ?? "not_stated"),
		leaf: str(row.vuln_leaf),
		firm: String(row.firm ?? row.firm_id ?? ""),
		project: String(row.project ?? ""),
		year: Number.isFinite(Number(row.audit_year)) && row.audit_year !== null ? Number(row.audit_year) : null,
		languages: Array.isArray(row.languages) ? row.languages.map(String) : [],
		url: str(row.original_url),
		excerpt,
		attribution: str(row.text_attribution),
		license: str(row.text_license),
	};
}

function leafMatches(leaf: unknown, classes: string[]): boolean {
	if (typeof leaf !== "string") return false;
	return classes.some((entry) => leaf === entry || leaf.startsWith(`${entry}.`));
}

function languageMatches(row: Record<string, unknown>, languages: string[]): boolean {
	if (!languages.length) return true;
	const rowLanguages = Array.isArray(row.languages) ? row.languages.map(String) : [];
	const known = rowLanguages.filter((language) => language !== "unknown");
	if (!known.length) return true;
	return known.some((language) => languages.some((wanted) => wanted.toLowerCase() === language.toLowerCase()));
}

function haystack(row: Record<string, unknown>): { title: string; body: string } {
	return { title: String(row.title ?? "").toLowerCase(), body: (bodyOf(row) ?? "").toLowerCase() };
}

function termScore(text: { title: string; body: string }, terms: string[]): number {
	let score = 0;
	for (const term of terms) {
		if (text.title.includes(term)) score += 3;
		else if (text.body.includes(term)) score += 1;
	}
	return score;
}

function queryTerms(value: string): string[] {
	const phrases = [...value.matchAll(/"([^"]+)"/g)].map((match) => match[1]!.toLowerCase().trim()).filter(Boolean);
	const words = value
		.replace(/"[^"]+"/g, " ")
		.toLowerCase()
		.split(/[^a-z0-9_]+/)
		.filter((word) => word.length >= 3 && !STOPWORDS.has(word));
	return [...new Set([...phrases, ...words])].slice(0, 24);
}

interface Ranked {
	score: number;
	row: Record<string, unknown>;
}

function better(left: Ranked, right: Ranked): number {
	return (
		right.score - left.score ||
		(SEVERITY_RANK[String(right.row.severity)] ?? 0) - (SEVERITY_RANK[String(left.row.severity)] ?? 0) ||
		Number(right.row.audit_year ?? 0) - Number(left.row.audit_year ?? 0) ||
		String(left.row.finding_uid).localeCompare(String(right.row.finding_uid))
	);
}

function pushTop(list: Ranked[], item: Ranked, keep: number): void {
	list.push(item);
	if (list.length > keep * 4) {
		list.sort(better);
		list.length = keep * 2;
	}
}

function finalize(list: Ranked[], limit: number): PriorFinding[] {
	const seen = new Set<string>();
	const out: PriorFinding[] = [];
	for (const item of list.sort(better)) {
		const report = `report:${String(item.row.report_id ?? "")}`;
		const title = `title:${String(item.row.title ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "")}`;
		if (seen.has(report) || seen.has(title)) continue;
		seen.add(report);
		seen.add(title);
		out.push(toPrior(item.row));
		if (out.length >= limit) break;
	}
	return out;
}

/** Lexical search over the local corpus. Filters are exact; text terms rank (title hits count three times). */
export async function searchCorpus(
	dir: string,
	query: CorpusQuery,
): Promise<{ release: string; matched: number; results: PriorFinding[] }> {
	if (!corpusInstalled(dir)) throw new Error("Corpus not installed: call harness_corpus with action=sync first");
	const limit = Math.min(Math.max(query.limit ?? 20, 1), 100);
	const terms = query.text ? queryTerms(query.text) : [];
	const severities = (query.severities ?? []).map((value) => value.toLowerCase());
	const project = query.project?.toLowerCase();
	const ranked: Ranked[] = [];
	let matched = 0;
	for await (const row of corpusRows(dir)) {
		if (query.leaves?.length && !leafMatches(row.vuln_leaf, query.leaves)) continue;
		if (severities.length && !severities.includes(String(row.severity))) continue;
		if (!languageMatches(row, query.languages ?? [])) continue;
		if (project && !String(row.project ?? "").toLowerCase().includes(project)) continue;
		const score = terms.length ? termScore(haystack(row), terms) : 0;
		if (terms.length && score === 0) continue;
		matched += 1;
		pushTop(ranked, { score, row }, limit);
	}
	return { release: CORPUS_RELEASE, matched, results: finalize(ranked, limit) };
}

/** Languages and mechanism terms detected in the scoped source; used to pick relevant past findings. */
export function sourceMechanisms(snapshot: Snapshot): { languages: string[]; terms: string[] } {
	const languages = new Set<string>();
	const terms = new Set<string>();
	for (const file of snapshot.files) {
		const extension = file.path.slice(file.path.lastIndexOf(".") + 1).toLowerCase();
		const language = LANGUAGE_BY_EXTENSION[extension];
		if (language) languages.add(language);
		for (const mechanism of MECHANISMS) {
			if (mechanism.source.test(file.content)) for (const term of mechanism.terms) terms.add(term);
		}
	}
	return { languages: [...languages].sort(), terms: [...terms] };
}

export function web3LensOfCell(cell: string): string | null {
	const match = /(?:^|:)hunt:web3:([a-z-]+):\d+$/.exec(cell);
	return match && LENS_CLASSES[match[1]!] ? match[1]! : null;
}

/** One pass over the corpus: top medium+ findings with full text per web3 hunt cell, ranked by mechanism terms from the source. */
export async function priorArtForLenses(
	dir: string,
	snapshot: Snapshot,
	perLens = 4,
): Promise<Map<string, PriorFinding[]>> {
	const { languages, terms } = sourceMechanisms(snapshot);
	const ranked = new Map<string, Ranked[]>(Object.keys(LENS_CLASSES).map((lens) => [lens, []]));
	for await (const row of corpusRows(dir)) {
		if ((SEVERITY_RANK[String(row.severity)] ?? 0) < 2 || !bodyOf(row)) continue;
		if (!languageMatches(row, languages)) continue;
		let text: { title: string; body: string } | null = null;
		for (const [lens, classes] of Object.entries(LENS_CLASSES)) {
			if (!leafMatches(row.vuln_leaf, classes)) continue;
			text ??= haystack(row);
			const score = termScore(text, terms);
			if (terms.length && score === 0) continue;
			pushTop(ranked.get(lens)!, { score, row }, perLens);
		}
	}
	return new Map([...ranked].map(([lens, list]) => [lens, finalize(list, perLens)]));
}

function findingTokens(finding: Finding): string[] {
	return queryTerms(`${finding.title} ${finding.rootCause} ${finding.attackClass}`).filter((token) => token.length >= 5);
}

/** Closest past findings to each candidate (IDF-weighted token overlap), for duplicate / known-issue and severity checks. */
export async function similarPriorFindings(
	dir: string,
	candidates: { id: string; finding: Finding }[],
	snapshot: Snapshot,
	perCandidate = 3,
): Promise<Map<string, PriorFinding[]>> {
	const out = new Map<string, PriorFinding[]>();
	if (!candidates.length) return out;
	const { languages } = sourceMechanisms(snapshot);
	const tokensById = new Map(candidates.map((candidate) => [candidate.id, findingTokens(candidate.finding)]));
	const allTokens = [...new Set([...tokensById.values()].flat())];
	const df = new Map(allTokens.map((token) => [token, 0]));
	const pools = new Map(candidates.map((candidate) => [candidate.id, [] as { hits: string[]; row: Record<string, unknown> }[]]));
	let total = 0;
	for await (const row of corpusRows(dir)) {
		if (!bodyOf(row) || !languageMatches(row, languages)) continue;
		total += 1;
		const text = haystack(row);
		const present = allTokens.filter((token) => text.title.includes(token) || text.body.includes(token));
		for (const token of present) df.set(token, df.get(token)! + 1);
		for (const [id, tokens] of tokensById) {
			const hits = present.filter((token) => tokens.includes(token));
			if (hits.length < 2) continue;
			const pool = pools.get(id)!;
			pool.push({ hits, row });
			if (pool.length > 400) {
				pool.sort((left, right) => right.hits.length - left.hits.length);
				pool.length = 200;
			}
		}
	}
	const idf = (token: string) => Math.log(1 + total / (1 + (df.get(token) ?? 0)));
	for (const [id, pool] of pools) {
		const ranked = pool.map(({ hits, row }) => {
			const text = haystack(row);
			const score = hits.reduce((sum, token) => sum + idf(token) * (text.title.includes(token) ? 2 : 1), 0);
			return { score, row };
		});
		out.set(id, finalize(ranked, perCandidate));
	}
	return out;
}

export function compactPrior(prior: PriorFinding[]): unknown[] {
	return prior.map((item) => ({
		uid: item.uid,
		severity: item.severity,
		class: item.leaf,
		title: item.title,
		firm: item.firm,
		project: item.project,
		year: item.year,
		url: item.url,
		excerpt: item.excerpt,
	}));
}
