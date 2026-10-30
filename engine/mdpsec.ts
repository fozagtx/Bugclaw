import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const MDPSEC_ORIGINS = {
	"bug-bounty-hunting-prompts": "https://github.com/mdpsec/bug-bounty-hunting-prompts",
	"should-i-submit": "https://github.com/mdpsec/should-i-submit",
} as const;

export const MDPSEC_PACK_NAMES = Object.keys(MDPSEC_ORIGINS) as MdpsecPackName[];
export type MdpsecPackName = keyof typeof MDPSEC_ORIGINS;

/**
 * Rubrics distilled from mdpsec/bug-bounty-hunting-prompts (phase-05b critical,
 * phase-06 triage, phase-08 verify, phase-10 duplicate check) and
 * mdpsec/should-i-submit (prompt.md). Independently rewritten for a read-only
 * source harness: no browser, accounts, OOB, proxies, or live target requests.
 * The vendored originals under ./mdpsec/ are reference, never executed.
 */
export const SO_WHAT_TEST = `So-What test (mdpsec P06): "What does an attacker ACTUALLY do with this?" The answer must be concrete demonstrated impact from the cited source: data of another principal read or written, value moved or minted, an account or role taken, persistent code execution, or a clean chain to one of those that the evidence actually shows. The author's severity is not authoritative; the demonstrated outcome is. A report that asserts critical but only shows information disclosure plus "could lead to" is not a finding.`;

export const OWNED_TEST_ACCOUNT_TRAP = `Owned-test-account trap (mdpsec P06). Owning both accounts A and B is a test harness, not an attacker capability. Every cross-tenant / IDOR / "access victim's X" claim has TWO independent preconditions and must evidence both: (1) authz broken: A reaches B's object given its identifier; (2) identifier obtainable: an attacker who controls only their own account can learn the victim's identifier through sequential or low-entropy ids, or a leak in a list/search/autocomplete/profile/redirect/error/JS/webhook path that the source shows. Reading the victim id out of the victim account is not a source. A UUIDv4 or other high-entropy opaque token is not enumerable by itself. Proving (1) alone is at most needs-context with the exact unresolved prerequisite named; it is never supported.`;

export const HARDENING_MISS_GATE = `Hardening-miss gate (mdpsec P06). These are not findings until the source shows the downstream compromise they enable: no rate limit / no lockout / OTP never throttles / rate limit keyed on a client header; missing HttpOnly or CSP; verbose errors or stack traces; introspection enabled; version disclosure; CORS without a credentialed read of a real secret; username or account-existence oracles; timing side channels without a named secret. A guessable low-entropy secret PLUS an unthrottled path PLUS a reachable valid target is the bar. The exception is when the unthrottled guess itself extracts value (gift card, voucher, promo, redeemable balance in a low-entropy space); that passes.`;

export const MECHANISM_PORTFOLIO = `Search control (mdpsec P05b). Treat the hunt as a portfolio of mechanism families, not a checklist of CWEs. For every concrete primitive, name the attacker-controlled values, their lifetime, the affected objects, the trust boundary, and every downstream consumer. Chase chains through caches, persistent state, identity changes, async jobs, parsers, callbacks, dynamic dispatch, and privileged operations. When a family stalls, mark it blocked in coverage and move to an underexplored family; reopen only for a materially new mechanism, input path, consumer, or chain. Do not stop after the first plausible story.`;

export const COUNTEREVIDENCE_RULE = `Counterevidence (mdpsec P08). Before any non-rejecting verdict, state the strongest benign or intended explanation, the exact control or alternate path you checked against it, the result, and the one concrete fact that would raise or lower severity. A prior model verdict or a historical example is not counterevidence. A valid attack path starts from stated attacker capability, acquires each prerequisite before first use, invokes the vulnerable behavior, then confirms impact; no unexplained pasted id, token, role, or prepared state may appear.`;

export const LEAD_NOT_REPORT = `Lead-versus-report gate (mdpsec should-i-submit). A candidate is a lead, not a finding, when it carries "provisional", "potential impact if confirmed", "needs validation", an open research section, impact that depends on discovering whether another system trusts the state, exploratory tasks instead of atomic reproduction steps, no concrete unauthorized outcome, or asks the reviewer to find a stronger chain. Do not rescue a lead by inventing a different issue or broadening scope.`;

export const DUPLICATE_STANDARD = `Duplicate standard (mdpsec P10). Compare: underlying defective behavior; affected component and trust boundary; endpoint or function and operation; the authentication or authorization failure; exploit primitive and attacker prerequisites; proven impact; whether one remediation fixes both; material differences that need a separate fix. Same CWE, title, severity, product, or impact language alone is insufficient. A different endpoint is still a duplicate when the same control and the same fix cover both. A similar endpoint is not a duplicate when the backend control, tenant boundary, data flow, exploit path, or remediation differs. Uncertainty is possible-duplicate, never not-duplicate; merge only on likely-duplicate. When merging, carry over any proven fact absent from the canonical that strengthens severity, delivery, prerequisites, or scope; redundant wording, repeated requests, and extra evidence of identical scope are not material.`;

export const PRE_SUBMIT_HARD_FAILURES = `Pre-submit hard failures (mdpsec should-i-submit), each caps the candidate regardless of how good the rest looks: out of scope; fully intended behavior; missing attacker delivery; theoretical or below-floor impact; still a lead. Submission floor is medium. Live reproduction was NOT performed by this harness, so the honest pre-submit answer for any surviving candidate is NOT YET, never YES.`;

export type PreSubmitAnswer = "NO" | "NOT YET" | "CANNOT DECIDE SAFELY";

export interface PreSubmitGate {
	answer: PreSubmitAnswer;
	why: string;
	next: string;
	doNotRun: string;
}

/**
 * Deterministic pre-submit answer per candidate, derived only from recorded
 * harness verdicts. YES is unreachable: the harness never reproduces.
 */
export function preSubmitGate(candidate: {
	status: string;
	validation?: { verdict: string; missingContext?: string[] } | null;
	judgment?: { verdict: string } | null;
}): PreSubmitGate {
	const doNotRun = "Any live, production, or public-chain action; exploit execution; patch application.";
	const validation = candidate.validation?.verdict;
	const judgment = candidate.judgment?.verdict;
	if (validation === "rejected" || judgment === "not-a-risk" || judgment === "wrong-component") {
		return {
			answer: "NO",
			why:
				judgment === "wrong-component"
					? "VVS filed this against the wrong component; it is not a finding for this target."
					: "The independent validator or VVS judgment disproved the candidate or found no bounty-grade impact.",
			next: "Nothing. Archive the candidate with the recorded reason.",
			doNotRun,
		};
	}
	if (validation === "needs-context" || judgment === "latent") {
		const missing = candidate.validation?.missingContext?.[0];
		return {
			answer: "CANNOT DECIDE SAFELY",
			why: missing
				? `One prerequisite is unresolved: ${missing}`
				: "The candidate depends on deployment, dependency, or delivery facts that are not in the snapshot.",
			next: "Resolve that exact prerequisite from source you control before any reproduction; if it is unreachable, archive as disproved.",
			doNotRun,
		};
	}
	if (validation === "supported" || judgment === "exploitable-in-source") {
		return {
			answer: "NOT YET",
			why: "Source-supported hypothesis only. No reproduction was executed, so attacker delivery and impact are unproven.",
			next: "Reproduce on the exact original snapshot in an isolated local environment with a negative control, then re-review as one finished report.",
			doNotRun,
		};
	}
	return {
		answer: "CANNOT DECIDE SAFELY",
		why: `Candidate status is ${candidate.status}; independent validation did not complete.`,
		next: "Finish validation before any human reproduction effort.",
		doNotRun,
	};
}

export interface MdpsecPackVersion {
	name: MdpsecPackName;
	origin: string;
	commit: string;
	clonedAt: string | null;
	root: string;
}

export interface MdpsecInstall {
	root: string;
	packs: MdpsecPackVersion[];
}

export function mdpsecVendorRoot(): string {
	return join(dirname(fileURLToPath(import.meta.url)), "mdpsec");
}

export function loadInstalledMdpsec(): MdpsecInstall {
	const root = mdpsecVendorRoot();
	const packs = MDPSEC_PACK_NAMES.map((name) => {
		const packRoot = join(root, name);
		if (!existsSync(join(packRoot, "ORIGIN")) || !existsSync(join(packRoot, "LICENSE"))) {
			throw new Error(`mdpsec pack ${name} is not installed under ${packRoot}`);
		}
		const originText = readFileSync(join(packRoot, "ORIGIN"), "utf8");
		const origin = /origin=(\S+)/.exec(originText)?.[1] ?? MDPSEC_ORIGINS[name];
		const clonedAt = /cloned=(\S+)/.exec(originText)?.[1] ?? null;
		const commit = originText
			.split("\n")
			.map((line) => line.trim())
			.find((line) => /^[0-9a-f]{40}$/.test(line));
		if (!commit) throw new Error(`mdpsec pack ${name} ORIGIN is missing the cloned commit`);
		return { name, origin, commit, clonedAt, root: packRoot };
	});
	return { root, packs };
}
