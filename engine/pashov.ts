import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const PASHOV_ORIGIN = "https://github.com/pashov/skills";

export const PASHOV_SKILL_NAMES = ["x-ray", "solidity-auditor", "fizz"] as const;
export type PashovSkillName = (typeof PASHOV_SKILL_NAMES)[number];

/** Independently authored hunt cells matching pashov/solidity-auditor's twelve agents (v4.1). */
export const SOLIDITY_AUDITOR_LENSES = {
	"math-precision":
		"Pashov math-precision agent. Map WAD/RAY/BPS and token/oracle decimals. Exploit wrong rounding (shares down, debt/fees up), 1-wei truncation, mul-before-div vs div-before-mul, downcasts, and first-depositor share inflation. Proof needs concrete numbers. Attack class: insolvency, rounding extraction. Do not run a fuzzer.",
	"access-control":
		"Pashov access-control agent. Map every role, modifier, and inline check. Exploit the weakest writer of a shared variable, initialize/front-run, privilege escalation, confused-deputy calls, proxy/storage-slot collisions, and NFT-specific approval bypasses (ERC721 permit, EIP-1271 signatures, Gnosis Safe setFallbackHandler). Permissionless value or authority changes are in scope; documented admin power is not a finding by itself. Attack class: missing or bypassable access control.",
	"economic-security":
		"Pashov economic-security agent. Break oracles, tokens, and incentives: fee-on-transfer, rebasing, blacklist, void-return, sandwichable price-dependent ops, hard-coded-zero slippage parameters (amountOutMinimum, deadline, sqrtPriceLimitX96), privileged owner/operator mempool sandwiches of pool metrics, ERC-4626 max* vs actual mint, sentinel addresses, shared-cap starvation. Name who profits, how much, at what cost. Attack class: oracle/slippage manipulation, token-behavior mismatch, donation/inflation.",
	"execution-trace":
		"Pashov execution-trace agent. Follow entry to final state: mismatched claimed vs sent amounts, fee deducted then original amount forwarded, abi.encodePacked vs decode, stale reads after external calls, partial updates, interleaving of request/wait/execute, leftover approvals. For bridges/cross-chain code, trace requestId uniqueness across re-orgs, replay protection, and refund/compensation on rejected deposits or failed fallback. Attack class: value leak, encoding mismatch, TOCTOU across calls, bridge replay/stuck funds.",
	"invariant":
		"Pashov invariant agent. Extract conservation laws, state couplings, and caps; list every writer of each term. Break round-trips, path divergence, commutativity, zero/max/first/last, emergency transitions. Name the invariant, the call sequence that breaks it, and values before/after. Attack class: conservation break, skipped cap, round-trip leak.",
	periphery:
		"Pashov periphery agent. Attack libraries, helpers, encoders, abstract bases first. Unvalidated helper inputs that callers trust (e.g., token address must be a member of the pair, reserve arrays must match the reported token order), corrupt return widths, hidden storage side effects, assembly byte-width bugs, false existence proofs, gas loops that brick callers, provider swap races. Attack class: helper-trust gap, encoding width, gas griefing.",
	"first-principles":
		"Pashov first-principles agent. Do not pattern-match named CWEs. For every state-changing function, list implicit assumptions (freshness, ordering, identity, nonzero denominator, coupled storage, hard-coded protocol constants such as fee caps, gas reserves, and price thresholds that assume a fixed token decimal or chain gas market) and violate them. Report unnamed logic errors with the assumption, the violation, and a trace. Attack class: broken assumption, desynchronized coupling.",
	asymmetry:
		"Pashov asymmetry agent. Diff paired operations (deposit/withdraw, mint/burn, encode/decode, user vs forceAdmin, stake/unstake, vote/unvote). Storage writes that do not mirror; governance or reward power that persists after the underlying stake/position is exited; branch pairs (native vs ERC20, empty vs nonempty) that skip a check the other side has. Attack class: unpaired accounting, branch-asymmetric guard.",
	boundary:
		"Pashov boundary agent. Enumerate every external call, payable, sentinel-address branch, token-address parameter, and bytes decode. Empty code at receiver, void-return tokens, zero/max inputs, failed vs fake-success low-level calls. Attack class: external-call corner, sentinel bypass, token noncompliance.",
	"numerical-gap":
		"Pashov numerical-gap agent. Hunt seams between precision, invariants, and boundaries: invariants that hold in reals but drift under truncation; formulas that go to zero at the edge; caps checked against a differently scaled value; mismatched formulas between a view function and the state-changing function it is paired with; collateral factors or haircuts applied inconsistently across realized/unrealized balance buckets. Do not re-do the standalone math or invariant cells. Attack class: rounding-drifted invariant, edge-precision zero, view-state mismatch.",
	"trust-gap":
		"Pashov trust-gap agent. Hunt seams between access control, economics, and asymmetry: a correctly guarded function whose formula is sandwichable by that role; deposit vs withdraw using different prices; admin setters that redirect in-flight value. Do not re-file a bare missing-modifier. Attack class: privileged economic extract, asymmetric pricing.",
	"flow-gap":
		"Pashov flow-gap agent. Hunt seams between execution trace, periphery, and first principles: a clean internal path that trusts a fee-on-transfer return; a completed flow whose end-state contradicts the protocol purpose; callback re-entry that uses pre-callback state; untrusted hooks that clear/bypass reentrancy guards; external token callbacks (ERC1155/ERC721 safeTransferFrom, vault deposit/withdraw callbacks) that run before the protocol records ownership or rental state. Attack class: cross-lens flow break, purpose-violating end-state, guard bypass.",
} as const;

export const SOLIDITY_AUDITOR_LENS_IDS = Object.keys(SOLIDITY_AUDITOR_LENSES) as (keyof typeof SOLIDITY_AUDITOR_LENSES)[];

export interface PashovSkillVersion {
	name: PashovSkillName;
	version: string;
	skillMd: string;
}

export interface PashovInstall {
	origin: string;
	commit: string;
	clonedAt: string | null;
	root: string;
	skills: PashovSkillVersion[];
}

export function pashovVendorRoot(): string {
	return join(dirname(fileURLToPath(import.meta.url)), "pashov");
}

export function loadInstalledPashov(): PashovInstall {
	const root = pashovVendorRoot();
	if (!existsSync(join(root, "ORIGIN")) || !existsSync(join(root, "LICENSE"))) {
		throw new Error("Pashov skills are not installed under ./pashov/");
	}
	const originText = readFileSync(join(root, "ORIGIN"), "utf8");
	const origin = /origin=(\S+)/.exec(originText)?.[1] ?? PASHOV_ORIGIN;
	const clonedAt = /cloned=(\S+)/.exec(originText)?.[1] ?? null;
	const commit = originText
		.split("\n")
		.map((line) => line.trim())
		.find((line) => /^[0-9a-f]{40}$/.test(line));
	if (!commit) throw new Error("Pashov ORIGIN is missing the cloned commit");
	const skills = PASHOV_SKILL_NAMES.map((name) => {
		const skillMd = join(root, name, "SKILL.md");
		const versionFile = join(root, name, "VERSION");
		if (!existsSync(skillMd) || !existsSync(versionFile)) {
			throw new Error(`Pashov skill ${name} is incomplete at ${join(root, name)}`);
		}
		return { name, version: readFileSync(versionFile, "utf8").trim(), skillMd };
	});
	return { origin, commit, clonedAt, root, skills };
}

export function pashovSlashPreview(skill: PashovSkillName, install: PashovInstall): string {
	const version = install.skills.find((entry) => entry.name === skill)?.version ?? "?";
	const shared = [
		`Installed from ${install.origin} @ ${install.commit} (skill v${version}).`,
		`Vendor path: ${install.root}/${skill}/`,
		"This is a harness mapping. Models declare tools; they cannot execute shell, forge, Echidna, Medusa, or write into the target tree.",
	];
	if (skill === "x-ray") {
		return [
			"Pashov x-ray → VDH recon (architecture, threats, entry points, invariants).",
			...shared,
			"Not executed: enumerate.sh, forge/hardhat coverage, analyze_git_security.py.",
			"Output: architecture.md and x-ray.md in the harness output directory after harness_run with web3 in scope.",
			"Next: harness_plan with scope.json, then harness_run.",
		].join("\n");
	}
	if (skill === "solidity-auditor") {
		return [
			"Pashov solidity-auditor → twelve parallel VDH hunt cells (math-precision, access-control, economic-security, execution-trace, invariant, periphery, first-principles, asymmetry, boundary, numerical-gap, trust-gap, flow-gap).",
			...shared,
			"Not executed: bash find, bundle cat into /tmp, Agent spawns outside this orchestrator, assemble.sh, the .solidity-auditor/ memory ledger and run files, ASCII banner as a product.",
			"Dedup/gates stay on VDH validate + VVS. Hunter ≠ validator.",
			"Loop mode maps to sequential hunt passes; each later pass gets the already-found list.",
			"Next: harness_plan with domains including web3, then harness_run.",
		].join("\n");
	}
	return [
		"Pashov fizz → propose-only invariant properties (pashov.fizz).",
		...shared,
		"Not executed: Echidna, Medusa, Foundry testers, run_echidna.js, run_medusa.js. The harness never writes test/fizz/ or fizz_data/ into the operator's tree.",
		"Output: fizz-proposed.md in the harness output directory. Wishlist records the un-run campaign.",
		"Next: harness_run with domains including web3.",
	].join("\n");
}
