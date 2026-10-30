import { randomUUID } from "node:crypto";
import { closeSync, constants, fsyncSync, lstatSync, openSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { preSubmitGate } from "./mdpsec.ts";
import type { PriorFinding } from "./corpus.ts";
import type { HarnessReport } from "./runner.ts";

function markdownText(value: string): string {
	return value
		.replace(/[&<>]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[char]!)
		.replace(/[\\`*_[\]{}()#+.!|~-]/g, "\\$&");
}

export function renderReport(report: HarnessReport): string {
	const lines = [
		`# Security research: ${markdownText(report.name)}`,
		"",
		`Pipeline: **${report.status}**. Confirmed vulnerabilities: **0**.`,
		"VDH discovers; VVS triages on a different model. Model-supported candidates are unverified hypotheses, not bounty-ready findings. No reproduction or patch was executed.",
		"Pre-submit gate never returns YES: no candidate was reproduced.",
		"Complete means all planned model tasks completed, not that the target is secure or all bugs were found.",
		"",
		`Snapshot: \`${report.snapshot}\``,
		`Prompt version: \`${report.promptVersion}\``,
		`Reserved model calls (including failures/interruption): ${report.reservedCalls}.`,
		`Recorded successful-call tokens: ${report.recordedTokens.input} input / ${report.recordedTokens.output} output. Failed-call billing is unknown.`,
		`Nested runtime silent-failure risk: **${report.nestedRuntime.silentFailureRisk ? "yes" : "no"}**.`,
		markdownText(report.nestedRuntime.advice),
		"",
		"## Pashov skills",
		"",
		`Installed from \`${markdownText(report.pashov.origin)}\` @ \`${markdownText(report.pashov.commit)}\`.`,
		...report.pashov.skills.map(
			(skill) => `- \`${markdownText(skill.name)}\` v${markdownText(skill.version)} → ${markdownText(skill.skillMd)}`,
		),
		"x-ray maps to VDH recon. solidity-auditor maps to twelve web3 hunt cells. fizz proposes invariant properties and is never executed.",
		"",
		"## mdpsec prompt packs",
		"",
		...report.mdpsec.packs.map(
			(pack) => `- \`${markdownText(pack.name)}\` installed from \`${markdownText(pack.origin)}\` @ \`${markdownText(pack.commit)}\`.`,
		),
		"Live phases, browser, accounts, OOB, and should-i-submit live validation are never executed; rubrics are folded into hunt/validate/judgment/dedup prompts.",
		"",
		"## Models per stage",
		"",
		"Discovery (VDH) and validation/judgment (VVS) should use different models. Stage prompts ask the operator to switch to a better frontier model before each pending stage.",
		...report.stageModels.map(
			(entry) =>
				`- ${markdownText(entry.stage)}/${markdownText(entry.role)}: \`${markdownText(entry.model.provider)}/${markdownText(entry.model.id)}\``,
		),
		"",
		"## Architecture and assumptions",
		"",
		markdownText(report.architecture ?? report.recon?.summary ?? "Recon did not complete."),
		"",
		markdownText(report.recon?.summary ?? ""),
		"",
		...(report.recon?.actors ?? []).map((value) => `- Actor: ${markdownText(value)}`),
		...(report.recon?.invariants ?? []).map((value) => `- Invariant: ${markdownText(value)}`),
		...(report.recon?.attackClasses ?? []).map(
			(value) => `- Extra attack class \`${markdownText(value.id)}\`: ${markdownText(value.methodology)}`,
		),
		...(report.recon?.missingContext ?? []).map((value) => `- Missing context: ${markdownText(value)}`),
		"",
		"## Prior art (Web3 Audit Database)",
		"",
		...priorArtLines(report),
		"",
		"## Filtering funnel",
		"",
		"VDH: raw candidates are everything hunters emitted before independent validation. Needs-reproduction is still unverified. Rejected means the validator disproved the candidate. This is not a recall score.",
		`Raw candidates: ${report.funnel.rawCandidates}. Clusters: ${report.funnel.uniqueClusters}. VDH duplicates folded into clusters: ${report.funnel.vdhDuplicates}. Shallow hunts: ${report.funnel.shallowHunts}.`,
		`Rejected: ${report.funnel.rejected}. Needs context: ${report.funnel.needsContext}. Needs reproduction: ${report.funnel.needsReproduction}. Unvalidated: ${report.funnel.unvalidated}.`,
		`VVS: exploitable-in-source ${report.funnel.judgedExploitableInSource}; latent ${report.funnel.judgedLatent}; wrong-component ${report.funnel.judgedWrongComponent}; not-a-risk ${report.funnel.judgedNotARisk}; proposed fixes (not applied) ${report.funnel.proposedFixes}.`,
		"This funnel is orchestration accounting, not a recall score and not proof that remaining candidates are bugs.",
		"",
		"## Declared tools and wishlist",
		"",
		"Agents may declare VDH/VVS tools at any time. The harness runs them; models cannot execute them. Wishlist items are missing dependencies — they are not invented results.",
		...report.declaredTools.flatMap((entry) =>
			entry.tools.map((tool) => `- ${markdownText(entry.task)} declared \`${markdownText(tool.tool)}\`: ${markdownText(tool.reason)}`),
		),
		...report.wishlist.map((item) => `- Wishlist \`${item.id}\` from ${markdownText(item.origin)}: ${markdownText(item.need)} — ${markdownText(item.reason)}`),
		...report.trace.missing.map((item) => `- Trace gap: ${markdownText(item)}`),
		report.declaredTools.length || report.wishlist.length || report.trace.missing.length ? "" : "- None.",
		"",
		"## Coverage ledger",
		"",
		...report.coverage.map(
			(cell) =>
				`- ${markdownText(cell.task)}: **${cell.status}**${cell.shallow ? " — shallow" : ""}${cell.error ? ` — ${markdownText(cell.error)}` : ""}${cell.details ? ` — ${markdownText(cell.details)}` : ""}`,
		),
		"",
		"Coverage is model-reported attention, not verified branch coverage. Pending/failed cells are gaps. Shallow means a completed hunt returned zero findings; it was re-queued as gapfill. suspiciously-fast means the hunter returned almost no tokens and spawned no sibling/wishlist — treat as a crashed cell, not a clean bill of health.",
		"",
		"## Hardening notes (not findings)",
		"",
		"Defense-in-depth gaps and missing deployment context are not vulnerabilities.",
		...(report.recon?.missingContext ?? []).map((value) => `- ${markdownText(value)}`),
		report.recon?.missingContext?.length ? "" : "- None recorded.",
		"",
		"## Clusters",
		"",
		...report.clusters.map(
			(cluster) =>
				`- \`${cluster.id}\` (${cluster.candidateIds.length}): ${markdownText(cluster.trustBoundary)} — ${cluster.files.map(markdownText).join(", ") || "no files"}`,
		),
		"",
		"## Candidate queue",
		"",
	];
	for (const candidate of report.candidates) {
		const finding = candidate.finding;
		const gate = preSubmitGate(candidate);
		lines.push(
			`### ${markdownText(finding.title)}`,
			"",
			`ID: \`${candidate.id}\``,
			`Status: **${candidate.status}**; proposed severity: **${finding.severity}**.`,
			"",
			`Cluster: \`${candidate.clusterId}\``,
			`Attacker: ${markdownText(finding.attacker)}`,
			`Intent broken: ${markdownText(finding.intentBroken)}`,
			`Attack class: ${markdownText(finding.attackClass)}`,
			`Boundary: ${markdownText(finding.trustBoundary)}`,
			"",
			`Root cause: ${markdownText(finding.rootCause)}`,
			`Impact: ${markdownText(finding.impact)}`,
			"",
			"Preconditions:",
			...finding.preconditions.map((value) => `- ${markdownText(value)}`),
			"",
			"Proposed local reproduction (not executed):",
			...finding.reproduction.map((value, i) => `${i + 1}. ${markdownText(value)}`),
			"",
			`Proposed remediation: ${markdownText(finding.remediation)}`,
			"",
			"Source citations:",
			...finding.evidence.map((cite) => {
				const fence = "`".repeat(Math.max(3, ...(cite.quote.match(/`+/g) ?? []).map((run) => run.length + 1)));
				return `\n${markdownText(cite.path)}:${cite.startLine}–${cite.endLine}\n\n${fence}text\n${cite.quote}\n${fence}\n`;
			}),
			`Independent validator: ${markdownText(candidate.validation?.reason ?? "Not completed")}`,
			`Independent reverify (factual claims only; not a confirmed bug): ${markdownText(candidate.verification?.reason ?? "Not run")}`,
			"",
			`VVS judgment: ${markdownText(candidate.judgment?.reason ?? "Not run (only needs-reproduction candidates enter VVS)")}`,
			candidate.fixProposal
				? `VVS fix proposal (blocked, not applied): ${markdownText(candidate.fixProposal.notes)} — ${markdownText(candidate.fixProposal.blockReason)}`
				: "VVS fix proposal: none.",
			"",
			`Pre-submit gate (mdpsec should-i-submit): **${gate.answer}**`,
			`Why: ${markdownText(gate.why)}`,
			`Do this next: ${markdownText(gate.next)}`,
			`Do not run: ${markdownText(gate.doNotRun)}`,
			"",
			...(candidate.validation?.missingContext ?? []).map((value) => `- Required context: ${markdownText(value)}`),
			"",
		);
	}
	lines.push(
		"## Human release gate",
		"",
		"Before disclosure: recheck program scope, reproduce on the exact original snapshot in an isolated local environment, record expected/actual results, verify a minimal fix with the same regression test, redact sensitive evidence, and obtain human review.",
		"Never publish this report automatically. Findings, quotes and program metadata may be confidential.",
		"",
	);
	return lines.join("\n");
}

export function renderFindingsJson(report: HarnessReport): string {
	const body = {
		version: 1,
		snapshot: report.snapshot,
		promptVersion: report.promptVersion,
		verifiedFindings: 0 as const,
		note: "Mechanical schema only. verified on a candidate means source claims matched, not that a vulnerability is confirmed. Tests and patches were not executed.",
		candidates: report.candidates.map((candidate) => ({
			id: candidate.id,
			clusterId: candidate.clusterId,
			status: candidate.status,
			severity: candidate.finding.severity,
			title: candidate.finding.title,
			attacker: candidate.finding.attacker,
			intentBroken: candidate.finding.intentBroken,
			trustBoundary: candidate.finding.trustBoundary,
			attackClass: candidate.finding.attackClass,
			rootCause: candidate.finding.rootCause,
			impact: candidate.finding.impact,
			evidence: candidate.finding.evidence,
			validation: candidate.validation?.verdict ?? null,
			reverify: candidate.verification?.verdict ?? null,
			judgment: candidate.judgment?.verdict ?? null,
			fixBlocked: Boolean(candidate.fixProposal),
		})),
	};
	const parsed = JSON.parse(JSON.stringify(body)) as typeof body;
	if (parsed.verifiedFindings !== 0 || !Array.isArray(parsed.candidates)) throw new Error("findings.json mechanical check failed");
	return JSON.stringify(parsed, null, 2);
}

export function renderFindingsDetail(report: HarnessReport): string {
	const rows = report.candidates.filter(
		(candidate) =>
			candidate.status === "needs-reproduction" &&
			(candidate.finding.severity === "critical" || candidate.finding.severity === "high" || candidate.finding.severity === "medium"),
	);
	const lines = [
		`# Findings detail: ${markdownText(report.name)}`,
		"",
		"MEDIUM+ source-supported candidates only. Still unverified. No exploit was executed.",
		"",
	];
	if (!rows.length) {
		lines.push("None.", "");
		return lines.join("\n");
	}
	for (const candidate of rows) {
		const finding = candidate.finding;
		lines.push(
			`## ${markdownText(finding.title)}`,
			"",
			`Status **${candidate.status}**. Reverify: ${markdownText(candidate.verification?.verdict ?? "pending")}.`,
			"",
			...finding.evidence.map((cite) => `- ${markdownText(cite.path)}:${cite.startLine}–${cite.endLine}`),
			"",
			markdownText(finding.rootCause),
			"",
		);
		const similar = report.priorArt.candidates[candidate.id] ?? [];
		if (similar.length) {
			lines.push("Similar past public findings (check the original report; not evidence for this target):", "");
			for (const item of similar) lines.push(`- ${priorLine(item)}`);
			lines.push("");
		}
	}
	return lines.join("\n");
}

function priorLine(item: PriorFinding): string {
	const where = [item.firm, item.project, item.year ? String(item.year) : ""].filter(Boolean).join(", ");
	const link = item.url ? ` <${item.url.replace(/[<>\s]/g, "")}>` : "";
	return `[${markdownText(item.severity)}] ${markdownText(item.title)} — ${markdownText(where)} \`${markdownText(item.uid)}\`${link}`;
}

function priorArtLines(report: HarnessReport): string[] {
	const use = report.priorArt;
	if (use.status === "not-web3") return ["Not used: no web3 domain in scope."];
	if (use.status === "not-installed")
		return ["Not used: corpus not installed. Ask the agent to call `harness_corpus` with action=sync, then rerun."];
	const matched = Object.keys(use.candidates).length;
	return [
		`Release \`${markdownText(use.release)}\` from https://web3-audits.dicksonwu.xyz/ fed past findings to ${Object.keys(use.cells).length} web3 hunt cells as untrusted pattern hints. ${matched} candidates have similar past findings (listed in FINDINGS-DETAIL.md and report.json).`,
		"Corpus records are AI-assisted extractions of public reports: a similar past finding is a lead for known-issue and severity checks, not evidence. Quoted text keeps its publisher's rights.",
	];
}

function renderXray(report: HarnessReport): string {
	const recon = report.recon;
	const lines = [
		"# X-ray (Pashov, source-only)",
		"",
		`Installed from ${report.pashov.origin} @ ${report.pashov.commit}.`,
		"This harness maps x-ray onto VDH recon. enumerate.sh, forge/hardhat coverage, and git security scripts were not executed.",
		"",
		"## Overview",
		"",
		recon?.architecture ?? recon?.summary ?? "Recon did not complete.",
		"",
		"## Threat model",
		"",
		...(recon?.actors ?? []).map((value) => `- Actor: ${value}`),
		...(recon?.entryPoints ?? []).map((value) => `- Entry: ${value}`),
		...(recon?.trustBoundaries ?? []).map((value) => `- Boundary: ${value}`),
		"",
		"## Invariants",
		"",
		...(recon?.invariants ?? []).map((value) => `- ${value}`),
		recon?.invariants?.length ? "" : "- None recorded.",
		"",
		"## Missing context",
		"",
		...(recon?.missingContext ?? []).map((value) => `- ${value}`),
		recon?.missingContext?.length ? "" : "- None recorded.",
		"",
	];
	return `${lines.join("\n")}\n`;
}

function renderFizz(report: HarnessReport): string {
	const lines = [
		"# Fizz (Pashov, propose-only)",
		"",
		`Installed from ${report.pashov.origin} @ ${report.pashov.commit}.`,
		"Echidna, Medusa, and Foundry testers were not executed. Nothing was written into the operator's tree.",
		"",
	];
	if (!report.fizz) {
		lines.push("No fizz pass (web3 was not in scope, or the propose stage did not complete).", "");
		return `${lines.join("\n")}\n`;
	}
	if (!report.fizz.properties.length) {
		lines.push("No properties proposed.", "");
	} else {
		for (const property of report.fizz.properties) {
			lines.push(`## ${property.name}`, "", property.invariant, "", `Handler hint: ${property.handlerHint}`, "");
		}
	}
	if (report.fizz.blockers.length) {
		lines.push("## Blockers", "", ...report.fizz.blockers.map((item) => `- ${item}`), "");
	}
	return `${lines.join("\n")}\n`;
}

export function writeReports(directory: string, report: HarnessReport): void {
	for (const [name, contents] of [
		["report.json", JSON.stringify(report, null, 2)],
		["report.md", renderReport(report)],
		["architecture.md", `${report.architecture ?? report.recon?.summary ?? "Recon did not complete."}\n`],
		["x-ray.md", renderXray(report)],
		["fizz-proposed.md", renderFizz(report)],
		["findings.json", renderFindingsJson(report)],
		["FINDINGS-DETAIL.md", renderFindingsDetail(report)],
	]) {
		const destination = join(directory, name);
		try {
			if (!lstatSync(destination).isFile()) throw new Error("Report destination must be a regular file");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
		const temporary = join(directory, `.report-${randomUUID()}`);
		const fd = openSync(
			temporary,
			constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
			0o600,
		);
		try {
			writeFileSync(fd, contents);
			fsyncSync(fd);
		} finally {
			closeSync(fd);
		}
		try {
			renameSync(temporary, destination);
		} catch (error) {
			unlinkSync(temporary);
			throw error;
		}
	}
}
