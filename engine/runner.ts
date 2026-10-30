import { createHash } from "node:crypto";
import { CORPUS_RELEASE, corpusInstalled, type PriorFinding, priorArtForLenses, similarPriorFindings, web3LensOfCell } from "./corpus.ts";
import { extractJsonObject, isProviderErrorPayload } from "./json.ts";
import { inspectNestedRuntime, type NestedRuntimeStatus } from "./nested-runtime.ts";
import {
	dedupPrompt,
	feedbackPrompt,
	fizzPrompt,
	fixingPrompt,
	huntPrompt,
	judgmentPrompt,
	LENSES,
	PROMPT_VERSION,
	RECON_FOCI,
	reconFocusPrompt,
	reconSynthesisPrompt,
	reverifyPrompt,
	SYSTEM,
	verdictPrompt,
} from "./prompts.ts";
import { loadInstalledMdpsec, type MdpsecInstall } from "./mdpsec.ts";
import { loadInstalledPashov, type PashovInstall } from "./pashov.ts";
import {
	type Feedback,
	type Finding,
	findingId,
	type FixProposal,
	type Judgment,
	type FizzProposal,
	parseDedup,
	parseFeedback,
	parseFizz,
	parseFixProposal,
	parseHunt,
	parseJudgment,
	parseRecon,
	parseReverify,
	parseVerdict,
	type Recon,
	type Reverify,
	STAGE_SCHEMAS,
	type Verdict,
} from "./schema.ts";
import { sliceBudget, sliceSource, type SourceSlice } from "./slice.ts";
import { huntLooksCrashed } from "./mechanical.ts";
import type { HarnessConfig, ModelRef, Snapshot } from "./scope.ts";
import {
	applyStageChoice,
	type CatalogModel,
	type ModelRole,
	type PipelineStage,
	sameModel,
	type StageModelPrompt,
	type StageModelSelection,
} from "./stage-models.ts";
import type { RunStore } from "./store.ts";
import {
	type DeclaredTool,
	invertedIndexShortlist,
	peelTools,
	siblingTaskId,
	traceDependencies,
	wishlistTaskId,
} from "./tools.ts";

export interface ModelRequest {
	model: ModelRef;
	system: string;
	prompt: string;
	maxOutputTokens: number;
	signal: AbortSignal;
	schema?: { name: string; schema: Record<string, unknown> };
}

export interface ModelResponse {
	text: string;
	inputTokens: number;
	outputTokens: number;
}

export interface ModelClient {
	complete(request: ModelRequest): Promise<ModelResponse>;
}

export interface HuntTask {
	id: string;
	lens: string;
	pass: number;
	tool: "vdh.hunt" | "vdh.gapfill" | "vdh.sibling";
}

export interface Candidate {
	id: string;
	clusterId: string;
	finding: Finding;
	origins: string[];
	validation: Verdict | null;
	judgment: Judgment | null;
	verification: Reverify | null;
	fixProposal: FixProposal | null;
	status: "needs-reproduction" | "rejected" | "needs-context" | "unvalidated";
}

export interface CoverageCell {
	task: string;
	status: string;
	details: string | null;
	error: string | null;
	shallow: boolean;
}

export interface Cluster {
	id: string;
	candidateIds: string[];
	files: string[];
	trustBoundary: string;
}

export interface Funnel {
	rawCandidates: number;
	uniqueClusters: number;
	shallowHunts: number;
	rejected: number;
	needsContext: number;
	needsReproduction: number;
	unvalidated: number;
	vdhDuplicates: number;
	vvsDuplicates: number;
	judgedExploitableInSource: number;
	judgedLatent: number;
	judgedWrongComponent: number;
	judgedNotARisk: number;
	proposedFixes: number;
}

export interface WishlistItem {
	id: string;
	need: string;
	reason: string;
	origin: string;
}

export interface HarnessReport {
	version: 1;
	name: string;
	identity: string;
	snapshot: string;
	promptVersion: string;
	models: HarnessConfig["models"];
	status: "complete" | "incomplete";
	reservedCalls: number;
	recordedTokens: { input: number; output: number };
	verifiedFindings: 0;
	files: { path: string; sha256: string; lines: number }[];
	recon: ReturnType<typeof parseRecon> | null;
	architecture: string | null;
	pashov: PashovInstall;
	mdpsec: MdpsecInstall;
	fizz: FizzProposal | null;
	coverage: CoverageCell[];
	funnel: Funnel;
	clusters: Cluster[];
	wishlist: WishlistItem[];
	declaredTools: { task: string; tools: DeclaredTool[] }[];
	trace: { edges: { fromPath: string; toPath: string }[]; missing: string[] };
	nestedRuntime: NestedRuntimeStatus;
	stageModels: StageModelSelection[];
	priorArt: PriorArtUse;
	candidates: Candidate[];
}

export interface PriorArtUse {
	source: "web3-audit-database";
	release: string;
	status: "used" | "not-installed" | "not-web3";
	cells: Record<string, string[]>;
	candidates: Record<string, PriorFinding[]>;
}

export function runIdentity(config: HarnessConfig, snapshot: Snapshot): string {
	return createHash("sha256")
		.update(JSON.stringify({ config, root: snapshot.root, snapshot: snapshot.digest, version: PROMPT_VERSION }))
		.digest("hex");
}

export function plan(config: HarnessConfig): HuntTask[] {
	return config.domains.flatMap((domain) =>
		Object.entries(LENSES[domain]).flatMap(([name, lens]) =>
			Array.from({ length: config.limits.passes }, (_, pass) => ({
				id: `hunt:${domain}:${name}:${pass}`,
				lens,
				pass,
				tool: "vdh.hunt" as const,
			})),
		),
	);
}

export function planDynamicHunts(recon: Recon): HuntTask[] {
	return recon.attackClasses.map((attackClass) => ({
		id: `hunt:dynamic:${attackClass.id}:0`,
		lens: attackClass.methodology,
		pass: 0,
		tool: "vdh.hunt" as const,
	}));
}

function clusterCandidates(candidates: Candidate[]): Cluster[] {
	const groups = new Map<string, Candidate[]>();
	for (const candidate of candidates) {
		const group = groups.get(candidate.clusterId) ?? [];
		group.push(candidate);
		groups.set(candidate.clusterId, group);
	}
	return [...groups.entries()]
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([id, group]) => ({
			id,
			candidateIds: group.map((candidate) => candidate.id).sort(),
			files: [...new Set(group.flatMap((candidate) => candidate.finding.evidence.map((cite) => cite.path)))].sort(),
			trustBoundary: group[0].finding.trustBoundary,
		}));
}

function funnel(candidates: Candidate[], coverage: CoverageCell[]): Funnel {
	const counts = { rejected: 0, needsContext: 0, needsReproduction: 0, unvalidated: 0 };
	for (const candidate of candidates) {
		if (candidate.status === "rejected") counts.rejected++;
		else if (candidate.status === "needs-context") counts.needsContext++;
		else if (candidate.status === "needs-reproduction") counts.needsReproduction++;
		else counts.unvalidated++;
	}
	const clusterSizes = new Map<string, number>();
	for (const candidate of candidates) clusterSizes.set(candidate.clusterId, (clusterSizes.get(candidate.clusterId) ?? 0) + 1);
	return {
		rawCandidates: candidates.length,
		uniqueClusters: clusterSizes.size,
		shallowHunts: coverage.filter((cell) => cell.shallow).length,
		...counts,
		vdhDuplicates: [...clusterSizes.values()].reduce((total, size) => total + Math.max(0, size - 1), 0),
		vvsDuplicates: candidates.filter((candidate) => candidate.origins.length > 1).length,
		judgedExploitableInSource: candidates.filter((candidate) => candidate.judgment?.verdict === "exploitable-in-source").length,
		judgedLatent: candidates.filter((candidate) => candidate.judgment?.verdict === "latent").length,
		judgedWrongComponent: candidates.filter((candidate) => candidate.judgment?.verdict === "wrong-component").length,
		judgedNotARisk: candidates.filter((candidate) => candidate.judgment?.verdict === "not-a-risk").length,
		proposedFixes: candidates.filter((candidate) => candidate.fixProposal).length,
	};
}

export async function runHarness(
	config: HarnessConfig,
	snapshot: Snapshot,
	store: RunStore,
	client: ModelClient,
	options: { prompt?: StageModelPrompt; catalog?: CatalogModel[]; corpusDir?: string | null } = {},
): Promise<HarnessReport> {
	if (Date.parse(config.authorization.expiresAt) <= Date.now()) throw new Error("Authorization expired");
	const models = {
		recon: { ...config.models.recon },
		hunter: { ...config.models.hunter },
		validator: { ...config.models.validator },
	};
	const stageModels: StageModelSelection[] = [];
	const catalog = options.catalog ?? Object.values(models);
	const declaredTools: { task: string; tools: DeclaredTool[] }[] = [];
	const wishlist = new Map<string, WishlistItem>();
	let siblingCount = 0;

	function pending(id: string): boolean {
		return store.get(id)?.status !== "done";
	}

	function contextWindowFor(model: ModelRef): number | undefined {
		return catalog.find((entry) => sameModel(entry, model))?.contextWindow;
	}

	function sliced(
		model: ModelRef,
		extra: { prefer?: string[]; lens?: string; recon?: Recon | null; finding?: Finding | null } = {},
	): SourceSlice {
		return sliceSource(snapshot, {
			...extra,
			maxChars: sliceBudget(config.limits.maxInputChars, contextWindowFor(model)),
		});
	}

	async function select(stage: PipelineStage, role: ModelRole, workPending: boolean): Promise<ModelRef> {
		let chosen = models[role];
		if (workPending && options.prompt) {
			chosen = applyStageChoice(
				role,
				await options.prompt.choose({
					stage,
					role,
					current: models[role],
					models,
					catalog,
				}),
				models,
			);
			models[role] = chosen;
		}
		stageModels.push({ stage, role, model: { ...chosen } });
		return chosen;
	}

	async function execute<T>(
		id: string,
		model: ModelRef,
		prompt: string,
		parse: (value: unknown) => T,
		schema: ModelRequest["schema"],
	): Promise<{ value: T; tools: DeclaredTool[] } | null> {
		const prior = store.get(id);
		if (prior?.status === "done") {
			const result = prior.result as { value: unknown; tools?: DeclaredTool[] };
			const value = parse(result.value);
			const tools = result.tools ?? [];
			if (tools.length) declaredTools.push({ task: id, tools });
			return { value, tools };
		}
		if (!store.reserve(id, config.limits.maxCalls)) return null;
		if (Date.parse(config.authorization.expiresAt) <= Date.now()) {
			store.fail(id, "authorization-expired");
			return null;
		}
		const window = catalog.find((entry) => sameModel(entry, model))?.contextWindow;
		const inputChars = SYSTEM.length + prompt.length;
		if (inputChars > config.limits.maxInputChars) {
			store.fail(id, "context-limit: narrow the explicitly scoped files");
			return null;
		}
		if (window && inputChars / 4 > window * 0.25) {
			store.fail(id, "context-limit: task exceeded 25% of the model context window");
			return null;
		}
		const controller = new AbortController();
		let timer: ReturnType<typeof setTimeout> | undefined;
		let phase = "model-error-or-timeout";
		try {
			const timeout = new Promise<never>((_, reject) => {
				timer = setTimeout(() => {
					controller.abort();
					reject(new Error("timeout"));
				}, config.limits.timeoutMs);
			});
			const response = await Promise.race([
				client.complete({
					model,
					system: SYSTEM,
					prompt,
					maxOutputTokens: config.limits.maxOutputTokens,
					signal: controller.signal,
					schema,
				}),
				timeout,
			]);
			phase = "invalid-model-output";
			if (
				typeof response.text !== "string" ||
				response.text.length > config.limits.maxOutputTokens * 32 ||
				![response.inputTokens, response.outputTokens].every((count) => Number.isSafeInteger(count) && count >= 0)
			) {
				throw new Error("Invalid response envelope");
			}
			let payload: unknown;
			try {
				payload = extractJsonObject(response.text);
			} catch {
				throw new Error("Invalid response envelope");
			}
			if (isProviderErrorPayload(payload)) {
				phase = "provider-error-in-body";
				throw new Error("Provider error in HTTP-success body");
			}
			const peeled = peelTools(payload);
			const value = parse(peeled.body);
			if (peeled.tools.length) declaredTools.push({ task: id, tools: peeled.tools });
			store.complete(id, {
				value,
				tools: peeled.tools,
				inputTokens: response.inputTokens,
				outputTokens: response.outputTokens,
			});
			return { value, tools: peeled.tools };
		} catch {
			store.fail(id, phase);
			return null;
		} finally {
			clearTimeout(timer);
			controller.abort();
		}
	}

	async function runPool<T>(items: T[], worker: (item: T) => Promise<void>): Promise<void> {
		let next = 0;
		await Promise.all(
			Array.from({ length: config.limits.concurrency }, async () => {
				while (next < items.length) {
					const item = items[next++];
					await worker(item);
				}
			}),
		);
	}

	function addWishlist(origin: string, need: string, reason: string): void {
		const id = wishlistTaskId(`${origin}:${need}`);
		if (wishlist.has(id) || wishlist.size >= 32) return;
		store.ensure(id, "wishlist");
		if (pending(id)) store.completeLocal(id, { value: { need, reason, origin }, inputTokens: 0, outputTokens: 0, tools: [] });
		wishlist.set(id, { id, need, reason, origin });
	}

	const candidates = new Map<string, Candidate>();
	const huntFindings = new Map<string, number>();
	const extraHunts: HuntTask[] = [];
	const lensByCell = new Map<string, string>();

	function ingest(huntId: string, findings: Finding[]): void {
		huntFindings.set(huntId, findings.length);
		for (const finding of findings) {
			const clusterId = findingId(finding);
			const variant = createHash("sha256").update(JSON.stringify(finding)).digest("hex").slice(0, 16);
			const id = `${clusterId}-${variant}`;
			const existing = candidates.get(id);
			if (existing) {
				existing.origins.push(huntId);
				continue;
			}
			candidates.set(id, {
				id,
				clusterId,
				finding,
				origins: [huntId],
				validation: null,
				judgment: null,
				verification: null,
				fixProposal: null,
				status: "unvalidated",
			});
		}
	}

	function absorb(origin: string, tools: DeclaredTool[], defaultLens: string): void {
		for (const declared of tools) {
			if (declared.tool === "vdh.wishlist" && declared.need) {
				addWishlist(origin, declared.need, declared.reason);
				continue;
			}
			if (declared.tool === "vdh.sibling" && declared.seed && siblingCount < 6) {
				const id = siblingTaskId(declared.seed);
				if (extraHunts.some((hunt) => hunt.id === id) || store.get(id)) continue;
				siblingCount += 1;
				extraHunts.push({
					id,
					lens: declared.lens || declared.seed,
					pass: 0,
					tool: "vdh.sibling",
				});
				continue;
			}
			if (declared.tool === "vdh.gapfill" && declared.cell) {
				const cell = declared.cell;
				const gapId = cell.startsWith("gapfill:") ? cell : `gapfill:${cell}`;
				if (extraHunts.some((hunt) => hunt.id === gapId) || store.get(gapId)) continue;
				extraHunts.push({
					id: gapId,
					lens: declared.lens || declared.rewrite || lensByCell.get(cell) || defaultLens,
					pass: 1,
					tool: "vdh.gapfill",
				});
			}
		}
	}

	const reconIds = (Object.keys(RECON_FOCI) as (keyof typeof RECON_FOCI)[]).map((focus) => `recon:${focus}`);
	for (const id of reconIds) store.ensure(id, "recon");
	store.ensure("recon", "recon");
	const reconModel = await select(
		"recon",
		"recon",
		reconIds.some((id) => pending(id)) || pending("recon"),
	);
	const reconParts: Recon[] = [];
	const reconSlice = sliced(reconModel);
	await runPool(Object.keys(RECON_FOCI) as (keyof typeof RECON_FOCI)[], async (focus) => {
		const result = await execute(
			`recon:${focus}`,
			reconModel,
			reconFocusPrompt(reconSlice.source, config.domains, focus, reconSlice.omitted),
			parseRecon,
			STAGE_SCHEMAS.recon,
		);
		if (result) {
			reconParts.push(result.value);
			absorb(`recon:${focus}`, result.tools, focus);
		}
	});
	let recon: Recon | null = null;
	if (reconParts.length === Object.keys(RECON_FOCI).length) {
		const synthesized = await execute(
			"recon",
			reconModel,
			reconSynthesisPrompt(reconSlice.source, reconParts, reconSlice.omitted),
			parseRecon,
			STAGE_SCHEMAS.recon,
		);
		recon = synthesized?.value ?? null;
		if (synthesized) absorb("recon", synthesized.tools, recon.summary);
	} else if (pending("recon") && store.reserve("recon", config.limits.maxCalls)) {
		store.fail("recon", "recon-subagents-failed");
	}

	let fizz: FizzProposal | null = null;
	if (recon && config.domains.includes("web3")) {
		store.ensure("pashov.fizz", "fizz");
		const fizzModel = await select("fizz", "hunter", pending("pashov.fizz"));
		const fizzSlice = sliced(fizzModel, { recon });
		const proposed = await execute(
			"pashov.fizz",
			fizzModel,
			fizzPrompt(fizzSlice.source, recon, fizzSlice.omitted),
			parseFizz,
			STAGE_SCHEMAS.fizz,
		);
		fizz = proposed?.value ?? null;
		if (proposed) absorb("pashov.fizz", proposed.tools, "pashov.fizz");
		addWishlist(
			"pashov.fizz",
			"Echidna/Medusa invariant campaign",
			"pashov/fizz proposes properties; this harness never executes fuzzers or writes test/fizz into the target",
		);
	}

	async function runHunts(stage: PipelineStage, hunts: HuntTask[], rejectedPatterns: string[]): Promise<void> {
		if (!hunts.length || !recon) return;
		for (const hunt of hunts) {
			store.ensure(hunt.id, hunt.tool === "vdh.gapfill" ? "gapfill" : "hunt");
			lensByCell.set(hunt.id, hunt.lens);
		}
		const hunter = await select(
			stage,
			"hunter",
			hunts.some((hunt) => pending(hunt.id)),
		);
		const byPass = new Map<number, HuntTask[]>();
		for (const hunt of hunts) {
			const group = byPass.get(hunt.pass) ?? [];
			group.push(hunt);
			byPass.set(hunt.pass, group);
		}
		for (const pass of [...byPass.keys()].sort((left, right) => left - right)) {
			const group = byPass.get(pass)!;
			const found = alreadyFound(candidates);
			await runPool(group, async (hunt) => {
				const slice = sliced(hunter, { lens: hunt.lens, recon });
				const result = await execute(
					hunt.id,
					hunter,
					huntPrompt(slice.source, recon!, hunt.lens, hunt.pass, config, {
						cell: hunt.id,
						priorArt: priorArtFor(hunt.id),
						rejectedPatterns,
						alreadyFound: found,
						tool: hunt.tool,
						omitted: slice.omitted,
					}),
					(value) => parseHunt(value, snapshot, config.limits.maxFindingsPerTask),
					STAGE_SCHEMAS.hunt(config.limits.maxFindingsPerTask, snapshot),
				);
				ingest(hunt.id, result?.value.findings ?? []);
				if (result) absorb(hunt.id, result.tools, hunt.lens);
			});
		}
	}

	async function validateUnvalidated(stage: PipelineStage): Promise<void> {
		const queue = [...candidates.values()]
			.filter((candidate) => candidate.status === "unvalidated")
			.sort((a, b) => a.id.localeCompare(b.id));
		if (!queue.length) return;
		for (const candidate of queue) store.ensure(`validate:${candidate.id}`, "validate");
		const validator = await select(
			stage,
			"validator",
			queue.some((candidate) => pending(`validate:${candidate.id}`)),
		);
		await runPool(queue, async (candidate) => {
			const slice = sliced(validator, { finding: candidate.finding, recon });
			const result = await execute(
				`validate:${candidate.id}`,
				validator,
				verdictPrompt(slice.source, candidate.finding, slice.omitted),
				(value) => parseVerdict(value, snapshot),
				STAGE_SCHEMAS.verdict(snapshot),
			);
			candidate.validation = result?.value ?? null;
			candidate.status =
				candidate.validation?.verdict === "supported" ? "needs-reproduction" : (candidate.validation?.verdict ?? "unvalidated");
			if (result) absorb(`validate:${candidate.id}`, result.tools, candidate.finding.attackClass);
		});
	}

	const corpusDirectory = options.corpusDir ?? null;
	const priorArt: PriorArtUse = {
		source: "web3-audit-database",
		release: CORPUS_RELEASE,
		status: !config.domains.includes("web3") ? "not-web3" : corpusDirectory && corpusInstalled(corpusDirectory) ? "used" : "not-installed",
		cells: {},
		candidates: {},
	};
	const priorByLens = priorArt.status === "used" ? await priorArtForLenses(corpusDirectory!, snapshot) : new Map<string, PriorFinding[]>();
	function priorArtFor(cell: string): PriorFinding[] | undefined {
		const lens = web3LensOfCell(cell);
		const prior = lens ? priorByLens.get(lens) : undefined;
		if (prior?.length) priorArt.cells[cell] = prior.map((item) => item.uid);
		return prior;
	}

	const trace = traceDependencies(snapshot.files);
	store.ensure("trace", "trace");
	if (pending("trace")) store.completeLocal("trace", { value: trace, inputTokens: 0, outputTokens: 0, tools: [] });
	for (const need of trace.missing) addWishlist("trace", need, "vdh.trace: dependency or consumer not in this snapshot");
	for (const edge of trace.edges) {
		if (siblingCount >= 6) break;
		const id = `hunt:trace:${createHash("sha256").update(`${edge.fromPath}->${edge.toPath}`).digest("hex").slice(0, 12)}:0`;
		if (extraHunts.some((hunt) => hunt.id === id) || store.get(id)) continue;
		siblingCount += 1;
		extraHunts.push({
			id,
			lens: `Trace whether untrusted input at ${edge.fromPath} can reach a sink or privileged write in ${edge.toPath}. Stay on this edge; do not invent out-of-snapshot consumers.`,
			pass: 0,
			tool: "vdh.sibling",
		});
	}

	if (recon) {
		const scheduled = [...plan(config), ...planDynamicHunts(recon)];
		for (const hunt of scheduled) lensByCell.set(hunt.id, hunt.lens);
		let wave = [...scheduled];
		for (let cycle = 0; cycle < 6 && wave.length; cycle++) {
			await runHunts(cycle === 0 ? "hunt" : "gapfill", wave, rejectedPatterns(candidates));
			await validateUnvalidated("validate");
			const shallow = wave.filter((hunt) => {
				if (hunt.tool === "vdh.gapfill") return false;
				const record = store.get(hunt.id);
				return record?.status === "done" && (huntFindings.get(hunt.id) ?? 0) === 0;
			});
			if (cycle === 0) {
				const notes = [
					...shallow.map((hunt) => `shallow:${hunt.id}`),
					...[...candidates.values()]
						.filter((candidate) => candidate.status === "rejected")
						.map((candidate) => `rejected:${candidate.finding.attackClass}:${candidate.finding.rootCause}`),
				]
					.sort()
					.slice(0, 24)
					.join("\n");
				store.ensure("feedback", "feedback");
				if (notes && (pending("feedback") || extraHunts.length)) {
					const hunter = await select("feedback", "hunter", pending("feedback"));
					const slice = sliced(hunter, { recon });
					const result = await execute(
						"feedback",
						hunter,
						feedbackPrompt(slice.source, recon, notes || "no notes", slice.omitted),
						parseFeedback,
						STAGE_SCHEMAS.feedback,
					);
					if (result) {
						absorb("feedback", result.tools, recon.summary);
						for (const rewrite of result.value.sharperLenses) {
							if (rewrite.cell) lensByCell.set(rewrite.cell, rewrite.lens);
						}
					}
				} else if (pending("feedback")) {
					store.completeLocal("feedback", {
						value: { notes: "no shallow or rejected work", sharperLenses: [] } satisfies Feedback,
						inputTokens: 0,
						outputTokens: 0,
						tools: [],
					});
				}
			}
			const gapfills: HuntTask[] = shallow.map((hunt) => ({
				id: `gapfill:${hunt.id}`,
				lens: lensByCell.get(hunt.id) ?? hunt.lens,
				pass: 1,
				tool: "vdh.gapfill" as const,
			}));
			extraHunts.push(...gapfills.filter((hunt) => !store.get(hunt.id) && !extraHunts.some((item) => item.id === hunt.id)));
			wave = extraHunts.splice(0, extraHunts.length).filter((hunt) => !store.get(hunt.id) || pending(hunt.id));
		}
		const supported = [...candidates.values()]
			.filter((candidate) => candidate.status === "needs-reproduction")
			.sort((a, b) => a.id.localeCompare(b.id));
		if (supported.length) {
			for (const candidate of supported) store.ensure(`reverify:${candidate.id}`, "reverify");
			const verifier = await select(
				"reverify",
				"validator",
				supported.some((candidate) => pending(`reverify:${candidate.id}`)),
			);
			await runPool(supported, async (candidate) => {
				const slice = sliced(verifier, { finding: candidate.finding, recon });
				const result = await execute(
					`reverify:${candidate.id}`,
					verifier,
					reverifyPrompt(slice.source, candidate.finding, slice.omitted),
					(value) => parseReverify(value, snapshot),
					STAGE_SCHEMAS.reverify(snapshot),
				);
				candidate.verification = result?.value ?? null;
				if (candidate.verification?.verdict === "rejected") candidate.status = "rejected";
				if (result) absorb(`reverify:${candidate.id}`, result.tools, candidate.finding.attackClass);
			});
		}
		store.ensure("vvs-dedup", "vvs-dedup");
		const listedForIndex = [...candidates.values()];
		if (pending("vvs-dedup")) {
			store.completeLocal("vvs-dedup", {
				value: {
					shortlists: Object.fromEntries(
						listedForIndex.map((candidate) => [candidate.id, invertedIndexShortlist(candidate, listedForIndex)]),
					),
				},
				inputTokens: 0,
				outputTokens: 0,
				tools: [],
			});
		}
		if (listedForIndex.length >= 2) {
			store.ensure("vvs-dedup-agent", "vvs-dedup");
			const judge = await select("vvs-dedup", "validator", pending("vvs-dedup-agent"));
			const summaries = listedForIndex.map((candidate) => ({
				id: candidate.id,
				clusterId: candidate.clusterId,
				title: candidate.finding.title,
				trustBoundary: candidate.finding.trustBoundary,
				rootCause: candidate.finding.rootCause,
				files: candidate.finding.evidence.map((cite) => cite.path),
				shortlist: invertedIndexShortlist(candidate, listedForIndex),
			}));
			const merged = await execute(
				"vvs-dedup-agent",
				judge,
				dedupPrompt(summaries),
				parseDedup,
				STAGE_SCHEMAS.dedup,
			);
			if (merged) {
				absorb("vvs-dedup-agent", merged.tools, "vvs.dedup");
				for (const merge of merged.value.merges) {
					const canonical = candidates.get(merge.canonicalId);
					if (!canonical) continue;
					for (const duplicateId of merge.duplicateIds) {
						const duplicate = candidates.get(duplicateId);
						if (!duplicate || duplicateId === merge.canonicalId) continue;
						canonical.origins.push(...duplicate.origins);
					}
				}
			}
		}
		const survivors = [...candidates.values()]
			.filter((candidate) => candidate.status === "needs-reproduction")
			.sort((a, b) => a.id.localeCompare(b.id));
		if (survivors.length) {
			for (const candidate of survivors) store.ensure(`vvs-judgment:${candidate.id}`, "vvs-judgment");
			const judge = await select(
				"vvs-judgment",
				"validator",
				survivors.some((candidate) => pending(`vvs-judgment:${candidate.id}`)),
			);
			const listed = [...candidates.values()];
			await runPool(survivors, async (candidate) => {
				const slice = sliced(judge, { finding: candidate.finding, recon });
				const result = await execute(
					`vvs-judgment:${candidate.id}`,
					judge,
					judgmentPrompt(slice.source, candidate.finding, invertedIndexShortlist(candidate, listed), slice.omitted),
					(value) => parseJudgment(value, snapshot),
					STAGE_SCHEMAS.judgment(snapshot),
				);
				candidate.judgment = result?.value ?? null;
				if (result) absorb(`vvs-judgment:${candidate.id}`, result.tools, candidate.finding.attackClass);
			});
			const fixQueue = survivors.filter((candidate) => candidate.judgment?.verdict === "exploitable-in-source");
			if (fixQueue.length) {
				for (const candidate of fixQueue) store.ensure(`vvs-fixing:${candidate.id}`, "vvs-fixing");
				const fixer = await select(
					"vvs-fixing",
					"validator",
					fixQueue.some((candidate) => pending(`vvs-fixing:${candidate.id}`)),
				);
				await runPool(fixQueue, async (candidate) => {
					const slice = sliced(fixer, { finding: candidate.finding, recon });
					const result = await execute(
						`vvs-fixing:${candidate.id}`,
						fixer,
						fixingPrompt(slice.source, candidate.finding, slice.omitted),
						parseFixProposal,
						STAGE_SCHEMAS.fix,
					);
					candidate.fixProposal = result?.value ?? null;
					if (result) absorb(`vvs-fixing:${candidate.id}`, result.tools, candidate.finding.attackClass);
				});
			}
		}
	}

	const tasks = store.list();
	const recordedTokens = { input: 0, output: 0 };
	for (const task of tasks.filter((task) => task.status === "done")) {
		const result = task.result as { inputTokens?: number; outputTokens?: number };
		recordedTokens.input += result.inputTokens ?? 0;
		recordedTokens.output += result.outputTokens ?? 0;
	}
	const coverage: CoverageCell[] = tasks.map((task) => {
		const huntCount = huntFindings.get(task.id);
		const shallow = (task.stage === "hunt" || task.stage === "gapfill") && task.status === "done" && huntCount === 0;
		const spawned = declaredTools.some((entry) => entry.task === task.id);
		const outputTokens = (task.result as { outputTokens?: number } | null)?.outputTokens ?? 0;
		const crashed = shallow && huntLooksCrashed(outputTokens, huntCount ?? 0, spawned);
		const coverageText =
			(task.stage === "hunt" || task.stage === "gapfill") && task.status === "done"
				? (task.result as { value?: { coverage?: string } }).value?.coverage
				: null;
		return {
			task: task.id,
			status: task.status,
			error: task.error,
			shallow: Boolean(shallow),
			details: crashed
				? `suspiciously-fast${coverageText ? `: ${coverageText}` : ""}`
				: coverageText
					? `${shallow ? "shallow: " : ""}${coverageText}`
					: null,
		};
	});
	const listed = [...candidates.values()]
		.sort((a, b) => a.id.localeCompare(b.id))
		.map((candidate) => ({ ...candidate, origins: candidate.origins.sort() }));
	if (priorArt.status === "used") {
		const similar = await similarPriorFindings(
			corpusDirectory!,
			listed.filter((candidate) => candidate.status !== "rejected"),
			snapshot,
		);
		priorArt.candidates = Object.fromEntries([...similar].filter(([, rows]) => rows.length));
	}
	return {
		version: 1,
		name: config.name,
		identity: runIdentity(config, snapshot),
		snapshot: snapshot.digest,
		promptVersion: PROMPT_VERSION,
		models: config.models,
		stageModels,
		status: tasks.every((task) => task.status === "done") ? "complete" : "incomplete",
		reservedCalls: tasks.reduce((total, task) => total + task.attempts, 0),
		recordedTokens,
		verifiedFindings: 0,
		files: snapshot.files.map(({ path, sha256, lines }) => ({ path, sha256, lines })),
		recon,
		architecture: recon?.architecture ?? null,
		pashov: loadInstalledPashov(),
		mdpsec: loadInstalledMdpsec(),
		fizz,
		coverage,
		funnel: funnel(listed, coverage),
		clusters: clusterCandidates(listed),
		wishlist: [...wishlist.values()].sort((left, right) => left.id.localeCompare(right.id)),
		declaredTools,
		trace,
		nestedRuntime: inspectNestedRuntime(),
		priorArt,
		candidates: listed,
	};
}

function rejectedPatterns(candidates: Map<string, Candidate>): string[] {
	return [...candidates.values()]
		.filter((candidate) => candidate.status === "rejected")
		.map((candidate) => `${candidate.finding.attackClass}: ${candidate.finding.rootCause}`)
		.sort()
		.slice(0, 12);
}

function alreadyFound(candidates: Map<string, Candidate>): string[] {
	return [
		...new Set(
			[...candidates.values()]
				.filter((candidate) => candidate.status !== "rejected")
				.map(
					(candidate) =>
						`${candidate.finding.title} (${candidate.finding.evidence[0]?.path ?? "?"}:${candidate.finding.evidence[0]?.startLine ?? "?"}) [${candidate.finding.attackClass}]`,
				),
		),
	]
		.sort()
		.slice(0, 40);
}
