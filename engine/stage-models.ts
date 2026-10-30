import type { HarnessConfig, ModelRef } from "./scope.ts";

export type PipelineStage =
	| "recon"
	| "hunt"
	| "validate"
	| "gapfill"
	| "trace"
	| "feedback"
	| "reverify"
	| "vvs-dedup"
	| "vvs-judgment"
	| "vvs-fixing"
	| "fizz";
export type ModelRole = "recon" | "hunter" | "validator";

export interface CatalogModel {
	provider: string;
	id: string;
	contextWindow?: number;
	maxTokens?: number;
	hasCredentials?: boolean;
}

export interface StageModelSelection {
	stage: PipelineStage;
	role: ModelRole;
	model: ModelRef;
}

export interface StageModelRequest {
	stage: PipelineStage;
	role: ModelRole;
	current: ModelRef;
	models: HarnessConfig["models"];
	catalog: CatalogModel[];
}

export interface StageModelPrompt {
	choose(request: StageModelRequest): Promise<ModelRef>;
}

export const STAGE_MODEL_ADVICE =
	"Cloudflare: treat models as interchangeable. Use whatever frontier model is currently best for this stage, and keep discovery and validation on different models so they cross-check each other.";

const ROLE_PURPOSE: Record<ModelRole, string> = {
	recon: "VDH recon: map architecture and write the threat model",
	hunter: "VDH discovery (hunt/gapfill/sibling/feedback). Prefer a different model than the last hunt if a stronger one is available",
	validator: "VDH validate/reverify + VVS judgment/fixing. Must not be the same model as the hunter",
};

export function sameModel(left: ModelRef, right: ModelRef): boolean {
	return left.provider === right.provider && left.id === right.id;
}

export function formatModel(model: ModelRef): string {
	return `${model.provider}/${model.id}`;
}

export function parseModelRef(value: string): ModelRef | null {
	const trimmed = value.trim();
	const match = /^([^/\s]+)[/ ](.+)$/.exec(trimmed);
	if (!match) return null;
	const provider = match[1].trim();
	const id = match[2].trim();
	if (!provider || !id) return null;
	return { provider, id };
}

export function suggestStageModels(catalog: CatalogModel[], current: ModelRef, forbidden: ModelRef | null): ModelRef[] {
	const ranked = [...catalog].sort((left, right) => (right.contextWindow ?? 0) - (left.contextWindow ?? 0));
	const seen = new Set<string>();
	const suggestions: ModelRef[] = [];
	for (const entry of ranked) {
		if (entry.hasCredentials === false) continue;
		if (sameModel(entry, current) || (forbidden && sameModel(entry, forbidden))) continue;
		if (seen.has(entry.provider)) continue;
		seen.add(entry.provider);
		suggestions.push({ provider: entry.provider, id: entry.id });
		if (suggestions.length === 6) break;
	}
	return suggestions;
}

export function forbiddenForRole(role: ModelRole, models: HarnessConfig["models"]): ModelRef | null {
	if (role === "hunter") return models.validator;
	if (role === "validator") return models.hunter;
	return null;
}

export function applyStageChoice(role: ModelRole, chosen: ModelRef, models: HarnessConfig["models"]): ModelRef {
	const forbidden = forbiddenForRole(role, models);
	if (forbidden && sameModel(chosen, forbidden)) {
		throw new Error("Hunter and validator must be different models");
	}
	return chosen;
}

export function formatStagePrompt(request: StageModelRequest, suggestions: ModelRef[]): string {
	const forbidden = forbiddenForRole(request.role, request.models);
	const lines = [
		`STAGE ${request.stage.toUpperCase()} — switch to a better model for ${request.role} (${ROLE_PURPOSE[request.role]}).`,
		STAGE_MODEL_ADVICE,
		`Current ${request.role}: ${formatModel(request.current)}`,
	];
	if (forbidden)
		lines.push(`Must differ from ${request.role === "hunter" ? "validator" : "hunter"}: ${formatModel(forbidden)}`);
	if (suggestions.length) {
		lines.push("Largest-context catalog models from other providers (live catalog, not a canned list):");
		for (const [index, model] of suggestions.entries()) {
			lines.push(`  ${index + 1}. ${formatModel(model)}`);
		}
	}
	lines.push("Enter a number, provider/id, or blank to keep the current model.");
	return lines.join("\n");
}

export function parseStageChoice(
	input: string,
	current: ModelRef,
	suggestions: ModelRef[],
	catalog: CatalogModel[],
): { model: ModelRef } | { error: string } {
	const trimmed = input.trim();
	if (!trimmed) return { model: current };
	if (/^\d+$/.test(trimmed)) {
		const index = Number(trimmed) - 1;
		if (!suggestions[index]) return { error: "Unknown suggestion number" };
		return { model: suggestions[index] };
	}
	const parsed = parseModelRef(trimmed);
	if (!parsed) return { error: "Use provider/id, a suggestion number, or blank to keep the current model" };
	if (
		catalog.length &&
		!catalog.some((entry) => sameModel(entry, parsed)) &&
		!sameModel(parsed, current) &&
		!suggestions.some((entry) => sameModel(entry, parsed))
	) {
		return { error: "Unknown model; run the models command and paste provider/id" };
	}
	return { model: parsed };
}

export interface InteractiveStagePromptOptions {
	listModels: () => CatalogModel[];
	authorize?: (model: ModelRef) => Promise<void>;
	readLine: () => Promise<string>;
	writeLine: (line: string) => void;
	tty: boolean;
}

export function createStageModelPrompt(options: InteractiveStagePromptOptions): StageModelPrompt {
	return {
		async choose(request: StageModelRequest): Promise<ModelRef> {
			const catalog = options.listModels();
			const forbidden = forbiddenForRole(request.role, request.models);
			const suggestions = suggestStageModels(catalog, request.current, forbidden);
			options.writeLine(formatStagePrompt({ ...request, catalog }, suggestions));
			if (!options.tty) {
				options.writeLine(
					"stdin is not a TTY; keeping the current model. Re-run on a terminal to switch, or pass --keep-models to skip this prompt.",
				);
				return request.current;
			}
			for (let attempt = 0; attempt < 5; attempt++) {
				const parsed = parseStageChoice(await options.readLine(), request.current, suggestions, catalog);
				if ("error" in parsed) {
					options.writeLine(parsed.error);
					continue;
				}
				try {
					const chosen = applyStageChoice(request.role, parsed.model, request.models);
					if (options.authorize) await options.authorize(chosen);
					if (!sameModel(chosen, request.current)) {
						options.writeLine(`Using ${formatModel(chosen)} for ${request.stage}/${request.role}.`);
					}
					return chosen;
				} catch (error) {
					options.writeLine(error instanceof Error ? error.message : "Invalid model choice");
				}
			}
			options.writeLine(`Keeping ${formatModel(request.current)} after failed choices.`);
			return request.current;
		},
	};
}
