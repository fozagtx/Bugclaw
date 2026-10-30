import { homedir } from "node:os";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { AgentClient } from "./agent-client.ts";
import type { ModelClient, ModelRequest, ModelResponse } from "./runner.ts";
import type { HarnessConfig, ModelRef } from "./scope.ts";

export type Transport = "anthropic-messages" | "openai-chat" | "gemini" | "agent";

export interface CatalogEntry {
	provider: string;
	id: string;
	contextWindow: number;
	maxTokens: number;
	baseUrl: string;
	transport: Transport;
}

export interface ProviderClientOptions {
	env?: NodeJS.ProcessEnv;
	fetch?: typeof fetch;
	readFile?: (path: string) => string | undefined;
	homedir?: string;
}

export interface ListedModel {
	provider: string;
	id: string;
	contextWindow: number;
	maxTokens: number;
	hasCredentials: boolean;
}

interface ModelSpec {
	id: string;
	contextWindow: number;
	maxTokens: number;
}

interface ProviderSpec {
	provider: string;
	transport: Transport;
	baseUrl?: string;
	models: ModelSpec[];
}

const MINIMAX_MODELS: ModelSpec[] = [
	{ id: "MiniMax-M2.7", contextWindow: 200000, maxTokens: 128000 },
	{ id: "MiniMax-M2.7-highspeed", contextWindow: 200000, maxTokens: 128000 },
	{ id: "MiniMax-M3", contextWindow: 512000, maxTokens: 128000 },
];

const PROVIDERS: ProviderSpec[] = [
	{ provider: "minimax", transport: "anthropic-messages", baseUrl: "https://api.minimax.io/anthropic", models: MINIMAX_MODELS },
	{ provider: "minimax-cn", transport: "anthropic-messages", baseUrl: "https://api.minimaxi.com/anthropic", models: MINIMAX_MODELS },
	{
		provider: "anthropic",
		transport: "anthropic-messages",
		baseUrl: "https://api.anthropic.com",
		models: [
			{ id: "claude-opus-4-1", contextWindow: 200000, maxTokens: 32000 },
			{ id: "claude-sonnet-4-5", contextWindow: 200000, maxTokens: 64000 },
			{ id: "claude-haiku-4-5", contextWindow: 200000, maxTokens: 64000 },
		],
	},
	{
		provider: "openai",
		transport: "openai-chat",
		baseUrl: "https://api.openai.com/v1",
		models: [
			{ id: "gpt-5", contextWindow: 400000, maxTokens: 128000 },
			{ id: "gpt-5-mini", contextWindow: 400000, maxTokens: 128000 },
			{ id: "gpt-4.1", contextWindow: 1047576, maxTokens: 32768 },
			{ id: "gpt-4o", contextWindow: 128000, maxTokens: 16384 },
			{ id: "o3-mini", contextWindow: 200000, maxTokens: 100000 },
		],
	},
	{
		provider: "openrouter",
		transport: "openai-chat",
		baseUrl: "https://openrouter.ai/api/v1",
		models: [
			{ id: "anthropic/claude-sonnet-4.5", contextWindow: 200000, maxTokens: 64000 },
			{ id: "openai/gpt-5", contextWindow: 400000, maxTokens: 128000 },
			{ id: "google/gemini-2.5-pro", contextWindow: 1048576, maxTokens: 65536 },
			{ id: "deepseek/deepseek-r1", contextWindow: 163840, maxTokens: 65536 },
		],
	},
	{
		provider: "deepseek",
		transport: "openai-chat",
		baseUrl: "https://api.deepseek.com/v1",
		models: [
			{ id: "deepseek-chat", contextWindow: 131072, maxTokens: 8192 },
			{ id: "deepseek-reasoner", contextWindow: 131072, maxTokens: 65536 },
		],
	},
	{
		provider: "nebius",
		transport: "openai-chat",
		baseUrl: "https://api.tokenfactory.nebius.com/v1",
		models: [
			{ id: "nvidia/Nemotron-3-Ultra-550b-a55b", contextWindow: 1048576, maxTokens: 32768 },
			{ id: "nvidia/nemotron-3-super-120b-a12b", contextWindow: 262144, maxTokens: 32768 },
			{ id: "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B", contextWindow: 262144, maxTokens: 32768 },
			{ id: "nvidia/Nemotron-3_5-Lightning", contextWindow: 1048576, maxTokens: 32768 },
			{ id: "openai/gpt-oss-120b", contextWindow: 131072, maxTokens: 32768 },
			{ id: "deepseek-ai/DeepSeek-V4-Pro", contextWindow: 131072, maxTokens: 32768 },
		],
	},
	{
		provider: "google",
		transport: "gemini",
		baseUrl: "https://generativelanguage.googleapis.com",
		models: [
			{ id: "gemini-2.5-pro", contextWindow: 1048576, maxTokens: 65536 },
			{ id: "gemini-2.5-flash", contextWindow: 1048576, maxTokens: 65536 },
		],
	},
	{ provider: "openai-compatible", transport: "openai-chat" },
];

const ENV_KEY_HINT: Record<string, string> = {
	minimax: "MINIMAX_API_KEY",
	"minimax-cn": "MINIMAX_CN_API_KEY",
	anthropic: "ANTHROPIC_API_KEY",
	openai: "OPENAI_API_KEY",
	openrouter: "OPENROUTER_API_KEY",
	deepseek: "DEEPSEEK_API_KEY",
	nebius: "NEBIUS_API_KEY",
	google: "GEMINI_API_KEY",
	"openai-compatible": "HARNESS_OPENAI_COMPAT_API_KEY",
	agent: "BUGCLAW_AGENT_DIR",
};

function readConfigApiKey(
	readFile: (path: string) => string | undefined,
	home: string,
	dataDirEnv?: string,
): string | undefined {
	const candidates = [
		dataDirEnv ? join(dataDirEnv, "config.yaml") : undefined,
		join(home, ".minimax-code", "config.yaml"),
		join(home, ".minimax", "config.yaml"),
	].filter((path): path is string => Boolean(path));
	for (const path of candidates) {
		const text = readFile(path);
		if (!text) continue;
		const block = /minimax_api:\s*\n((?:[ \t]+[^\n]*\n)+)/.exec(text);
		const key = (block?.[1] ?? text).match(/(?:^|\n)[ \t]*apiKey:\s*["']?([^\s"']+)/)?.[1];
		if (key) return key;
	}
	return undefined;
}

function defaultReadFile(path: string): string | undefined {
	try {
		return readFileSync(path, "utf8");
	} catch {
		return undefined;
	}
}

function isLoopbackBaseUrl(baseUrl: string): boolean {
	try {
		const host = new URL(baseUrl).hostname;
		return host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
	} catch {
		return false;
	}
}

function parseCompatModels(value: string | undefined): ModelSpec[] {
	if (!value) return [];
	const models: ModelSpec[] = [];
	for (const item of value.split(",")) {
		const parts = item.split(":").map((part) => part.trim());
		const id = parts[0];
		if (!id) continue;
		const contextWindow = Number(parts[1]) || 128000;
		const maxTokens = Number(parts[2]) || 8192;
		models.push({ id, contextWindow, maxTokens });
	}
	return models;
}

function narrowConfig(config: HarnessConfig, providers: string[]): HarnessConfig {
	const models: Record<string, ModelRef> = {};
	for (const [role, ref] of Object.entries(config.models)) {
		if (providers.includes(ref.provider)) models[role] = ref;
	}
	return { ...config, models };
}

const INCOMPLETE = "Incomplete, failed or tool-bearing model response";

export class ProviderClient implements ModelClient {
	private authorized = false;
	private readonly env: NodeJS.ProcessEnv;
	private readonly fetchImpl: typeof fetch;
	private readonly readFile: (path: string) => string | undefined;
	private readonly home: string;
	private readonly models: CatalogEntry[];
	private agentClient?: AgentClient;

	constructor(options: ProviderClientOptions = {}) {
		this.env = options.env ?? process.env;
		this.fetchImpl = options.fetch ?? fetch;
		this.readFile = options.readFile ?? defaultReadFile;
		this.home = options.homedir ?? homedir();
		this.models = this.buildCatalog();
	}

	private providerSpecs(): ProviderSpec[] {
		const specs = PROVIDERS.filter((spec) => spec.provider !== "openai-compatible").map((spec) => ({ ...spec }));
		const openai = specs.find((spec) => spec.provider === "openai");
		if (openai) openai.baseUrl = this.env.OPENAI_BASE_URL?.trim() || openai.baseUrl;
		const nebius = specs.find((spec) => spec.provider === "nebius");
		if (nebius) nebius.baseUrl = this.env.NEBIUS_BASE_URL?.trim() || nebius.baseUrl;
		const compatBase = this.env.HARNESS_OPENAI_COMPAT_BASE_URL?.trim();
		if (compatBase) {
			specs.push({
				provider: "openai-compatible",
				transport: "openai-chat",
				baseUrl: compatBase,
				models: parseCompatModels(this.env.HARNESS_OPENAI_COMPAT_MODELS),
			});
		}
		if (this.env.BUGCLAW_AGENT_DIR?.trim()) {
			specs.push({
				provider: "agent",
				transport: "agent",
				baseUrl: "",
				models: [
					{ id: "coding-agent", contextWindow: 1_000_000, maxTokens: 100_000 },
					{ id: "coding-agent-2", contextWindow: 1_000_000, maxTokens: 100_000 },
				],
			});
		}
		return specs;
	}

	private buildCatalog(): CatalogEntry[] {
		const specs = this.providerSpecs();
		const byKey = new Map<string, CatalogEntry>();
		for (const spec of specs) {
			for (const model of spec.models ?? []) {
				if (spec.baseUrl === undefined) continue;
				byKey.set(`${spec.provider}/${model.id}`, {
					provider: spec.provider,
					id: model.id,
					contextWindow: model.contextWindow,
					maxTokens: model.maxTokens,
					baseUrl: spec.baseUrl,
					transport: spec.transport,
				});
			}
		}
		const raw = this.env.SECURITY_HARNESS_MODELS?.trim();
		if (raw) {
			try {
				const parsed: unknown = JSON.parse(raw);
				if (Array.isArray(parsed)) {
					for (const entry of parsed) {
						if (typeof entry !== "object" || entry === null) continue;
						const candidate = entry as { provider?: unknown; id?: unknown; contextWindow?: unknown; maxTokens?: unknown };
						if (typeof candidate.provider !== "string" || typeof candidate.id !== "string") continue;
						const spec = specs.find((item) => item.provider === candidate.provider);
						if (spec?.baseUrl === undefined) continue;
						byKey.set(`${spec.provider}/${candidate.id}`, {
							provider: spec.provider,
							id: candidate.id,
							contextWindow: typeof candidate.contextWindow === "number" ? candidate.contextWindow : 128000,
							maxTokens: typeof candidate.maxTokens === "number" ? candidate.maxTokens : 8192,
							baseUrl: spec.baseUrl,
							transport: spec.transport,
						});
					}
				}
			} catch {}
		}
		return [...byKey.values()];
	}

	listModels(): ListedModel[] {
		return this.models.map(({ provider, id, contextWindow, maxTokens }) => ({
			provider,
			id,
			contextWindow,
			maxTokens,
			hasCredentials: this.hasCredentials(provider),
		}));
	}

	async preflight(config: HarnessConfig): Promise<void> {
		this.authorized = false;
		if (!config.authorization.allowRemoteModels) throw new Error("Remote model transmission is not authorized");
		if (Date.parse(config.authorization.expiresAt) <= Date.now()) throw new Error("Authorization expired");
		for (const ref of Object.values(config.models)) this.assertUsable(ref, config);
		if (Object.values(config.models).some((ref) => ref.provider === "agent")) {
			await this.agent().preflight(narrowConfig(config, ["agent"]));
		}
		this.authorized = true;
	}

	async authorize(ref: ModelRef, config: HarnessConfig): Promise<void> {
		if (!this.authorized) throw new Error("Remote model preflight is required");
		if (ref.provider === "agent") return this.agent().authorize(ref);
		this.assertUsable(ref, config);
	}

	private agent(): AgentClient {
		if (!this.agentClient) this.agentClient = new AgentClient({ env: this.env });
		return this.agentClient;
	}

	private findModel(ref: ModelRef): CatalogEntry | undefined {
		return this.models.find((model) => model.provider === ref.provider && model.id === ref.id);
	}

	private apiKey(provider: string): string | undefined {
		const env = this.env;
		if (provider === "minimax") return env.MINIMAX_API_KEY?.trim() || this.configKey();
		if (provider === "minimax-cn")
			return env.MINIMAX_CN_API_KEY?.trim() || env.MINIMAX_API_KEY?.trim() || this.configKey();
		if (provider === "anthropic") return env.ANTHROPIC_API_KEY?.trim() || undefined;
		if (provider === "openai") return env.OPENAI_API_KEY?.trim() || undefined;
		if (provider === "openrouter") return env.OPENROUTER_API_KEY?.trim() || undefined;
		if (provider === "deepseek") return env.DEEPSEEK_API_KEY?.trim() || undefined;
		if (provider === "nebius") return env.NEBIUS_API_KEY?.trim() || undefined;
		if (provider === "google") return env.GEMINI_API_KEY?.trim() || env.GOOGLE_API_KEY?.trim() || undefined;
		if (provider === "openai-compatible") return env.HARNESS_OPENAI_COMPAT_API_KEY?.trim() || undefined;
		return undefined;
	}

	private configKey(): string | undefined {
		return readConfigApiKey(this.readFile, this.home, this.env.MINIMAX_DATA_DIR?.trim());
	}

	private hasCredentials(provider: string): boolean {
		if (provider === "agent") return Boolean(this.env.BUGCLAW_AGENT_DIR?.trim());
		if (this.apiKey(provider)) return true;
		if (provider === "openai-compatible") {
			const baseUrl = this.env.HARNESS_OPENAI_COMPAT_BASE_URL?.trim();
			return Boolean(baseUrl) && isLoopbackBaseUrl(baseUrl);
		}
		return false;
	}

	private credentialsError(provider: string): Error {
		const hint = ENV_KEY_HINT[provider] ?? "the provider API key";
		const suffix = provider === "minimax" || provider === "minimax-cn" ? " or apiKey in ~/.minimax-code/config.yaml" : "";
		return new Error(`No credentials for provider ${provider}: set ${hint}${suffix}`);
	}

	private assertUsable(ref: ModelRef, config: HarnessConfig): void {
		if (!config.authorization.allowRemoteModels) throw new Error("Remote model transmission is not authorized");
		const model = this.findModel(ref);
		if (!model) throw new Error("Configured model is absent from the installed catalog; use the models command");
		if (config.limits.maxOutputTokens > model.maxTokens) throw new Error("Output budget exceeds model capability");
		if (!this.hasCredentials(ref.provider)) throw this.credentialsError(ref.provider);
	}

	async complete(request: ModelRequest): Promise<ModelResponse> {
		if (!this.authorized) throw new Error("Remote model preflight is required");
		const model = this.findModel(request.model);
		if (!model) throw new Error("Unknown model");
		if (!this.hasCredentials(request.model.provider)) throw this.credentialsError(request.model.provider);
		if (model.transport === "agent") return this.agent().complete(request);
		const key = this.apiKey(request.model.provider);
		const inputBound = Buffer.byteLength(request.system + request.prompt, "utf8") + 8192;
		if (inputBound + request.maxOutputTokens > model.contextWindow) throw new Error("Model context budget exceeded");
		if (model.transport === "anthropic-messages") return this.completeAnthropic(model, key, request);
		if (model.transport === "gemini") return this.completeGemini(model, key, request);
		return this.completeOpenAI(model, key, request);
	}

	private async post(url: string, headers: Record<string, string>, body: unknown, signal?: AbortSignal) {
		const response = await this.fetchImpl(url, {
			method: "POST",
			headers,
			body: JSON.stringify(body),
			signal,
		});
		const text = await response.text();
		if (!response.ok) throw new Error(INCOMPLETE);
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch {
			throw new Error(INCOMPLETE);
		}
		if (typeof parsed !== "object" || parsed === null) throw new Error(INCOMPLETE);
		return parsed as Record<string, unknown>;
	}

	private async completeAnthropic(model: CatalogEntry, key: string | undefined, request: ModelRequest): Promise<ModelResponse> {
		const payload = await this.post(
			`${model.baseUrl}/v1/messages`,
			{
				"content-type": "application/json",
				"x-api-key": key ?? "",
				"anthropic-version": "2023-06-01",
			},
			{
				model: model.id,
				max_tokens: request.maxOutputTokens,
				system: request.system,
				messages: [{ role: "user", content: request.prompt }],
			},
			request.signal,
		);
		if (payload.type === "error") throw new Error(INCOMPLETE);
		if (payload.stop_reason !== "end_turn") throw new Error(INCOMPLETE);
		if (!Array.isArray(payload.content)) throw new Error(INCOMPLETE);
		const textParts: string[] = [];
		for (const part of payload.content) {
			if (typeof part !== "object" || part === null) throw new Error(INCOMPLETE);
			const item = part as { type?: unknown; text?: unknown };
			if (item.type === "tool_use") throw new Error(INCOMPLETE);
			if (item.type === "text" && typeof item.text === "string") textParts.push(item.text);
		}
		const usage = payload.usage as { input_tokens?: unknown; output_tokens?: unknown } | undefined;
		const inputTokens = typeof usage?.input_tokens === "number" ? usage.input_tokens : 0;
		const outputTokens = typeof usage?.output_tokens === "number" ? usage.output_tokens : 0;
		return { text: textParts.join(""), inputTokens, outputTokens };
	}

	private async completeOpenAI(model: CatalogEntry, key: string | undefined, request: ModelRequest): Promise<ModelResponse> {
		const headers: Record<string, string> = { "content-type": "application/json" };
		if (key) headers.authorization = `Bearer ${key}`;
		const tokenField = model.provider === "openai" ? "max_completion_tokens" : "max_tokens";
		const body: Record<string, unknown> = {
			model: model.id,
			[tokenField]: request.maxOutputTokens,
			messages: [
				{ role: "system", content: request.system },
				{ role: "user", content: request.prompt },
			],
		};
		if (model.provider === "nebius" && request.schema) {
			body.response_format = {
				type: "json_schema",
				json_schema: {
					name: request.schema.name,
					strict: true,
					schema: request.schema.schema,
				},
			};
		}
		const payload = await this.post(
			`${model.baseUrl}/chat/completions`,
			headers,
			body,
			request.signal,
		);
		if (payload.error !== undefined) throw new Error(INCOMPLETE);
		if (!Array.isArray(payload.choices)) throw new Error(INCOMPLETE);
		const choice = payload.choices[0] as { finish_reason?: unknown; message?: unknown } | undefined;
		if (typeof choice !== "object" || choice === null) throw new Error(INCOMPLETE);
		if (choice.finish_reason !== "stop") throw new Error(INCOMPLETE);
		const message = choice.message as { content?: unknown; tool_calls?: unknown } | undefined;
		if (typeof message !== "object" || message === null) throw new Error(INCOMPLETE);
		if (message.tool_calls !== undefined && message.tool_calls !== null && (!Array.isArray(message.tool_calls) || message.tool_calls.length > 0)) {
			throw new Error(INCOMPLETE);
		}
		if (typeof message.content !== "string") throw new Error(INCOMPLETE);
		const usage = payload.usage as { prompt_tokens?: unknown; completion_tokens?: unknown } | undefined;
		const inputTokens = typeof usage?.prompt_tokens === "number" ? usage.prompt_tokens : 0;
		const outputTokens = typeof usage?.completion_tokens === "number" ? usage.completion_tokens : 0;
		return { text: message.content, inputTokens, outputTokens };
	}

	private async completeGemini(model: CatalogEntry, key: string | undefined, request: ModelRequest): Promise<ModelResponse> {
		const headers: Record<string, string> = { "content-type": "application/json" };
		if (key) headers["x-goog-api-key"] = key;
		const payload = await this.post(
			`${model.baseUrl}/v1beta/models/${encodeURIComponent(model.id)}:generateContent`,
			headers,
			{
				systemInstruction: { parts: [{ text: request.system }] },
				contents: [{ role: "user", parts: [{ text: request.prompt }] }],
				generationConfig: { maxOutputTokens: request.maxOutputTokens },
			},
			request.signal,
		);
		if (!Array.isArray(payload.candidates)) throw new Error(INCOMPLETE);
		const candidate = payload.candidates[0] as { finishReason?: unknown; content?: unknown } | undefined;
		if (typeof candidate !== "object" || candidate === null) throw new Error(INCOMPLETE);
		if (candidate.finishReason !== "STOP") throw new Error(INCOMPLETE);
		const content = candidate.content as { parts?: unknown } | undefined;
		if (typeof content !== "object" || content === null || !Array.isArray(content.parts)) throw new Error(INCOMPLETE);
		const textParts: string[] = [];
		for (const part of content.parts) {
			if (typeof part !== "object" || part === null) throw new Error(INCOMPLETE);
			const item = part as { text?: unknown; functionCall?: unknown };
			if (item.functionCall !== undefined) throw new Error(INCOMPLETE);
			if (typeof item.text === "string") textParts.push(item.text);
		}
		const usage = payload.usageMetadata as { promptTokenCount?: unknown; candidatesTokenCount?: unknown } | undefined;
		const inputTokens = typeof usage?.promptTokenCount === "number" ? usage.promptTokenCount : 0;
		const outputTokens = typeof usage?.candidatesTokenCount === "number" ? usage.candidatesTokenCount : 0;
		return { text: textParts.join(""), inputTokens, outputTokens };
	}
}

export function allModels(env?: NodeJS.ProcessEnv): ListedModel[] {
	return new ProviderClient({ env }).listModels();
}

export function createClient(_config: HarnessConfig, env?: NodeJS.ProcessEnv): ModelClient {
	return new ProviderClient({ env });
}
