import { setTimeout as delay } from "node:timers/promises";
import { config } from "./config.ts";

export class NebiusClient {
	private readonly env: NodeJS.ProcessEnv;
	private readonly fetcher: typeof fetch;

	constructor(env: NodeJS.ProcessEnv = process.env, fetcher: typeof fetch = globalThis.fetch) {
		this.env = env;
		this.fetcher = fetcher;
	}

	private async request(url: string, init: RequestInit): Promise<Response> {
		if (!this.env.NEBIUS_API_KEY) throw new Error("NEBIUS_API_KEY is required");
		for (let attempt = 0; attempt < 2; attempt++) {
			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), 600_000);
			try {
				const response = await this.fetcher(url, {
					...init,
					headers: { authorization: `Bearer ${this.env.NEBIUS_API_KEY}`, ...init.headers },
					signal: controller.signal,
				});
				if (attempt === 0 && (response.status === 429 || response.status >= 500)) {
					await delay(1000);
					continue;
				}
				return response;
			} finally {
				clearTimeout(timer);
			}
		}
		throw new Error("Nebius request failed after one retry");
	}

	async complete(model: string, system: string, prompt: string, schema?: { name: string; schema: Record<string, unknown> }) {
		const { baseUrl } = config(this.env);
		const body: Record<string, unknown> = {
			model: model.replace(/^nebius\//, ""),
			max_tokens: 16000,
			messages: [{ role: "system", content: system }, { role: "user", content: prompt }],
		};
		if (schema) {
			body.response_format = {
				type: "json_schema",
				json_schema: { name: schema.name, strict: true, schema: schema.schema },
			};
		}
		const response = await this.request(`${baseUrl}/chat/completions`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});
		if (!response.ok) throw new Error(`Nebius HTTP ${response.status}`);
		return parseChatResponse(await response.json());
	}

	async listModels(): Promise<string[]> {
		const { baseUrl } = config(this.env);
		const response = await this.request(`${baseUrl}/models`, { method: "GET" });
		if (!response.ok) throw new Error(`Nebius models HTTP ${response.status}`);
		const payload = await response.json() as { data?: Array<{ id?: unknown }> };
		return (payload.data ?? []).flatMap((item) => typeof item.id === "string" ? [item.id] : []);
	}
}

export function parseChatResponse(payload: any) {
	const choice = payload?.choices?.[0];
	const message = choice?.message;
	if (choice?.finish_reason !== "stop" || !message || (message.tool_calls != null && (!Array.isArray(message.tool_calls) || message.tool_calls.length))) {
		throw new Error("Nebius returned an incomplete or tool-bearing response");
	}
	if (typeof message.content !== "string") throw new Error("Nebius response has no content");
	return { value: firstJson(message.content), inputTokens: payload.usage?.prompt_tokens ?? 0, outputTokens: payload.usage?.completion_tokens ?? 0 };
}

export function firstJson(text: string): Record<string, unknown> {
	const start = text.indexOf("{");
	if (start < 0) throw new Error("No JSON object in model response");
	let depth = 0;
	let string = false;
	let escape = false;
	for (let i = start; i < text.length; i++) {
		const char = text[i]!;
		if (string) {
			if (escape) escape = false;
			else if (char === "\\") escape = true;
			else if (char === '"') string = false;
		} else if (char === '"') string = true;
		else if (char === "{") depth++;
		else if (char === "}" && --depth === 0) {
			const result = JSON.parse(text.slice(start, i + 1));
			if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("Expected JSON object");
			return result;
		}
	}
	throw new Error("Incomplete JSON object");
}
