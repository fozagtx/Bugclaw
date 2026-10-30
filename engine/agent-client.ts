import { randomUUID } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, writeFileSync, existsSync, unlinkSync } from "node:fs";
import { env } from "node:process";
import type { ModelClient, ModelRequest, ModelResponse } from "./runner.ts";
import type { HarnessConfig, ModelRef } from "./scope.ts";

export interface AgentClientOptions {
	env?: NodeJS.ProcessEnv;
}

export class AgentClient implements ModelClient {
	private authorized = false;
	private readonly env: NodeJS.ProcessEnv;
	private readonly agentDir: string;

	constructor(options: AgentClientOptions = {}) {
		this.env = options.env ?? env;
		const dir = this.env.BUGCLAW_AGENT_DIR?.trim();
		if (!dir) throw new Error("Set BUGCLAW_AGENT_DIR to a directory where the coding agent reads prompts and writes responses");
		this.agentDir = dir;
		mkdirSync(this.agentDir, { recursive: true });
	}

	listModels(): { provider: string; id: string; contextWindow: number; maxTokens: number }[] {
		return [
			{ provider: "agent", id: "coding-agent", contextWindow: 1_000_000, maxTokens: 100_000 },
			{ provider: "agent", id: "coding-agent-2", contextWindow: 1_000_000, maxTokens: 100_000 },
		];
	}

	async preflight(config: HarnessConfig): Promise<void> {
		this.authorized = false;
		if (!config.authorization.allowRemoteModels) throw new Error("Remote model transmission is not authorized");
		if (Date.parse(config.authorization.expiresAt) <= Date.now()) throw new Error("Authorization expired");
		for (const ref of Object.values(config.models)) this.assertUsable(ref);
		this.authorized = true;
	}

	async authorize(ref: ModelRef): Promise<void> {
		if (!this.authorized) throw new Error("Remote model preflight is required");
		this.assertUsable(ref);
	}

	private assertUsable(ref: ModelRef): void {
		if (ref.provider !== "agent") {
			throw new Error("Configured model is absent from the installed catalog; use the models command");
		}
	}

	async complete(request: ModelRequest): Promise<ModelResponse> {
		if (!this.authorized) throw new Error("Remote model preflight is required");
		const id = randomUUID();
		const promptPath = `${this.agentDir}/prompt-${id}.json`;
		const responsePath = `${this.agentDir}/response-${id}.txt`;
		writeFileSync(
			promptPath,
			JSON.stringify(
				{
					id,
					system: request.system,
					prompt: request.prompt,
					maxOutputTokens: request.maxOutputTokens,
				},
				null,
				2,
			),
			"utf8",
		);
		while (!existsSync(responsePath)) {
			if (request.signal?.aborted) throw new Error("timeout");
			await new Promise((resolve) => setTimeout(resolve, 500));
		}
		const text = readFileSync(responsePath, "utf8");
		try {
			unlinkSync(promptPath);
			unlinkSync(responsePath);
		} catch {}
		return { text, inputTokens: 0, outputTokens: 0 };
	}
}
