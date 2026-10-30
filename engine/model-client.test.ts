import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ProviderClient } from "./model-client.ts";
import type { ModelRequest } from "./runner.ts";
import { parseConfig } from "./scope.ts";

function setup(models?: { hunter: { provider: string; id: string }; validator: { provider: string; id: string } }) {
	const hunter = models?.hunter ?? { provider: "minimax", id: "MiniMax-M2.7" };
	const validator = models?.validator ?? { provider: "minimax", id: "MiniMax-M3" };
	const config = parseConfig({
		version: 1,
		name: "adapter-contract",
		authorization: { reference: "test", expiresAt: "2099-01-01T00:00:00Z", allowRemoteModels: true },
		root: ".",
		files: ["app.ts"],
		domains: ["web2"],
		models: { recon: hunter, hunter, validator },
		limits: {
			maxCalls: 10,
			maxInputChars: 20000,
			maxOutputTokens: 4096,
			timeoutMs: 1000,
			concurrency: 1,
			passes: 1,
			maxFindingsPerTask: 3,
		},
	});
	const request: ModelRequest = {
		model: config.models.hunter,
		system: "Read-only test",
		prompt: "Return JSON",
		maxOutputTokens: 4096,
		signal: new AbortController().signal,
	};
	return { config, request };
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

test("adapter requires authorization, then completes without tools", async () => {
	const { config, request } = setup();
	const calls: unknown[] = [];
	const client = new ProviderClient({
		env: { MINIMAX_API_KEY: "mm-test" },
		fetch: async (input, init) => {
			calls.push({ url: String(input), body: JSON.parse(String(init?.body)) });
			return jsonResponse({
				stop_reason: "end_turn",
				content: [{ type: "text", text: '{"ok":true}' }],
				usage: { input_tokens: 3, output_tokens: 2 },
			});
		},
	});
	await assert.rejects(client.complete(request), /preflight/);
	await client.preflight(config);
	assert.equal((await client.complete(request)).text, '{"ok":true}');
	assert.equal(calls.length, 1);
	const call = calls[0] as { url: string; body: { model: string; max_tokens: number; messages: unknown } };
	assert.equal(call.url, "https://api.minimax.io/anthropic/v1/messages");
	assert.equal(call.body.model, "MiniMax-M2.7");
	assert.equal(call.body.max_tokens, 4096);
	config.authorization.allowRemoteModels = false;
	await assert.rejects(client.preflight(config), /not authorized/);
	await assert.rejects(client.complete(request), /preflight/);
});

test("adapter rejects truncated, errored and tool-bearing responses", async () => {
	const { config, request } = setup();
	const payloads = [
		{ stop_reason: "max_tokens", content: [{ type: "text", text: "{}" }] },
		{ type: "error", stop_reason: "end_turn", content: [{ type: "text", text: "provider-secret" }] },
		{ stop_reason: "end_turn", content: [{ type: "tool_use", name: "bash", input: { command: "no" } }] },
	];
	for (const payload of payloads) {
		const client = new ProviderClient({
			env: { MINIMAX_API_KEY: "mm-test" },
			fetch: async () => jsonResponse(payload),
		});
		await client.preflight(config);
		await assert.rejects(client.complete(request), /Incomplete/);
	}
});

test("adapter refuses oversized context before dispatch", async () => {
	const { config, request } = setup();
	let calls = 0;
	const client = new ProviderClient({
		env: { MINIMAX_API_KEY: "mm-test" },
		fetch: async () => {
			calls += 1;
			return jsonResponse({ stop_reason: "end_turn", content: [{ type: "text", text: "{}" }] });
		},
	});
	await client.preflight(config);
	await assert.rejects(client.complete({ ...request, prompt: "x".repeat(200000) }), /context budget/);
	assert.equal(calls, 0);
});

test("adapter scopes credentials per provider", async () => {
	const { config } = setup();
	const withoutLogin = new ProviderClient({ env: {}, readFile: () => undefined });
	await assert.rejects(withoutLogin.preflight(config), /No credentials for provider minimax/);
	const openaiOnly = new ProviderClient({ env: { OPENAI_API_KEY: "sk-test" }, readFile: () => undefined });
	await assert.rejects(openaiOnly.preflight(config), /No credentials for provider minimax/);
	const withEnv = new ProviderClient({ env: { MINIMAX_API_KEY: "mm-test" }, readFile: () => undefined });
	await withEnv.preflight(config);
	const withFile = new ProviderClient({
		env: {},
		homedir: "/tmp/harness-home",
		readFile: (path) =>
			path.endsWith("/.minimax-code/config.yaml")
				? "minimax_api:\n  apiKey: mm-from-file\n  baseURL: https://api.minimax.io/anthropic\n"
				: undefined,
	});
	await withFile.preflight(config);
	const cross = setup({
		hunter: { provider: "openai", id: "gpt-5" },
		validator: { provider: "anthropic", id: "claude-sonnet-4-5" },
	});
	const partial = new ProviderClient({ env: { OPENAI_API_KEY: "sk-test" }, readFile: () => undefined });
	await assert.rejects(partial.preflight(cross.config), /No credentials for provider anthropic/);
	const both = new ProviderClient({
		env: { OPENAI_API_KEY: "sk-test", ANTHROPIC_API_KEY: "sk-ant-test" },
		readFile: () => undefined,
	});
	await both.preflight(cross.config);
	const listed = withEnv.listModels();
	assert.ok(listed.some((entry) => entry.provider === "minimax" && entry.id === "MiniMax-M2.7"));
	assert.ok(listed.some((entry) => entry.provider === "minimax-cn" && entry.id === "MiniMax-M3"));
	assert.ok(listed.some((entry) => entry.provider === "openai" && entry.id === "gpt-4o"));
});

test("openai-chat transport posts chat completions and rejects bad shapes without leaking payloads", async () => {
	const { config, request } = setup({
		hunter: { provider: "openai", id: "gpt-5" },
		validator: { provider: "anthropic", id: "claude-sonnet-4-5" },
	});
	const calls: { url: string; headers: Record<string, string>; body: Record<string, unknown> }[] = [];
	const client = new ProviderClient({
		env: { OPENAI_API_KEY: "sk-test", ANTHROPIC_API_KEY: "sk-ant-test" },
		fetch: async (input, init) => {
			calls.push({
				url: String(input),
				headers: (init?.headers ?? {}) as Record<string, string>,
				body: JSON.parse(String(init?.body)),
			});
			return jsonResponse({
				choices: [{ finish_reason: "stop", message: { role: "assistant", content: '{"ok":true}', tool_calls: null } }],
				usage: { prompt_tokens: 3, completion_tokens: 2 },
			});
		},
	});
	await client.preflight(config);
	const response = await client.complete(request);
	assert.equal(response.text, '{"ok":true}');
	assert.equal(response.inputTokens, 3);
	assert.equal(response.outputTokens, 2);
	const call = calls[0];
	assert.equal(call.url, "https://api.openai.com/v1/chat/completions");
	assert.equal(call.headers.authorization, "Bearer sk-test");
	assert.equal(call.body.max_completion_tokens, 4096);
	assert.deepEqual(
		(call.body.messages as { role: string }[]).map((message) => message.role),
		["system", "user"],
	);
	const badPayloads = [
		{ choices: [{ finish_reason: "length", message: { role: "assistant", content: "{}" } }] },
		{ choices: [{ finish_reason: "stop", message: { role: "assistant", content: "{}", tool_calls: [{ id: "x" }] } }] },
		{ error: { message: "secret" } },
	];
	for (const payload of badPayloads) {
		const failing = new ProviderClient({
			env: { OPENAI_API_KEY: "sk-test", ANTHROPIC_API_KEY: "sk-ant-test" },
			fetch: async () => jsonResponse(payload),
		});
		await failing.preflight(config);
		const error = await failing.complete(request).then(
			() => undefined,
			(caught: unknown) => caught,
		);
		assert.ok(error instanceof Error);
		assert.match(error.message, /Incomplete/);
		assert.ok(!error.message.includes("secret"));
	}
});

test("openai provider honors OPENAI_BASE_URL", async () => {
	const { config, request } = setup({
		hunter: { provider: "openai", id: "gpt-4o" },
		validator: { provider: "openai", id: "o3-mini" },
	});
	let url = "";
	const client = new ProviderClient({
		env: { OPENAI_API_KEY: "sk-test", OPENAI_BASE_URL: "https://proxy.example.com/v1" },
		fetch: async (input) => {
			url = String(input);
			return jsonResponse({
				choices: [{ finish_reason: "stop", message: { role: "assistant", content: "{}" } }],
			});
		},
	});
	await client.preflight(config);
	await client.complete(request);
	assert.equal(url, "https://proxy.example.com/v1/chat/completions");
});

test("deepseek uses max_tokens on the openai-chat transport", async () => {
	const { config, request } = setup({
		hunter: { provider: "deepseek", id: "deepseek-chat" },
		validator: { provider: "deepseek", id: "deepseek-reasoner" },
	});
	let body: Record<string, unknown> | undefined;
	const client = new ProviderClient({
		env: { DEEPSEEK_API_KEY: "ds-test" },
		fetch: async (_input, init) => {
			body = JSON.parse(String(init?.body));
			return jsonResponse({
				choices: [{ finish_reason: "stop", message: { role: "assistant", content: "{}" } }],
			});
		},
	});
	await client.preflight(config);
	await client.complete(request);
	assert.equal(body?.max_tokens, 4096);
	assert.equal(body?.max_completion_tokens, undefined);
});

test("nebius uses its OpenAI-compatible endpoint, credentials, and catalog", async () => {
	const { config, request } = setup({
		hunter: { provider: "nebius", id: "nvidia/nemotron-3-super-120b-a12b" },
		validator: { provider: "nebius", id: "nvidia/Nemotron-3-Ultra-550b-a55b" },
	});
	const expectedModels = [
		{ id: "nvidia/Nemotron-3-Ultra-550b-a55b", contextWindow: 1048576, maxTokens: 32768 },
		{ id: "nvidia/nemotron-3-super-120b-a12b", contextWindow: 262144, maxTokens: 32768 },
		{ id: "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B", contextWindow: 262144, maxTokens: 32768 },
		{ id: "nvidia/Nemotron-3_5-Lightning", contextWindow: 1048576, maxTokens: 32768 },
		{ id: "openai/gpt-oss-120b", contextWindow: 131072, maxTokens: 32768 },
		{ id: "deepseek-ai/DeepSeek-V4-Pro", contextWindow: 131072, maxTokens: 32768 },
	];
	const withoutKey = new ProviderClient({ env: {}, readFile: () => undefined });
	const uncredentialed = withoutKey.listModels().filter((entry) => entry.provider === "nebius");
	assert.deepEqual(
		uncredentialed.map(({ id, contextWindow, maxTokens }) => ({ id, contextWindow, maxTokens })),
		expectedModels,
	);
	assert.ok(uncredentialed.every((entry) => !entry.hasCredentials));
	await assert.rejects(withoutKey.preflight(config), /set NEBIUS_API_KEY/);

	let url = "";
	let headers: Record<string, string> = {};
	let body: Record<string, unknown> = {};
	const client = new ProviderClient({
		env: { NEBIUS_API_KEY: "nb-test" },
		readFile: () => undefined,
		fetch: async (input, init) => {
			url = String(input);
			headers = (init?.headers ?? {}) as Record<string, string>;
			body = JSON.parse(String(init?.body));
			return jsonResponse({
				choices: [{ finish_reason: "stop", message: { role: "assistant", content: "{}" } }],
			});
		},
	});
	const schema = {
		name: "recon",
		schema: { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"], additionalProperties: false },
	};
	assert.ok(client.listModels().filter((entry) => entry.provider === "nebius").every((entry) => entry.hasCredentials));
	await client.preflight(config);
	await client.complete({ ...request, schema });
	assert.equal(url, "https://api.tokenfactory.nebius.com/v1/chat/completions");
	assert.equal(headers.authorization, "Bearer nb-test");
	assert.equal(body.model, "nvidia/nemotron-3-super-120b-a12b");
	assert.equal(body.max_tokens, 4096);
	assert.equal(body.max_completion_tokens, undefined);
	assert.deepEqual(body.response_format, {
		type: "json_schema",
		json_schema: {
			name: "recon",
			strict: true,
			schema: schema.schema,
		},
	});

	let overrideUrl = "";
	const overrideClient = new ProviderClient({
		env: { NEBIUS_API_KEY: "nb-test", NEBIUS_BASE_URL: "https://proxy.example.com/v1" },
		readFile: () => undefined,
		fetch: async (input) => {
			overrideUrl = String(input);
			return jsonResponse({
				choices: [{ finish_reason: "stop", message: { role: "assistant", content: "{}" } }],
			});
		},
	});
	await overrideClient.preflight(config);
	await overrideClient.complete(request);
	assert.equal(overrideUrl, "https://proxy.example.com/v1/chat/completions");
});

test("structured outputs are not sent to OpenAI, DeepSeek, or OpenAI-compatible providers", async () => {
	const schema = {
		name: "recon",
		schema: { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"], additionalProperties: false },
	};
	const cases = [
		{
			models: { hunter: { provider: "openai", id: "gpt-5" }, validator: { provider: "openai", id: "gpt-5-mini" } },
			env: { OPENAI_API_KEY: "oa-test" },
		},
		{
			models: {
				hunter: { provider: "deepseek", id: "deepseek-chat" },
				validator: { provider: "deepseek", id: "deepseek-reasoner" },
			},
			env: { DEEPSEEK_API_KEY: "ds-test" },
		},
		{
			models: {
				hunter: { provider: "openai-compatible", id: "local" },
				validator: { provider: "openai-compatible", id: "local-2" },
			},
			env: {
				HARNESS_OPENAI_COMPAT_BASE_URL: "http://127.0.0.1:11434/v1",
				HARNESS_OPENAI_COMPAT_MODELS: "local:32768:8192,local-2:32768:8192",
			},
		},
	];
	for (const { models, env } of cases) {
		const { config, request } = setup(models);
		let body: Record<string, unknown> = {};
		const client = new ProviderClient({
			env,
			readFile: () => undefined,
			fetch: async (_input, init) => {
				body = JSON.parse(String(init?.body));
				return jsonResponse({
					choices: [{ finish_reason: "stop", message: { role: "assistant", content: "{}" } }],
				});
			},
		});
		await client.preflight(config);
		await client.complete({ ...request, schema });
		assert.equal(body.response_format, undefined);
	}
});

test("gemini transport posts generateContent and rejects function calls and truncation", async () => {
	const { config, request } = setup({
		hunter: { provider: "google", id: "gemini-2.5-pro" },
		validator: { provider: "google", id: "gemini-2.5-flash" },
	});
	const calls: { url: string; headers: Record<string, string> }[] = [];
	const client = new ProviderClient({
		env: { GEMINI_API_KEY: "gm-test" },
		fetch: async (input, init) => {
			calls.push({ url: String(input), headers: (init?.headers ?? {}) as Record<string, string> });
			return jsonResponse({
				candidates: [{ finishReason: "STOP", content: { parts: [{ text: '{"ok":true}' }] } }],
				usageMetadata: { promptTokenCount: 3, candidatesTokenCount: 2 },
			});
		},
	});
	await client.preflight(config);
	const response = await client.complete(request);
	assert.equal(response.text, '{"ok":true}');
	assert.equal(response.inputTokens, 3);
	assert.equal(response.outputTokens, 2);
	assert.equal(
		calls[0].url,
		"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent",
	);
	assert.equal(calls[0].headers["x-goog-api-key"], "gm-test");
	const badPayloads = [
		{ candidates: [{ finishReason: "STOP", content: { parts: [{ functionCall: { name: "x" } }] } }] },
		{ candidates: [{ finishReason: "MAX_TOKENS", content: { parts: [{ text: "{}" }] } }] },
	];
	for (const payload of badPayloads) {
		const failing = new ProviderClient({
			env: { GEMINI_API_KEY: "gm-test" },
			fetch: async () => jsonResponse(payload),
		});
		await failing.preflight(config);
		await assert.rejects(failing.complete(request), /Incomplete/);
	}
});

test("openai-compatible provider appears only with a base URL and treats loopback as keyless-ok", async () => {
	const absent = new ProviderClient({ env: {}, readFile: () => undefined });
	assert.ok(!absent.listModels().some((entry) => entry.provider === "openai-compatible"));
	const loopbackEnv = {
		HARNESS_OPENAI_COMPAT_BASE_URL: "http://127.0.0.1:11434/v1",
		HARNESS_OPENAI_COMPAT_MODELS: "qwen2.5-coder:32768:8192",
	};
	const local = new ProviderClient({ env: loopbackEnv, readFile: () => undefined });
	const listed = local.listModels().find((entry) => entry.provider === "openai-compatible");
	assert.equal(listed?.id, "qwen2.5-coder");
	assert.equal(listed?.hasCredentials, true);
	const compat = setup({
		hunter: { provider: "openai-compatible", id: "qwen2.5-coder" },
		validator: { provider: "minimax", id: "MiniMax-M2.7" },
	});
	const calls: { url: string; headers: Record<string, string> }[] = [];
	const client = new ProviderClient({
		env: { ...loopbackEnv, MINIMAX_API_KEY: "mm-test" },
		readFile: () => undefined,
		fetch: async (input, init) => {
			calls.push({ url: String(input), headers: (init?.headers ?? {}) as Record<string, string> });
			return jsonResponse({
				choices: [{ finish_reason: "stop", message: { role: "assistant", content: "{}" } }],
			});
		},
	});
	await client.preflight(compat.config);
	await client.complete(compat.request);
	assert.equal(calls[0].url, "http://127.0.0.1:11434/v1/chat/completions");
	assert.equal(calls[0].headers.authorization, undefined);
	const remote = new ProviderClient({
		env: {
			HARNESS_OPENAI_COMPAT_BASE_URL: "https://openai.example.com/v1",
			HARNESS_OPENAI_COMPAT_MODELS: "qwen2.5-coder:32768:8192",
		},
		readFile: () => undefined,
	});
	const remoteListed = remote.listModels().find((entry) => entry.provider === "openai-compatible");
	assert.equal(remoteListed?.hasCredentials, false);
	const remoteClient = new ProviderClient({
		env: {
			HARNESS_OPENAI_COMPAT_BASE_URL: "https://openai.example.com/v1",
			HARNESS_OPENAI_COMPAT_MODELS: "qwen2.5-coder:32768:8192",
			MINIMAX_API_KEY: "mm-test",
		},
		readFile: () => undefined,
		fetch: async () => jsonResponse({}),
	});
	await assert.rejects(remoteClient.preflight(compat.config), /No credentials for provider openai-compatible/);
});

test("SECURITY_HARNESS_MODELS extends the catalog and skips unknown providers", async () => {
	const client = new ProviderClient({
		env: {
			MINIMAX_API_KEY: "mm-test",
			SECURITY_HARNESS_MODELS: JSON.stringify([
				{ provider: "anthropic", id: "claude-future", contextWindow: 1000000, maxTokens: 64000 },
				{ provider: "nebius", id: "vendor/future", contextWindow: 1000000, maxTokens: 64000 },
				{ provider: "nope", id: "ghost", contextWindow: 1000, maxTokens: 100 },
			]),
		},
		readFile: () => undefined,
	});
	const listed = client.listModels();
	assert.ok(listed.some((entry) => entry.provider === "anthropic" && entry.id === "claude-future"));
	assert.ok(listed.some((entry) => entry.provider === "nebius" && entry.id === "vendor/future"));
	assert.ok(!listed.some((entry) => entry.provider === "nope"));
});

test("agent provider lists coding agents only when BUGCLAW_AGENT_DIR is set", () => {
	const dir = mkdtempSync(join(tmpdir(), "bugclaw-agent-"));
	try {
		const without = new ProviderClient({ env: {}, readFile: () => undefined });
		assert.ok(!without.listModels().some((entry) => entry.provider === "agent"));
		const withDir = new ProviderClient({ env: { BUGCLAW_AGENT_DIR: dir }, readFile: () => undefined });
		const agent = withDir.listModels().find((entry) => entry.provider === "agent" && entry.id === "coding-agent");
		assert.equal(agent?.hasCredentials, true);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("listModels reports credential presence without exposing key material", () => {
	const key = "mm-super-secret-key";
	const client = new ProviderClient({ env: { MINIMAX_API_KEY: key }, readFile: () => undefined });
	const listed = client.listModels();
	for (const entry of listed) {
		assert.equal(typeof entry.hasCredentials, "boolean");
		assert.ok(!JSON.stringify(entry).includes(key));
	}
	assert.equal(listed.find((entry) => entry.provider === "minimax")?.hasCredentials, true);
	assert.equal(listed.find((entry) => entry.provider === "anthropic")?.hasCredentials, false);
});
