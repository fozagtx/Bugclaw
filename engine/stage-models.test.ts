import assert from "node:assert/strict";
import test from "node:test";
import {
	applyStageChoice,
	createStageModelPrompt,
	formatStagePrompt,
	parseStageChoice,
	STAGE_MODEL_ADVICE,
	suggestStageModels,
} from "./stage-models.ts";

const current = { provider: "provider-a", id: "model-small", contextWindow: 8_000 };
const hunter = { provider: "provider-a", id: "model-small" };
const validator = { provider: "provider-b", id: "model-mid", contextWindow: 32_000 };
const catalog = [
	current,
	validator,
	{ provider: "provider-c", id: "model-large", contextWindow: 200_000 },
	{ provider: "provider-b", id: "model-largest", contextWindow: 1_000_000 },
];

test("ranks live catalog entries by context window, one per other provider", () => {
	assert.deepEqual(suggestStageModels(catalog, hunter, validator), [
		{ provider: "provider-b", id: "model-largest" },
		{ provider: "provider-c", id: "model-large" },
	]);
});

test("skips catalog entries without credentials", () => {
	const keyed = catalog.map((entry) => ({ ...entry, hasCredentials: true }));
	keyed[2].hasCredentials = false;
	assert.deepEqual(suggestStageModels(keyed, hunter, validator), [
		{ provider: "provider-b", id: "model-largest" },
	]);
});

test("parses blank, numbered suggestions, and provider/id", () => {
	const suggestions = [{ provider: "provider-c", id: "model-large" }];
	assert.deepEqual(parseStageChoice("", hunter, suggestions, catalog), { model: hunter });
	assert.deepEqual(parseStageChoice("1", hunter, suggestions, catalog), {
		model: { provider: "provider-c", id: "model-large" },
	});
	assert.deepEqual(parseStageChoice("provider-b/model-largest", hunter, suggestions, catalog), {
		model: { provider: "provider-b", id: "model-largest" },
	});
	assert.equal("error" in parseStageChoice("9", hunter, suggestions, catalog), true);
	assert.equal("error" in parseStageChoice("missing/model", hunter, suggestions, catalog), true);
});

test("rejects using the same model for hunter and validator", () => {
	assert.throws(
		() => applyStageChoice("validator", hunter, { recon: hunter, hunter, validator }),
		/must be different/,
	);
	assert.deepEqual(
		applyStageChoice("validator", { provider: "provider-c", id: "model-large" }, { recon: hunter, hunter, validator }),
		{
			provider: "provider-c",
			id: "model-large",
		},
	);
});

test("interactive prompt asks to switch and keeps current on a non-TTY", async () => {
	const lines: string[] = [];
	const prompt = createStageModelPrompt({
		listModels: () => catalog,
		readLine: async () => {
			throw new Error("non-TTY must not read stdin");
		},
		writeLine: (line) => lines.push(line),
		tty: false,
	});
	const chosen = await prompt.choose({
		stage: "validate",
		role: "validator",
		current: validator,
		models: { recon: hunter, hunter, validator },
		catalog,
	});
	assert.deepEqual(chosen, validator);
	assert.ok(lines.some((line) => line.includes(STAGE_MODEL_ADVICE)));
	assert.ok(lines.some((line) => line.includes("not a TTY")));
});

test("TTY prompt accepts a suggestion and authorizes it", async () => {
	const authorized: string[] = [];
	const prompt = createStageModelPrompt({
		listModels: () => catalog,
		authorize: async (model) => {
			authorized.push(`${model.provider}/${model.id}`);
		},
		readLine: async () => "1",
		writeLine: () => {},
		tty: true,
	});
	const chosen = await prompt.choose({
		stage: "hunt",
		role: "hunter",
		current: hunter,
		models: { recon: hunter, hunter, validator },
		catalog,
	});
	assert.deepEqual(chosen, { provider: "provider-b", id: "model-largest" });
	assert.deepEqual(authorized, ["provider-b/model-largest"]);
	assert.match(
		formatStagePrompt(
			{
				stage: "hunt",
				role: "hunter",
				current: hunter,
				models: { recon: hunter, hunter, validator },
				catalog,
			},
			[{ provider: "provider-c", id: "model-large" }],
		),
		/STAGE HUNT/,
	);
});
