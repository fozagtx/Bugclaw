import assert from "node:assert/strict";
import test from "node:test";
import { extractJsonObject, isProviderErrorPayload } from "./json.ts";

test("extracts a JSON object from fenced or padded model bodies", () => {
	assert.deepEqual(extractJsonObject('{"ok":true}'), { ok: true });
	assert.deepEqual(extractJsonObject('```json\n{"ok":true}\n```'), { ok: true });
	assert.deepEqual(extractJsonObject('Here:\n{"ok":true}\nThanks'), { ok: true });
	assert.throws(() => extractJsonObject("not json"), /not a JSON object/);
});

test("classifies HTTP-success provider error payloads", () => {
	assert.equal(isProviderErrorPayload({ error: "rate limited" }), true);
	assert.equal(isProviderErrorPayload({ findings: [], coverage: "x" }), false);
	assert.equal(isProviderErrorPayload({ summary: "arch", error: "ignore if recon" }), false);
	assert.equal(isProviderErrorPayload("error"), false);
});
