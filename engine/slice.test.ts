import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { sliceBudget, sliceSource } from "./slice.ts";
import type { Snapshot, SourceFile } from "./scope.ts";

function file(path: string, content: string): SourceFile {
	return {
		path,
		content,
		sha256: createHash("sha256").update(content).digest("hex"),
		lines: content.split("\n").length,
	};
}

function snapshot(files: SourceFile[]): Snapshot {
	return { root: "/tmp", digest: "d", files };
}

test("sliceSource keeps preferred files and lists omitted paths instead of stuffing the window", () => {
	const small = file("auth.ts", "export function login() { return true; }\n");
	const noise = file("vendor.ts", `${"padding\n".repeat(400)}export const unused = 1;\n`);
	const result = sliceSource(snapshot([small, noise]), {
		prefer: ["auth.ts"],
		lens: "authentication sessions tenant isolation",
		maxChars: 800,
	});
	assert.deepEqual(result.included, ["auth.ts"]);
	assert.deepEqual(result.omitted, ["vendor.ts"]);
	assert.match(result.source, /FILE: auth\.ts/);
	assert.doesNotMatch(result.source, /FILE: vendor\.ts/);
});

test("sliceSource skips a huge non-preferred file rather than filling the window with it", () => {
	const small = file("auth.ts", "export function login() { return true; }\n");
	const noise = file("vendor.ts", `${"padding\n".repeat(400)}export const unused = 1;\n`);
	const result = sliceSource(snapshot([noise, small]), { maxChars: 800 });
	assert.deepEqual(result.included, ["auth.ts"]);
	assert.deepEqual(result.omitted, ["vendor.ts"]);
});

test("sliceBudget stays at most half the input cap and about a quarter of the model window", () => {
	assert.equal(sliceBudget(20_000), 10_000);
	assert.ok(sliceBudget(2_000_000, 8_000) < 8_000 * 0.25 * 4);
});
