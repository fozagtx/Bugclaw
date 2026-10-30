import assert from "node:assert/strict";
import test from "node:test";
import {
	HARNESS_TOOL_NAMES,
	invertedIndexShortlist,
	parseDeclaredTools,
	peelTools,
	siblingTaskId,
	traceDependencies,
} from "./tools.ts";

test("peels optional tools from a model body without changing the payload keys", () => {
	const peeled = peelTools({
		coverage: "target.ts",
		findings: [],
		tools: [{ tool: "vdh.wishlist", reason: "Need a FreeBSD VM", need: "FreeBSD VM" }],
	});
	assert.deepEqual(peeled.body, { coverage: "target.ts", findings: [] });
	assert.equal(peeled.tools[0]?.tool, "vdh.wishlist");
	assert.deepEqual(peelTools({ coverage: "target.ts", findings: [] }).tools, []);
});

test("rejects unknown or oversized tool declarations", () => {
	assert.throws(() => parseDeclaredTools([{ tool: "shell", reason: "no" }]), /Unknown harness tool/);
	assert.throws(
		() => parseDeclaredTools(Array.from({ length: 9 }, () => ({ tool: "vdh.hunt", reason: "x" }))),
		/Invalid tools list/,
	);
	assert.ok(HARNESS_TOOL_NAMES.includes("vvs.judgment"));
	assert.ok(HARNESS_TOOL_NAMES.includes("vdh.reverify"));
	assert.ok(HARNESS_TOOL_NAMES.includes("pashov.xray"));
	assert.ok(HARNESS_TOOL_NAMES.includes("pashov.auditor"));
	assert.ok(HARNESS_TOOL_NAMES.includes("pashov.fizz"));
});

test("traces relative imports inside the snapshot and wishlists missing specs", () => {
	const traced = traceDependencies([
		{ path: "app.ts", content: `import { transfer } from "./lib";\nimport fs from "fs";\n` },
		{ path: "lib.ts", content: "export function transfer() { return 1; }\n" },
	]);
	assert.deepEqual(traced.edges, [{ fromPath: "app.ts", toPath: "lib.ts" }]);
	assert.ok(traced.missing.some((item) => item.includes("fs")));
});

test("shortlists VVS duplicates by file, boundary, and rare tokens", () => {
	const finding = (id: string, rootCause: string, trustBoundary: string) => ({
		id,
		clusterId: "same",
		finding: {
			trustBoundary,
			rootCause,
			evidence: [{ path: "target.ts" }],
		},
	});
	const pool = [
		finding("a", "missing ownership check on record", "tenant boundary"),
		finding("b", "missing ownership check on record row", "tenant boundary"),
		finding("c", "unrelated rounding", "other"),
	];
	const shortlist = invertedIndexShortlist(pool[0], pool);
	assert.equal(shortlist[0], "b");
	assert.equal(siblingTaskId("seed-one").startsWith("hunt:sibling:"), true);
});
