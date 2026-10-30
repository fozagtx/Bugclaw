import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
	citedLinesAreCode,
	enclosingScope,
	huntLooksCrashed,
	mechanicalFixCheck,
	proposalLooksLikeCode,
	vacuousFinding,
} from "./mechanical.ts";
import type { Finding } from "./schema.ts";
import type { SourceFile } from "./scope.ts";

function file(path: string, content: string): SourceFile {
	return {
		path,
		content,
		sha256: createHash("sha256").update(content).digest("hex"),
		lines: content.split("\n").length,
	};
}

function sample(overrides: Partial<Finding> = {}): Finding {
	return {
		title: "Unbounded argument",
		severity: "high",
		attacker: "An untrusted caller",
		intentBroken: "Transfer amounts stay bounded",
		attackClass: "state-and-business-logic",
		preconditions: ["Caller reaches transfer"],
		trustBoundary: "caller to transfer",
		rootCause: "Amount is not bounded before transfer.",
		impact: "A caller can request an excessive amount",
		reproduction: ["Create a local unit test", "Call transfer with a large amount"],
		remediation: "Validate the amount",
		evidence: [],
		...overrides,
	};
}

test("enclosingScope and code-line checks follow the cited function", () => {
	const source = file("target.ts", "export function transfer(owner: string, amount: number) { return amount; }\n// comment only\n");
	assert.equal(enclosingScope(source, 1), "transfer");
	assert.equal(citedLinesAreCode(source, 1, 1), true);
	assert.equal(citedLinesAreCode(source, 2, 2), false);
});

test("vacuousFinding rejects tautologies and thin potential claims", () => {
	assert.equal(vacuousFinding(sample()), null);
	assert.equal(
		vacuousFinding(sample({ impact: "An attacker could theoretically cause an error", rootCause: "maybe" })),
		"vacuous-potential",
	);
	assert.equal(vacuousFinding(sample({ reproduction: ["one step"] })), "vacuous-thin-claim");
});

test("mechanicalFixCheck requires parseable patch and test text, not a tautology", () => {
	assert.equal(proposalLooksLikeCode("exec() executes things, therefore critical vulnerability"), false);
	assert.doesNotThrow(() =>
		mechanicalFixCheck(
			"function transfer(owner, amount) {\n  if (amount > 0) return amount;\n}\n",
			"function test() {\n  assert.equal(1, 1);\n}\n",
		),
	);
	assert.throws(() => mechanicalFixCheck("please fix it", "run the test"));
});

test("huntLooksCrashed is a near-empty hunter with no forks, not a normal empty cell", () => {
	assert.equal(huntLooksCrashed(0, 0, false), true);
	assert.equal(huntLooksCrashed(7, 0, false), false);
	assert.equal(huntLooksCrashed(0, 0, true), false);
});
