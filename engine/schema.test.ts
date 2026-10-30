import assert from "node:assert/strict";
import { test } from "node:test";
import { FINDING_KEYS, STAGE_KEYS, STAGE_SCHEMAS, parseVerdict } from "./schema.ts";
import { HARNESS_TOOL_NAMES, OPTIONAL_TOOL_KEYS } from "./tools.ts";

for (const name of Object.keys(STAGE_KEYS) as (keyof typeof STAGE_KEYS)[]) {
	test(`${name} schema required keys match its parser`, () => {
		const stage =
			name === "hunt"
				? STAGE_SCHEMAS.hunt(5)
				: name === "judgment" || name === "reverify" || name === "verdict"
					? STAGE_SCHEMAS[name]()
					: STAGE_SCHEMAS[name];
		assert.deepEqual(stage.schema.required, STAGE_KEYS[name]);
		assert.equal(stage.schema.additionalProperties, false);
		const properties = stage.schema.properties as Record<string, unknown>;
		assert.ok(properties.tools);
		assert.ok(!(stage.schema.required as string[]).includes("tools"));
	});
}

test("finding schema properties follow the parser's required key order and limits", () => {
	const hunt = STAGE_SCHEMAS.hunt(7).schema;
	const properties = hunt.properties as Record<string, unknown>;
	const findings = properties.findings as {
		maxItems: number;
		items: { properties: Record<string, unknown>; required: string[]; additionalProperties: boolean };
	};
	assert.equal(findings.maxItems, 7);
	assert.deepEqual(Object.keys(findings.items.properties), FINDING_KEYS);
	assert.deepEqual(findings.items.required, FINDING_KEYS);
	assert.equal(findings.items.additionalProperties, false);
	const severity = findings.items.properties.severity as { enum: string[] };
	assert.deepEqual(severity.enum, ["critical", "high", "medium", "low"]);
});

test("recon and tools schemas constrain the reported parser shapes", () => {
	const recon = STAGE_SCHEMAS.recon.schema.properties as Record<string, unknown>;
	const entryPoints = recon.entryPoints as { minItems: number; maxItems: number };
	assert.equal(entryPoints.minItems, 1);
	assert.equal(entryPoints.maxItems, 40);
	const attackClasses = recon.attackClasses as {
		maxItems: number;
		items: { properties: Record<string, unknown> };
	};
	assert.equal(attackClasses.maxItems, 6);
	assert.deepEqual(attackClasses.items.properties.id, {
		type: "string",
		minLength: 1,
		maxLength: 40,
		pattern: "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$",
	});

	const toolSchema = recon.tools as {
		maxItems: number;
		items: { properties: Record<string, unknown>; required: string[]; additionalProperties: boolean };
	};
	assert.equal(toolSchema.maxItems, 8);
	assert.deepEqual(toolSchema.items.required, ["tool", "reason"]);
	assert.equal(toolSchema.items.additionalProperties, false);
	assert.deepEqual((toolSchema.items.properties.tool as { enum: string[] }).enum, HARNESS_TOOL_NAMES);
	for (const key of OPTIONAL_TOOL_KEYS) assert.ok(key in toolSchema.items.properties);
});

test("text schemas do not use full-match regular expressions", () => {
	const recon = STAGE_SCHEMAS.recon.schema.properties as Record<string, unknown>;
	assert.deepEqual(recon.summary, { type: "string", minLength: 1, maxLength: 8000 });
});

test("citation schemas restrict paths to the current source snapshot", () => {
	const snapshot = {
		root: "/scope",
		digest: "hash",
		files: [{ path: "src/login.js", content: "line", sha256: "hash", lines: 1 }],
	};
	const hunt = STAGE_SCHEMAS.hunt(5, snapshot).schema.properties as Record<string, unknown>;
	const findings = hunt.findings as { items: { properties: Record<string, unknown> } };
	const findingEvidence = findings.items.properties.evidence as {
		items: { properties: Record<string, unknown> };
	};
	const citationPath = findingEvidence.items.properties.path as { enum: string[] };
	assert.deepEqual(citationPath.enum, ["src/login.js"]);
	for (const stage of [STAGE_SCHEMAS.judgment(snapshot), STAGE_SCHEMAS.reverify(snapshot), STAGE_SCHEMAS.verdict(snapshot)]) {
		const properties = stage.schema.properties as Record<string, unknown>;
		const evidence = properties.evidence as { items: { properties: Record<string, unknown> } };
		assert.deepEqual((evidence.items.properties.path as { enum: string[] }).enum, ["src/login.js"]);
	}
});

test("citation normalization accepts quote punctuation and whitespace variants but returns source text", () => {
	const actual = 'const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, "secret123");';
	const content = `${"\n".repeat(16)}${actual}`;
	const snapshot = {
		root: "/snapshot",
		digest: "snapshot",
		files: [{ path: "login.js", content, sha256: "hash", lines: 17 }],
	};
	const parse = (quote: string, path = "login.js", startLine = 17, endLine = 17) => parseVerdict({
		verdict: "supported",
		reason: "The source line supports the claim.",
		evidence: [{ path, startLine, endLine, quote }],
		missingContext: [],
	}, snapshot);
	const swappedQuotes = parse("const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, 'secret123');");
	assert.equal(swappedQuotes.evidence[0]?.quote, actual);

	const multiline = 'const token = jwt.sign({ id: rows[0].id,\n  role: rows[0].role }, "secret123");';
	const multilineSnapshot = {
		...snapshot,
		files: [{ path: "login.js", content: multiline, sha256: "hash", lines: 2 }],
	};
	const normalized = parseVerdict({
		verdict: "supported",
		reason: "The source lines support the claim.",
		evidence: [{ path: "login.js", startLine: 1, endLine: 2, quote: 'const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, "secret123");' }],
		missingContext: [],
	}, multilineSnapshot);
	assert.equal(normalized.evidence[0]?.quote, multiline);

	assert.throws(() => parse("jwt sign"), /Evidence quote does not match cited lines/);
	assert.throws(() => parse("const user = session.load();"), /Evidence quote does not match cited lines/);
	assert.throws(() => parse("const token = jwt.sign({ id: rows[0].id }, \"secret123\");", "outside.js"), /outside the source snapshot/);
});

test("citation schema describes quote normalization", () => {
	const evidence = (STAGE_SCHEMAS.verdict().schema.properties as Record<string, any>).evidence;
	assert.equal(evidence.items.properties.quote.description, "Source text of the cited lines (the harness replaces it with the exact file text).");
});
