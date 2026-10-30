import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { corpusDir, corpusEnabled, corpusStatus, searchCorpus, syncCorpus } from "./corpus.ts";
import { evaluate } from "./evaluate.ts";
import { inspectNestedRuntime, nestedRuntimeWarning } from "./nested-runtime.ts";
import { LENSES } from "./prompts.ts";
import { loadInstalledMdpsec } from "./mdpsec.ts";
import { loadInstalledPashov } from "./pashov.ts";
import { createClient, allModels } from "./model-client.ts";
import { writeReports } from "./report.ts";
import { type HarnessReport, plan, runHarness, runIdentity } from "./runner.ts";
import { loadSnapshot, parseConfig } from "./scope.ts";
import { createStageModelPrompt } from "./stage-models.ts";
import { readRunStatus } from "./status.ts";
import { RunStore } from "./store.ts";
import { HARNESS_TOOLS } from "./tools.ts";

const HELP = `Bugclaw source-discovery engine worker.
Bugclaw invokes this worker for an authorized source snapshot.
  models                                List catalog models across providers with credential presence (offline)
  plan <scope.json>                      Validate YOUR scope and show planned work (offline)
  status <output-directory>              Summarize report.json from a finished run (offline)
  evaluate <report.json> <labels.json>   Score human-reviewed labels for YOUR report (offline)
  corpus status|sync|search <query.json> Web3 Audit Database prior-art corpus (sync downloads the pinned release)
  run <scope.json> <output-directory> --allow-remote-models [--keep-models]
                                        Send the scoped source to the provider models named in YOUR scope.json
                                        Prompts before recon, hunt, validate and gapfill unless --keep-models
Repeat the same run command to resume. Changed scope/source/prompts require a new output directory.
Exit codes: 0 completed, 1 configuration/runtime error, 2 incomplete pipeline.
Nebius Token Factory reads NEBIUS_API_KEY; NEBIUS_BASE_URL optionally overrides its public default.
No target network requests, shell tools, test execution, transactions or automatic disclosure.
There is no demo, mock client, or canned target.
VDH stages (recon, hunt, validate, gapfill, dedup, trace, feedback, report, sibling, wishlist) and VVS stages (dedup, judgment, fixing) are tools the agent may declare at any time. The harness runs them; models cannot execute tools, patches, or tests.
The Bugclaw application owns reproduction, sandbox execution and human signoff.`;

const SAFE_ERROR_PREFIXES = [
	"Invalid engine configuration:",
	"Unsafe snapshot",
	"Snapshot ",
	"Output must be outside the source root",
	"Remote model transmission is not authorized",
	"Authorization expired",
	"Configured model is absent from the installed catalog",
	"Output budget exceeds model capability",
	"No credentials for provider ",
	"Model context budget exceeded",
	"engine run store:",
	"Corpus ",
];

let operation = "command parsing";
let argvPaths: string[] = [];

async function main(): Promise<void> {
	const [command, ...args] = process.argv.slice(2);
	argvPaths = args.map((arg) => resolve(arg));
	if (!command || command === "--help") {
		console.log(HELP);
		return;
	}
	if (command === "models" && args.length === 0) {
		console.log(JSON.stringify(allModels(), null, 2));
		return;
	}
	if (command === "evaluate" && args.length === 2) {
		operation = "benchmark label validation";
		const report: HarnessReport = JSON.parse(await readFile(resolve(args[0]), "utf8"));
		const labels: unknown = JSON.parse(await readFile(resolve(args[1]), "utf8"));
		console.log(JSON.stringify(evaluate(report, labels), null, 2));
		return;
	}
	if (command === "corpus" && (args[0] === "status" || args[0] === "sync") && args.length === 1) {
		operation = "corpus";
		const dir = corpusDir();
		console.log(JSON.stringify(args[0] === "sync" ? await syncCorpus(dir) : corpusStatus(dir), null, 2));
		return;
	}
	if (command === "corpus" && args[0] === "search" && args.length === 2) {
		operation = "corpus";
		const query = JSON.parse(args[1]!) as Record<string, unknown>;
		const list = (value: unknown) =>
			Array.isArray(value) ? value.map(String) : typeof value === "string" && value.trim() ? [value] : undefined;
		console.log(
			JSON.stringify(
				await searchCorpus(corpusDir(), {
					text: typeof query.query === "string" ? query.query : undefined,
					leaves: list(query.leaf),
					severities: list(query.severity),
					languages: list(query.language),
					project: typeof query.project === "string" ? query.project : undefined,
					limit: typeof query.limit === "number" ? query.limit : undefined,
				}),
				null,
				2,
			),
		);
		return;
	}
	if (command === "status" && args.length === 1) {
		operation = "run status";
		console.log(JSON.stringify(await readRunStatus(resolve(args[0])), null, 2));
		return;
	}
	if (
		!(
			(command === "plan" && args.length === 1) ||
			(command === "run" &&
				(args.length === 3 || (args.length === 4 && args[3] === "--keep-models")) &&
				args[2] === "--allow-remote-models")
		)
	)
		throw new Error(HELP);
	const configPath = resolve(args[0]);
	operation = "scope validation";
	const config = parseConfig(JSON.parse(await readFile(configPath, "utf8")));
	operation = "source snapshot validation";
	const snapshot = await loadSnapshot(config, dirname(configPath));
	if (command === "plan") {
		const tasks = plan(config);
		const nestedRuntime = inspectNestedRuntime();
		const warning = nestedRuntimeWarning(nestedRuntime);
		if (warning) console.error(warning);
		console.log(
			JSON.stringify(
				{
					identity: runIdentity(config, snapshot),
					snapshot: snapshot.digest,
					files: snapshot.files.map(({ path, sha256, lines }) => ({ path, sha256, lines })),
					tools: HARNESS_TOOLS,
					vdh: {
						recon: ["recon:architecture", "recon:threats", "recon:invariants", "recon"],
						hunts: tasks.map(({ id }) => id),
						then: ["vdh.validate", "vdh.gapfill", "vdh.dedup", "vdh.trace", "vdh.feedback", "vdh.report"],
						agentDeclared: ["vdh.sibling", "vdh.wishlist"],
					},
					vvs: ["vvs.dedup", "vvs.judgment", "vvs.fixing"],
					pashov: loadInstalledPashov(),
					mdpsec: loadInstalledMdpsec(),
					pashovMapped: {
						"x-ray": ["recon:architecture", "recon:threats", "recon:invariants", "recon"],
						"solidity-auditor": Object.keys(LENSES.web3).map((id) => `hunt:web3:${id}:0`),
						fizz: config.domains.includes("web3") ? ["pashov.fizz"] : [],
					},
					hunts: tasks.map(({ id }) => id),
					baseCalls: 4 + (config.domains.includes("web3") ? 1 : 0) + tasks.length,
					maximumTasksIncludingValidation:
						4 + (config.domains.includes("web3") ? 1 : 0) + tasks.length * (2 + config.limits.maxFindingsPerTask) + 8,
					hardCallCap: config.limits.maxCalls,
					nestedRuntime,
					note: "Pashov x-ray is VDH recon (three passes plus synthesis). Pashov solidity-auditor is twelve web3 hunt cells. Pashov fizz proposes invariant properties and is never executed. Recon may add extra attack-class hunts. Empty cells are gapfilled once. Agents may declare VDH/VVS/Pashov tools at any time; the harness runs them. VVS uses a different model than VDH. Independent validation cannot file findings. Patches are never applied. Hunt passes run in sequence and each later pass receives the findings earlier passes already reported.",
					warning:
						"Plan makes no model calls. Scope is an operator attestation, not proof of program authorization.",
				},
				null,
				2,
			),
		);
		return;
	}
	const output = resolve(args[1]);
	operation = "output directory validation";
	const outputWithinSource = relative(snapshot.root, output);
	if (
		!isAbsolute(outputWithinSource) &&
		outputWithinSource !== ".." &&
		!outputWithinSource.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)
	) {
		throw new Error("Output must be outside the source root");
	}
	const client = createClient(config);
	operation = "model authorization and credential preflight";
	await client.preflight(config);
	operation = "run identity and private database initialization";
	const store = new RunStore(output, runIdentity(config, snapshot));
	const keepModels = command === "run" && args[3] === "--keep-models";
	const tty = Boolean(process.stdin.isTTY);
	let rl: ReturnType<typeof createInterface> | undefined;
	const prompt =
		!keepModels
			? createStageModelPrompt({
					listModels: () => client.listModels(),
					authorize: (model) => client.authorize(model, config),
					readLine: async () => {
						rl ??= createInterface({ input: process.stdin, output: process.stderr });
						return rl.question("> ");
					},
					writeLine: (line) => console.error(line),
					tty,
				})
			: undefined;
	try {
		operation = "investigation pipeline";
		const report = await runHarness(config, snapshot, store, client, {
			prompt,
			catalog: client.listModels(),
			corpusDir: corpusEnabled() ? corpusDir() : null,
			tavilyApiKey: process.env.TAVILY_API_KEY ?? null,
		});
		operation = "private report writing";
		writeReports(output, report);
		const nestedWarning = nestedRuntimeWarning(report.nestedRuntime);
		if (nestedWarning) console.error(nestedWarning);
		console.log(`${report.status}; ${report.candidates.length} candidates; 0 verified findings. Reports: ${output}`);
		if (report.status === "incomplete") process.exitCode = 2;
	} finally {
		rl?.close();
		store.close();
	}
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : "";
	if (message === HELP) {
		process.stderr.write(HELP);
		process.exitCode = 1;
		return;
	}
	console.error(
		`Bugclaw engine failed during ${operation}. No private error payload was logged. Check the Bugclaw README and task ledger; use --help for syntax.`,
	);
	const errorRecord =
		error && typeof error === "object"
			? (error as { code?: unknown; path?: unknown })
			: {};
	const pathOperation = new Set([
		"scope validation",
		"source snapshot validation",
		"output directory validation",
		"run status",
		"benchmark label validation",
	]);
	const missingPath =
		errorRecord.code === "ENOENT" &&
		typeof errorRecord.path === "string" &&
		pathOperation.has(operation) &&
		argvPaths.find((candidate) => candidate === errorRecord.path);
	if (missingPath) {
		console.error(`Reason: file not found: ${missingPath}`);
	} else if (error instanceof SyntaxError && operation === "scope validation") {
		console.error("Reason: scope.json is not valid JSON");
	} else if (SAFE_ERROR_PREFIXES.some((prefix) => message.startsWith(prefix))) {
		console.error(`Reason: ${message}`);
	}
	process.exitCode = 1;
});
