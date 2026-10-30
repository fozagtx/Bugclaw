import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { isIP } from "node:net";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { access, readFile, stat } from "node:fs/promises";
import { extname, join, resolve, sep } from "node:path";
import { EventEmitter } from "node:events";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { config } from "./config.ts";
import { NebiusClient } from "./nebius.ts";
import { scan } from "./scan.ts";
import { reproduce } from "./repro.ts";
import { Store } from "./store.ts";
import { evidencePath } from "./evidence.ts";
import { runnerImageTag } from "./sandbox.ts";
import { EngineStateBusyError, scanActivity } from "./activity.ts";
import { findingReport } from "./report.ts";

const exec = promisify(execFile);
const events = new Map<string, EventEmitter>();
type ServeOptions = { host?: string; tlsCert?: string; tlsKey?: string };
const signoffDescription = "Human signoff is available only through the HTTP API and is never an MCP tool.";
const tools = [
	{ name: "bugclaw_scan", description: `Scan only an authorized local source snapshot. ${signoffDescription}`, inputSchema: { type: "object", properties: { source: {type:"string"}, authorization: {type:"string"}, files: {type:"array",items:{type:"string"}}, domains:{type:"array",items:{type:"string"}} }, required:["source","authorization"] } },
	{ name: "bugclaw_status", description: `Get scan status and summary. ${signoffDescription}`, inputSchema: {type:"object",properties:{scanId:{type:"string"}},required:["scanId"]} },
	{ name: "bugclaw_candidates", description: `List candidates; candidate statuses are not human confirmation. ${signoffDescription}`, inputSchema: {type:"object",properties:{scanId:{type:"string"}},required:["scanId"]} },
	{ name: "bugclaw_reproduce", description: `Reproduce a candidate only inside a network-denied OpenShell sandbox; never claim confirmed. ${signoffDescription}`, inputSchema: {type:"object",properties:{scanId:{type:"string"},candidateId:{type:"string"},fix:{type:"boolean",description:"also generate and verify a fix; off by default"}},required:["scanId"]} },
	{ name: "bugclaw_evidence", description: `Read replayable evidence stored inside Bugclaw's data directory. ${signoffDescription}`, inputSchema: {type:"object",properties:{path:{type:"string"}},required:["path"]} },
];

function createMcp(store: Store) {
	const mcp = new McpServer({ name: "bugclaw", version: "0.1.0" }, { capabilities: { tools: {} } });
	mcp.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
	mcp.setRequestHandler(CallToolRequestSchema, async (request) => {
		const name = request.params.name;
		const args = (request.params.arguments ?? {}) as Record<string, any>;
		let result: unknown;
		if (name === "bugclaw_scan") {
			result = await scan({ source: args.source, authorization: args.authorization, files: args.files, domains: args.domains }, store);
		} else if (name === "bugclaw_status") result = store.scan(args.scanId);
		else if (name === "bugclaw_candidates") result = store.candidates(args.scanId);
		else if (name === "bugclaw_reproduce") result = await reproduce(args.scanId, args.candidateId, { store, fix: args.fix === true });
		else if (name === "bugclaw_evidence") {
			const path = evidencePath(config().dataDir, args.path);
			result = await readFile(path, "utf8");
		} else throw new Error(`Unknown tool ${name}; signoff is human-only and is not an MCP tool`);
		return { content: [{ type: "text", text: JSON.stringify(result) }] };
	});
	return mcp;
}

export async function serve(port = 8787, store = new Store(), options: ServeOptions = {}) {
	const host = options.host ?? "127.0.0.1";
	const { tlsCert, tlsKey } = options;
	if (Boolean(tlsCert) !== Boolean(tlsKey)) throw new Error("Both --tls-cert and --tls-key are required");
	const { mcpToken } = config();
	if (!isLoopbackHost(host) && !mcpToken) throw new Error("BUGCLAW_MCP_TOKEN is required to bind a non-loopback host");
	const mcpOnly = servesOnlyMcp(host);
	const handler = async (req: any, res: any) => {
		const rawPath = (req.url ?? "/").split("?", 1)[0] ?? "/";
		let decodedPath: string;
		try { decodedPath = decodeURIComponent(rawPath); } catch { return json(res, 404, { error: "not found" }); }
		if (decodedPath.split("/").includes("..")) return json(res, 404, { error: "not found" });
		const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
		if (mcpOnly && url.pathname !== "/mcp") return json(res, 404, { error: "not found" });
		if (url.pathname === "/mcp") {
			if (mcpToken && !hasBearerToken(req.headers.authorization, mcpToken)) {
				res.writeHead(401, { "content-type": "application/json", "www-authenticate": "Bearer" });
				res.end(JSON.stringify({ error: "unauthorized" }));
				return;
			}
			if (!mcpToken && !isLoopbackHost(hostnameFromHost(req.headers.host ?? ""))) {
				return json(res, 403, { error: "MCP without BUGCLAW_MCP_TOKEN is only served to loopback hosts" });
			}
			const mcp = createMcp(store);
			const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
			res.once("close", () => {
				void transport.close();
				void mcp.close();
			});
			await mcp.connect(transport);
			await transport.handleRequest(req,res);
			return;
		}
		try {
			if (req.method === "GET" && url.pathname === "/api/health") {
				const key = Boolean(process.env.NEBIUS_API_KEY);
				const current = config();
				let models: string[] = [];
				let modelError: string | undefined;
				if (key) try { models = await new NebiusClient().listModels(); } catch (e) { modelError = String(e); }
				const [openshell,docker,runner] = await Promise.all([
					exec("openshell",["status"]).then((r)=>r.stdout.includes("Connected")).catch(()=>false),
					exec("docker",["info"]).then(()=>true).catch(()=>false),
					runnerImageTag().then((tag)=>exec("docker",["image","inspect",tag])).then(()=>true).catch(()=>false),
				]);
				return json(res,200,{nebius:{keyPresent:key,modelsAvailable:models.length>0,modelError},openshell,docker,engine:await exists(current.engineDir),runnerImage:runner,env:{nebiusApiKey:key,nebiusBaseUrl:current.baseUrl,dataDirCustom:Boolean(process.env.BUGCLAW_DATA),mcpToken:Boolean(process.env.BUGCLAW_MCP_TOKEN)}});
			}
			if (req.method === "GET" && url.pathname === "/api/activity") {
				const value = url.searchParams.get("limit");
				const requested = value === null ? 20 : Number(value);
				const limit = Number.isFinite(requested) ? Math.max(1, Math.min(50, Math.trunc(requested))) : 20;
				return json(res,200,store.recentActivity(limit));
			}
			if (req.method === "GET" && url.pathname === "/api/scans") return json(res,200,store.scans());
			if (req.method === "POST" && url.pathname === "/api/scans") {
				const body = await readJson(req);
				if (typeof body.authorization !== "string" || !body.authorization.trim()) return json(res,400,{error:"authorization reference is required"});
				const emitter = new EventEmitter();
				const id = randomUUID();
				events.set(id,emitter);
				void scan({source:String(body.source),authorization:body.authorization,files:strings(body.files),domains:strings(body.domains),id},store,(event)=>emitter.emit("event",event)).then((result)=>emitter.emit("event",{type:"complete",result})).catch((error)=>emitter.emit("event",{type:"error",message:String(error)}));
				return json(res,202,{id,status:"queued"});
			}
			if (req.method === "GET" && url.pathname.endsWith("/events")) {
				const id = url.pathname.split("/")[3]!;
				res.writeHead(200,{"content-type":"text/event-stream","cache-control":"no-cache","connection":"keep-alive"});
				const emitter=events.get(id);
				const listener=(event:unknown)=>res.write(`data: ${JSON.stringify(event)}\n\n`);
				emitter?.on("event",listener);
				req.on("close",()=>emitter?.off("event",listener));
				return;
			}
			const activity = /^\/api\/scans\/([^/]+)\/activity$/.exec(url.pathname);
			if (req.method === "GET" && activity) {
				const scanId = decodeURIComponent(activity[1]!);
				if (!store.scan(scanId)) return json(res,404,{error:"scan not found"});
				try {
					return json(res,200,scanActivity(config().dataDir,scanId));
				} catch (error) {
					if (error instanceof EngineStateBusyError) return json(res,503,{error:"engine state busy, retry"});
					throw error;
				}
			}
			const scanReport = /^\/api\/scans\/([^/]+)\/report$/.exec(url.pathname);
			if (req.method === "GET" && scanReport) {
				const scanId = decodeURIComponent(scanReport[1]!);
				if (!store.scan(scanId)) return json(res,404,{error:"scan not found"});
				const output = join(config().dataDir,"scans",scanId,"engine-output");
				const [markdown,findingsDetail] = await Promise.all([
					readOptional(join(output,"report.md")),
					readOptional(join(output,"FINDINGS-DETAIL.md")),
				]);
				const findings = await Promise.all((store.candidates(scanId) as any[]).map(async (candidate) => ({
					candidateId: candidate.id,
					title: candidate.title,
					markdown: await findingReport(store, candidate.id),
				})));
				return json(res,200,{markdown,findingsDetail,findings});
			}
			const candidateReport = /^\/api\/candidates\/([^/]+)\/report$/.exec(url.pathname);
			if (req.method === "GET" && candidateReport) {
				const candidateId = decodeURIComponent(candidateReport[1]!);
				if (!store.candidate(candidateId)) return json(res,404,{error:"candidate not found"});
				return json(res,200,{markdown:await findingReport(store,candidateId)});
			}
			const detail = /^\/api\/scans\/([^/]+)$/.exec(url.pathname);
			if (req.method === "GET" && detail) {
				const row = store.scan(decodeURIComponent(detail[1]!)) as any;
				if (!row) return json(res,404,{error:"scan not found"});
				let report: unknown = null;
				try { if (row.report !== null) report = JSON.parse(row.report); } catch {}
				const candidates = store.candidates(row.id).map((candidate: any) => ({ ...candidate, data: JSON.parse(candidate.data) }));
				return json(res,200,{...row,report,candidates});
			}
			if (req.method === "GET" && url.pathname === "/api/candidates") return json(res,200,store.candidates(url.searchParams.get("scan") ?? undefined));
			const candidate = /^\/api\/candidates\/([^/]+)$/.exec(url.pathname);
			if (req.method === "GET" && candidate) {
				const row=store.candidate(decodeURIComponent(candidate[1]!));
				const attempts = row ? store.attempts(row.id).map((attempt: any) => ({ ...attempt, result: parseStoredResult(attempt.result) })) : [];
				return row ? json(res,200,{...row,data:JSON.parse(row.data),attempts,signoffs:store.signoffs(row.id)}) : json(res,404,{error:"candidate not found"});
			}
			const reproduceRoute = /^\/api\/candidates\/([^/]+)\/reproduce$/.exec(url.pathname);
			if (req.method === "POST" && reproduceRoute) {
				const row=store.candidate(decodeURIComponent(reproduceRoute[1]!));
				if (!row) return json(res,404,{error:"candidate not found"});
				void reproduce(row.scan_id,row.id,{store,fix:false}).catch((error)=>store.attempt(row.id,"reproduce",{status:"failed",reason:error instanceof Error?error.message:"reproduction failed"}));
				return json(res,202,{candidateId:row.id,status:"queued"});
			}
			const signoff = /^\/api\/candidates\/([^/]+)\/signoff$/.exec(url.pathname);
			if (req.method === "POST" && signoff) {
				const candidateId=decodeURIComponent(signoff[1]!);
				if (!store.candidate(candidateId)) return json(res,404,{error:"candidate not found"});
				const body=await readJson(req);
				if (!["confirmed","rejected"].includes(body.decision) || typeof body.note!=="string" || !body.note.trim()) return json(res,400,{error:"decision and note are required"});
				store.signoff(candidateId,body.decision,body.note);
				return json(res,201,{decision:body.decision,at:new Date().toISOString()});
			}
			if (req.method === "GET" && url.pathname.startsWith("/api/evidence/")) {
				const path=decodeURIComponent(url.pathname.slice("/api/evidence/".length));
				try { return json(res,200,{content:await readFile(evidencePath(config().dataDir,path),"utf8")}); }
				catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return json(res,404,{error:"evidence file not found"}); throw error; }
			}
			if (req.method === "GET" && url.pathname !== "/api" && !url.pathname.startsWith("/api/") && !url.pathname.startsWith("/mcp/")) {
				const webPath = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
				const webRoot = resolve("web");
				const file=resolve(webRoot,`.${webPath}`);
				if (file.startsWith(`${resolve("web")}${sep}`) && await exists(file)) {
					const content=await readFile(file);
					res.writeHead(200,{"content-type":mime(extname(file))});res.end(content);return;
				}
				const index=resolve(webRoot,"index.html");
				if (index.startsWith(`${resolve("web")}${sep}`) && await exists(index)) {
					const content=await readFile(index);
					res.writeHead(200,{"content-type":mime(extname(index))});res.end(content);return;
				}
			}
			return json(res,404,{error:"not found"});
		} catch (error) { return json(res,500,{error:error instanceof Error?error.message:"request failed"}); }
	};
	const server = tlsCert && tlsKey
		? createHttpsServer({ cert: await readFile(tlsCert), key: await readFile(tlsKey) }, handler)
		: createHttpServer(handler);
	await new Promise<void>((resolvePromise, reject) => {
		server.once("error", reject);
		server.listen(port, host, resolvePromise);
	});
	return { server, port, host, close: async()=>{await new Promise<void>((r)=>server.close(()=>r()));} };
}

async function exists(path:string){try{await access(path);return true;}catch{return false;}}
function strings(value:unknown){return Array.isArray(value)&&value.every((v)=>typeof v==="string")?value:undefined;}
function json(res:any,status:number,value:unknown){res.writeHead(status,{"content-type":"application/json"});res.end(JSON.stringify(value));}
async function readJson(req:any):Promise<any>{let data="";for await(const part of req)data+=part;return JSON.parse(data||"{}");}
async function readOptional(file:string):Promise<string|null>{
	try{return await readFile(file,"utf8");}
	catch(error){if((error as {code?:string}).code==="ENOENT")return null;throw error;}
}
function parseStoredResult(result: unknown) {
	if (typeof result !== "string") return result;
	try { return JSON.parse(result); } catch { return result; }
}
function isLoopbackHost(host: string) {
	const normalized = host.toLowerCase().replace(/^\[|\]$/g, "");
	if (normalized === "localhost" || normalized.endsWith(".localhost") || normalized === "::1") return true;
	return isIP(normalized) === 4 && Number(normalized.split(".", 1)[0]) === 127;
}
function hostnameFromHost(host: string) {
	const value = host.trim();
	if (value.startsWith("[")) {
		const end = value.indexOf("]");
		return end < 0 ? value : value.slice(1, end);
	}
	const colon = value.lastIndexOf(":");
	return colon >= 0 && value.indexOf(":") === colon ? value.slice(0, colon) : value;
}
function servesOnlyMcp(host: string) {
	return !isLoopbackHost(host);
}
function hasBearerToken(header: unknown, token: string) {
	if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
	const supplied = Buffer.from(header.slice("Bearer ".length));
	const expected = Buffer.from(token);
	return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}
function mime(ext:string){return ({".html":"text/html",".js":"text/javascript",".css":"text/css",".svg":"image/svg+xml",".png":"image/png",".woff2":"font/woff2",".json":"application/json"})[ext]??"application/octet-stream";}
