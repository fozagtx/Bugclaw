import { scan } from "../src/scan.ts";
import { reproduce } from "../src/repro.ts";
import { serve } from "../src/server.ts";

const [command, ...args] = process.argv.slice(2);
async function main() {
	if (command === "scan") {
		const source=args[0];let authorization="";let files:string[]|undefined;let domains:string[]|undefined;
		for(let i=1;i<args.length;i++){if(args[i]==="--auth")authorization=args[++i]??"";else if(args[i]==="--files")files=(args[++i]??"").split(",").filter(Boolean);else if(args[i]==="--domains")domains=(args[++i]??"").split(",").filter(Boolean);}
		if(!source||!authorization)throw new Error('Usage: bugclaw scan <path|git-url> --auth "<reference>" [--files a,b] [--domains web2]');
		console.log(JSON.stringify(await scan({source,authorization,files,domains}),null,2));return;
	}
	if(command==="reproduce"){if(!args[0])throw new Error("Usage: bugclaw reproduce <scanId> [--candidate id]");const i=args.indexOf("--candidate");console.log(JSON.stringify(await reproduce(args[0],i>=0?args[i+1]:undefined),null,2));return;}
	if (command === "serve") {
		let port = 8787;
		let host = "127.0.0.1";
		let tlsCert: string | undefined;
		let tlsKey: string | undefined;
		for (let i = 0; i < args.length; i++) {
			const option = args[i]!;
			const value = args[++i];
			if (!value || value.startsWith("--")) throw new Error(`Missing value for ${option}`);
			if (option === "--port") port = Number(value);
			else if (option === "--host") host = value;
			else if (option === "--tls-cert") tlsCert = value;
			else if (option === "--tls-key") tlsKey = value;
			else throw new Error(`Unknown serve option ${option}`);
		}
		await serve(port, undefined, { host, tlsCert, tlsKey });
		const addressHost = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
		console.log(`Bugclaw listening on ${tlsCert ? "https" : "http"}://${addressHost}:${port}`);
		return;
	}
	throw new Error("Commands: scan, reproduce, serve");
}
main().catch((error)=>{console.error(error instanceof Error?error.message:String(error));process.exitCode=1;});
