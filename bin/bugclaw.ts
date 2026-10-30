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
	if(command==="serve"){let port=8787;const i=args.indexOf("--port");if(i>=0)port=Number(args[i+1]);await serve(port);console.log(`Bugclaw listening on http://127.0.0.1:${port}`);return;}
	throw new Error("Commands: scan, reproduce, serve");
}
main().catch((error)=>{console.error(error instanceof Error?error.message:String(error));process.exitCode=1;});
