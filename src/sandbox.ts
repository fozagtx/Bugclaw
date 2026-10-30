import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = resolve(".");
const policy = join(root, "sandbox/policy.yaml");
const dockerfile = join(root, "sandbox/Dockerfile");
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
let imageBuild: Promise<{ tag: string; image: any }> | undefined;

export class SandboxReadinessError extends Error {}

export async function runnerImageTag() {
	return `bugclaw-runner:${hash(await readFile(dockerfile, "utf8")).slice(0, 12)}`;
}

export async function runnerImage() {
	if (!imageBuild) imageBuild = (async () => {
		const tag = await runnerImageTag();
		await exec("docker", ["build","-t",tag,join(root,"sandbox")], {timeout:900000});
		const image = JSON.parse((await exec("docker", ["image","inspect",tag])).stdout)[0];
		return { tag, image };
	})();
	return imageBuild;
}

export class Sandbox {
	async ready() {
		try {
			const status = await exec("openshell", ["status"]);
			if (!status.stdout.includes("Connected")) throw new SandboxReadinessError("OpenShell gateway is not connected");
		} catch (error) {
			if (error instanceof SandboxReadinessError) throw error;
			throw new SandboxReadinessError(`OpenShell readiness check failed: ${error instanceof Error ? error.message : String(error)}`);
		}
		try { await exec("docker", ["info"]); }
		catch (error) { throw new SandboxReadinessError(`Docker readiness check failed: ${error instanceof Error ? error.message : String(error)}`); }
	}
	async run(snapshotDir: string, files: Array<{path:string;content:string}>, argv: string[], timeoutSec = 120) {
		await this.ready();
		let imageInfo: { tag: string; image: any };
		try { imageInfo = await runnerImage(); }
		catch (error) { throw new SandboxReadinessError(`Runner image is unavailable: ${error instanceof Error ? error.message : String(error)}`); }
		const {tag,image} = imageInfo;
		const sandbox = `bugclaw-${randomUUID().slice(0,8)}`;
		let stdout="", stderr="", exitCode=1, timedOut=false;
		const overlay = await mkdtemp(join(tmpdir(),"bugclaw-run-"));
		try {
			for (const file of files) {
				const path = resolve(overlay,file.path);
				if (!path.startsWith(`${overlay}/`)) throw new Error("Unsafe sandbox file path");
				await mkdir(join(path,".."),{recursive:true});
				await writeFile(path,file.content);
			}
			await exec("openshell",["sandbox","create","--name",sandbox,"--from",tag,"--policy",policy],{timeout:120000});
			await exec("openshell",["sandbox","upload",sandbox,snapshotDir,"/sandbox/work"],{timeout:120000});
			if(files.length) await exec("openshell",["sandbox","upload",sandbox,overlay,"/sandbox/work"],{timeout:120000});
			try {
				const result = await exec("openshell",["sandbox","exec","-n",sandbox,"--no-login-shell","--","sh","-c",'cd /sandbox/work && exec "$@"',"bugclaw",...argv],{timeout:timeoutSec*1000,maxBuffer:4_000_000});
				stdout=result.stdout; stderr=result.stderr; exitCode=0;
			} catch (error:any) {
				stdout=error.stdout??"";
				stderr=error.stderr??"";
				timedOut=error.code==="ETIMEDOUT" || error.killed===true;
				exitCode=typeof error.code==="number" ? error.code : timedOut ? 124 : 1;
			}
			return {stdout,stderr,exitCode,timedOut,imageTag:tag,imageDigest:image.RepoDigests?.[0]??image.Id,policyHash:hash(await readFile(policy,"utf8")),openshellVersion:(await exec("openshell",["--version"])).stdout.trim()};
		} finally {
			try { await exec("openshell",["sandbox","delete",sandbox,"--force"],{timeout:30000}); } catch {}
			await rm(overlay,{recursive:true,force:true});
		}
	}
}
