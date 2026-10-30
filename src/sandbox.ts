import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = resolve(".");
const policy = join(root, "sandbox/policy.yaml");
const dockerfile = join(root, "sandbox/Dockerfile");
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
let imageBuild: Promise<{ tag: string; image: any }> | undefined;

function openshell(args: string[], options: { timeout?: number; maxBuffer?: number } = {}) {
	const pending = exec("openshell", args, options);
	pending.child.stdin?.end();
	return pending;
}

function message(error: unknown) {
	if (error instanceof Error) {
		const stderr = "stderr" in error ? String(error.stderr ?? "").trim() : "";
		return [error.message, stderr].filter(Boolean).join(": ");
	}
	return String(error);
}

export class SandboxError extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "SandboxError";
	}
}

export class SandboxReadinessError extends SandboxError {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "SandboxReadinessError";
	}
}

async function infrastructureCommand(label: string, args: string[], timeout: number) {
	try {
		return await openshell(args, { timeout });
	} catch (error) {
		throw new SandboxError(`${label} failed: ${message(error)}`, { cause: error });
	}
}

export async function runnerImageTag() {
	return `bugclaw-runner:${hash(await readFile(dockerfile, "utf8")).slice(0, 12)}`;
}

export async function runnerImage() {
	if (!imageBuild) imageBuild = (async () => {
		const tag = await runnerImageTag();
		let image: any;
		try { image = JSON.parse((await exec("docker", ["image","inspect",tag])).stdout)[0]; }
		catch {
			await exec("docker", ["build","-t",tag,join(root,"sandbox")], {timeout:900000});
			image = JSON.parse((await exec("docker", ["image","inspect",tag])).stdout)[0];
		}
		return { tag, image };
	})();
	try {
		return await imageBuild;
	} catch (error) {
		imageBuild = undefined;
		throw new SandboxError(`Runner image build or inspection failed: ${message(error)}`, { cause: error });
	}
}

export class Sandbox {
	async ready() {
		try {
			const status = await openshell(["status"]);
			if (!status.stdout.includes("Connected")) throw new SandboxReadinessError("OpenShell gateway is not connected");
		} catch (error) {
			if (error instanceof SandboxReadinessError) throw error;
			throw new SandboxReadinessError(`OpenShell readiness check failed: ${message(error)}`, { cause: error });
		}
		try { await exec("docker", ["info"]); }
		catch (error) { throw new SandboxReadinessError(`Docker readiness check failed: ${message(error)}`, { cause: error }); }
	}
	async run(snapshotDir: string, files: Array<{path:string;content:string}>, argv: string[], timeoutSec = 120) {
		await this.ready();
		const imageInfo = await runnerImage();
		const {tag,image} = imageInfo;
		const sandbox = `bugclaw-${randomUUID().slice(0,8)}`;
		let stdout="", stderr="", exitCode=1, timedOut=false;
		const staging = await mkdtemp(join(tmpdir(),"bugclaw-run-"));
		const snapshotArchive = join(staging, ".bugclaw-snapshot.tar");
		const overlayArchive = join(staging, ".bugclaw-overlay.tar");
		const overlayRoot = join(staging, "overlay");
		let created = false;
		let runError: unknown;
		try {
			await mkdir(overlayRoot, { recursive: true, mode: 0o700 });
			for (const file of files) {
				const path = resolve(overlayRoot,file.path);
				if (!path.startsWith(`${overlayRoot}/`)) throw new SandboxError("Unsafe sandbox file path");
				await mkdir(dirname(path),{recursive:true});
				await writeFile(path,file.content);
			}
			await exec("tar",["-cf",snapshotArchive,"-C",snapshotDir,"."]);
			if(files.length) await exec("tar",["-cf",overlayArchive,"-C",overlayRoot,"."]);
			await infrastructureCommand("OpenShell sandbox create",["sandbox","create","--name",sandbox,"--from",tag,"--policy",policy],120000);
			created = true;
			await infrastructureCommand("OpenShell snapshot upload",["sandbox","upload","--no-git-ignore",sandbox,snapshotArchive,"/sandbox/work/"],120000);
			if(files.length) await infrastructureCommand("OpenShell overlay upload",["sandbox","upload","--no-git-ignore",sandbox,overlayArchive,"/sandbox/work/"],120000);
			const extractOverlay = files.length
				? "tar -xf .bugclaw-snapshot.tar && tar -xf .bugclaw-overlay.tar && rm .bugclaw-snapshot.tar .bugclaw-overlay.tar"
				: "tar -xf .bugclaw-snapshot.tar && rm .bugclaw-snapshot.tar";
			await infrastructureCommand(
				"OpenShell sandbox upload extraction",
				["sandbox","exec","-n",sandbox,"--no-tty","--","sh","-c",`cd /sandbox/work && ${extractOverlay}`],
				120000,
			);
			try {
				const result = await openshell(["sandbox","exec","-n",sandbox,"--no-tty","--","sh","-c",'cd /sandbox/work && exec "$@"',"bugclaw",...argv],{timeout:timeoutSec*1000,maxBuffer:4_000_000});
				stdout=result.stdout; stderr=result.stderr; exitCode=0;
			} catch (error:any) {
				stdout=error.stdout??"";
				stderr=error.stderr??"";
				timedOut=error.code==="ETIMEDOUT" || error.killed===true;
				exitCode=typeof error.code==="number" ? error.code : timedOut ? 124 : 1;
			}
			const openshellVersion = await infrastructureCommand("OpenShell version query",["--version"],30000);
			return {stdout,stderr,exitCode,timedOut,imageTag:tag,imageDigest:image.RepoDigests?.[0]??image.Id,policyHash:hash(await readFile(policy,"utf8")),openshellVersion:openshellVersion.stdout.trim()};
		} catch (error) {
			runError = error instanceof SandboxError ? error : new SandboxError(`Sandbox input staging failed: ${message(error)}`, { cause: error });
			throw runError;
		} finally {
			let cleanupError: unknown;
			if (created) {
				try { await infrastructureCommand("OpenShell sandbox delete",["sandbox","delete",sandbox],30000); }
				catch (error) { cleanupError = error; }
			}
			try { await rm(staging,{recursive:true,force:true}); }
			catch (error) { cleanupError ??= new SandboxError(`Sandbox staging cleanup failed: ${message(error)}`, { cause: error }); }
			if (cleanupError) {
				throw new SandboxError(
					runError ? `${message(runError)}; sandbox cleanup failed: ${message(cleanupError)}` : message(cleanupError),
					{ cause: cleanupError },
				);
			}
		}
	}
}
