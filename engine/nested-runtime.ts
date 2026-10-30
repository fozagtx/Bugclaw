import { existsSync, readFileSync } from "node:fs";

/** Cloudflare: inner unshare/sandbox silently fails without these Docker flags. */
export const NESTED_DOCKER_RUN_FLAGS = [
	"--security-opt",
	"seccomp=unconfined",
	"--security-opt",
	"apparmor=unconfined",
] as const;

export const NESTED_DOCKER_SECURITY_OPTS = ["seccomp=unconfined", "apparmor=unconfined"] as const;

export interface NestedRuntimeIO {
	exists(path: string): boolean;
	read(path: string): string | null;
}

export interface NestedRuntimeStatus {
	insideContainer: boolean;
	seccompFilter: boolean;
	apparmorConfined: boolean;
	silentFailureRisk: boolean;
	requiredDockerFlags: string[];
	advice: string;
}

const ADVICE =
	"If the harness runs inside Docker, pass --security-opt seccomp=unconfined --security-opt apparmor=unconfined. Docker's default profile makes an inner unshare/user-namespace sandbox fail to start with no useful error.";

export const NESTED_RUNTIME_ADVICE = ADVICE;

function defaultIO(): NestedRuntimeIO {
	return {
		exists: existsSync,
		read(path: string): string | null {
			try {
				return readFileSync(path, "utf8");
			} catch {
				return null;
			}
		},
	};
}

function insideContainer(io: NestedRuntimeIO): boolean {
	if (io.exists("/.dockerenv") || io.exists("/run/.containerenv")) return true;
	const cgroup = `${io.read("/proc/1/cgroup") ?? ""}\n${io.read("/proc/self/cgroup") ?? ""}`.toLowerCase();
	return /docker|containerd|podman|kubepods|lxc|libpod/.test(cgroup);
}

function seccompFilter(io: NestedRuntimeIO): boolean {
	const status = io.read("/proc/self/status");
	if (!status) return false;
	return /^Seccomp:\s*2\b/m.test(status);
}

function apparmorConfined(io: NestedRuntimeIO): boolean {
	const profile = (io.read("/proc/self/attr/current") ?? io.read("/proc/self/attr/apparmor/current") ?? "")
		.trim()
		.toLowerCase();
	if (!profile) return false;
	return profile !== "unconfined" && profile !== "kernel";
}

export function inspectNestedRuntime(io: NestedRuntimeIO = defaultIO()): NestedRuntimeStatus {
	const container = insideContainer(io);
	const seccomp = seccompFilter(io);
	const apparmor = apparmorConfined(io);
	const silentFailureRisk = container && (seccomp || apparmor);
	return {
		insideContainer: container,
		seccompFilter: seccomp,
		apparmorConfined: apparmor,
		silentFailureRisk,
		requiredDockerFlags: [...NESTED_DOCKER_RUN_FLAGS],
		advice: ADVICE,
	};
}

export function nestedRuntimeWarning(status: NestedRuntimeStatus): string | null {
	if (!status.silentFailureRisk) return null;
	return `NESTED_RUNTIME: ${status.advice}`;
}
