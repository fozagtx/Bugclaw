import assert from "node:assert/strict";
import test from "node:test";
import {
	inspectNestedRuntime,
	NESTED_DOCKER_RUN_FLAGS,
	type NestedRuntimeIO,
	nestedRuntimeWarning,
} from "./nested-runtime.ts";

function io(files: Record<string, string | true>): NestedRuntimeIO {
	return {
		exists: (path) => files[path] === true || typeof files[path] === "string",
		read: (path) => (typeof files[path] === "string" ? files[path] : null),
	};
}

test("host processes are not treated as a silent nested-sandbox failure", () => {
	const status = inspectNestedRuntime(io({ "/proc/self/status": "Seccomp:\t0\n" }));
	assert.equal(status.insideContainer, false);
	assert.equal(status.silentFailureRisk, false);
	assert.equal(nestedRuntimeWarning(status), null);
	assert.deepEqual(status.requiredDockerFlags, [...NESTED_DOCKER_RUN_FLAGS]);
});

test("Docker default seccomp/AppArmor is a silent-failure risk", () => {
	const status = inspectNestedRuntime(
		io({
			"/.dockerenv": true,
			"/proc/self/status": "Name:\tnode\nSeccomp:\t2\n",
			"/proc/self/attr/current": "docker-default\n",
		}),
	);
	assert.equal(status.insideContainer, true);
	assert.equal(status.seccompFilter, true);
	assert.equal(status.apparmorConfined, true);
	assert.equal(status.silentFailureRisk, true);
	assert.match(nestedRuntimeWarning(status) ?? "", /seccomp=unconfined/);
	assert.match(nestedRuntimeWarning(status) ?? "", /apparmor=unconfined/);
});

test("unconfined Docker is not a silent-failure risk", () => {
	const status = inspectNestedRuntime(
		io({
			"/.dockerenv": true,
			"/proc/self/status": "Seccomp:\t0\n",
			"/proc/self/attr/current": "unconfined",
		}),
	);
	assert.equal(status.insideContainer, true);
	assert.equal(status.silentFailureRisk, false);
	assert.equal(nestedRuntimeWarning(status), null);
});
