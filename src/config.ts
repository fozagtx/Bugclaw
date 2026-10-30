import { resolve } from "node:path";

const BASE_URL = "https://api.tokenfactory.nebius.com/v1";
const SUPER = "nebius/nvidia/nemotron-3-super-120b-a12b";
const ULTRA = "nebius/nvidia/Nemotron-3-Ultra-550b-a55b";

export function config(env: NodeJS.ProcessEnv = process.env) {
	const model = (override: string | undefined, fallback: string) => {
		const id = override?.trim() || fallback;
		if (!/^nebius\/nvidia\//i.test(id)) {
			throw new Error(`Bugclaw only runs NVIDIA Nemotron models on Nebius Token Factory: ${id}`);
		}
		return id;
	};
	return {
		baseUrl: (env.NEBIUS_BASE_URL?.trim() || BASE_URL).replace(/\/+$/, ""),
		models: {
			recon: model(env.BUGCLAW_RECON_MODEL, SUPER),
			hunter: model(env.BUGCLAW_HUNTER_MODEL, SUPER),
			validator: model(env.BUGCLAW_VALIDATOR_MODEL, ULTRA),
			repro: model(env.BUGCLAW_REPRO_MODEL, SUPER),
			judge: model(env.BUGCLAW_JUDGE_MODEL, ULTRA),
			fix: model(env.BUGCLAW_FIX_MODEL, ULTRA),
		},
		mcpToken: env.BUGCLAW_MCP_TOKEN || undefined,
		dataDir: resolve(env.BUGCLAW_DATA || "data"),
		engineDir: resolve(env.BUGCLAW_ENGINE_DIR || "engine"),
	};
}
