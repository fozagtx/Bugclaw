import { resolve } from "node:path";

const BASE_URL = "https://api.tokenfactory.nebius.com/v1";
const SUPER = "nebius/nvidia/nemotron-3-super-120b-a12b";
const ULTRA = "nebius/nvidia/Nemotron-3-Ultra-550b-a55b";

export function config(env: NodeJS.ProcessEnv = process.env) {
	return {
		baseUrl: (env.NEBIUS_BASE_URL?.trim() || BASE_URL).replace(/\/+$/, ""),
		models: {
			recon: env.BUGCLAW_RECON_MODEL?.trim() || SUPER,
			hunter: env.BUGCLAW_HUNTER_MODEL?.trim() || SUPER,
			validator: env.BUGCLAW_VALIDATOR_MODEL?.trim() || ULTRA,
			repro: env.BUGCLAW_REPRO_MODEL?.trim() || SUPER,
			judge: env.BUGCLAW_JUDGE_MODEL?.trim() || ULTRA,
			fix: env.BUGCLAW_FIX_MODEL?.trim() || ULTRA,
		},
		dataDir: resolve(env.BUGCLAW_DATA || "data"),
		engineDir: resolve(env.BUGCLAW_ENGINE_DIR || "engine"),
	};
}
