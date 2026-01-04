import axios from "axios";
import zlib from "zlib";
import { promisify } from "util";
import fs from "fs/promises";
import path from "path";
import yaml from "js-yaml";
import type { AttestationReport, ServiceProvider } from "../types";

const gunzip = promisify(zlib.gunzip);

export class TinfoilProvider implements ServiceProvider {
	name = "tinfoil";
	private configPath = path.join(__dirname, "../config/tinfoil_config.yml");
	private cache: Record<string, string> | null = null;

	private async getModelMap(): Promise<Record<string, string>> {
		if (this.cache) return this.cache;

		try {
			const fileContent = await fs.readFile(this.configPath, "utf-8");
			// biome-ignore lint/suspicious/noExplicitAny: YAML config is dynamic
			const config = yaml.load(fileContent) as any;

			const map: Record<string, string> = {};
			// Config structure:
			// models:
			//   model-name:
			//     enclaves: [host...]

			if (config.models) {
				for (const [key, value] of Object.entries(config.models)) {
					// biome-ignore lint/suspicious/noExplicitAny: YAML config is dynamic
					const modelData = value as any;
					if (
						modelData.enclaves &&
						Array.isArray(modelData.enclaves) &&
						modelData.enclaves.length > 0
					) {
						map[key] = modelData.enclaves[0];
					}
				}
			}

			this.cache = map;
			return map;
		} catch (err) {
			console.error("Failed to load Tinfoil config:", err);
			// Fallback to empty or throw? Throwing is safer as it means broken setup.
			throw new Error("Failed to load Tinfoil configuration");
		}
	}

	async fetchReport(modelId: string): Promise<AttestationReport> {
		const map = await this.getModelMap();
		const host = map[modelId];

		if (!host) {
			throw new Error(`Unknown Tinfoil model: ${modelId}`);
		}

		// Allow direct hostname usage if the modelId looks like a host (legacy support)
		const actualHost = modelId.includes(".") ? modelId : host;

		const url = `https://${actualHost}/.well-known/tinfoil-attestation`;
		console.log(`[Tinfoil] Fetching from ${url}`);

		const response = await axios.get(url);
		const data = response.data;
		const expectedPrefix = "https://tinfoil.sh/predicate/tdx-guest/";

		if (!data.format || !data.format.startsWith(expectedPrefix)) {
			throw new Error(
				`Unsupported Tinfoil attestation format: ${data.format || "missing"}`,
			);
		}

		if (!data.body) {
			throw new Error("Tinfoil response missing body");
		}

		const buffer = Buffer.from(data.body, "base64");
		const decoded = await gunzip(buffer);

		// Decoded is the raw Intel TDX Quote (binary)
		const quoteHex = decoded.toString("hex");

		return {
			intel_quote: quoteHex,
			nvidia_payload: undefined,
			raw: data,
		};
	}

	async listModels(): Promise<string[]> {
		const map = await this.getModelMap();
		return Object.keys(map);
	}
}
