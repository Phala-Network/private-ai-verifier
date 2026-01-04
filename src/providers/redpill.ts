import axios from "axios";
import type { AttestationReport, ServiceProvider } from "../types";

export class RedpillProvider implements ServiceProvider {
	name = "redpill";
	private apiBase = "https://api.redpill.ai/v1";

	async fetchReport(modelId: string): Promise<AttestationReport> {
		const reportUrl = `${this.apiBase}/attestation/report?model=${encodeURIComponent(modelId)}`;
		console.log(`[Redpill] Fetching from ${reportUrl}`);

		const response = await axios.get(reportUrl);
		const data = response.data;

		if (!data.intel_quote) {
			throw new Error("Redpill report missing intel_quote");
		}

		return {
			intel_quote: data.intel_quote,
			nvidia_payload: data.nvidia_payload,
			raw: data,
		};
	}

	async listModels(): Promise<string[]> {
		console.log(`[Redpill] Fetching models from ${this.apiBase}/models`);
		const response = await axios.get(`${this.apiBase}/models`);
		// Handle potential response wrappers nicely
		const data = response.data;
		const models = Array.isArray(data) ? data : data.data || [];

		// biome-ignore lint/suspicious/noExplicitAny: API response is dynamic
		return models.map((m: any) => m.id);
	}
}
