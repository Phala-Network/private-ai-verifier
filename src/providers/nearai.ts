import axios from "axios";
import crypto from "crypto";
import type { AttestationReport, ServiceProvider } from "../types";

export class NearaiProvider implements ServiceProvider {
	name = "nearai";
	private apiBase = "https://cloud-api.near.ai/v1";

	async fetchReport(modelId: string): Promise<AttestationReport> {
		const nonce = crypto.randomBytes(32).toString("hex");

		const params = {
			model: modelId,
			signing_algo: "ecdsa",
			nonce: nonce,
		};

		console.log(
			`[Near] Fetching report for ${modelId} with nonce ${nonce.substring(0, 8)}...`,
		);

		const response = await axios.get(`${this.apiBase}/attestation/report`, {
			params,
		});
		const data = response.data;

		// Near returns array of attestations. We pick the first one for now.
		// In strict verifiable flow, you might verify all or specific signing address.
		if (
			!data.model_attestations ||
			!Array.isArray(data.model_attestations) ||
			data.model_attestations.length === 0
		) {
			throw new Error("Near report missing model_attestations");
		}

		const firstAttestation = data.model_attestations[0];

		return {
			intel_quote: firstAttestation.intel_quote,
			nvidia_payload: firstAttestation.nvidia_payload,
			raw: data,
		};
	}

	async listModels(): Promise<string[]> {
		console.log(`[Near] Fetching models from ${this.apiBase}/model/list`);
		const response = await axios.get(`${this.apiBase}/model/list`);
		const data = response.data;

		// Map response to just model IDs
		// Assuming data is array or wrapped array
		const models = Array.isArray(data) ? data : data.models || [];
		// Extract 'id' if objects, or return strings if strings
		// biome-ignore lint/suspicious/noExplicitAny: API response is dynamic
		return models.map((m: any) => (typeof m === "string" ? m : m.modelId));
	}
}
