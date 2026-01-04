import axios from "axios";
import type { VerificationResult, Verifier } from "./types";

interface NvidiaAttestationPayload {
	nonce: string;
	arch: string;
	evidence_list: Array<{
		certificate: string;
		evidence: string;
		arch: string;
	}>;
}

export class NvidiaGpuVerifier implements Verifier {
	private readonly NRAS_URL =
		"https://nras.attestation.nvidia.com/v3/attest/gpu";

	async verify(payload: NvidiaAttestationPayload): Promise<VerificationResult> {
		try {
			// 1. Send to NRAS
			const response = await axios.post(this.NRAS_URL, payload, {
				headers: {
					accept: "application/json",
					"content-type": "application/json",
				},
			});

			if (response.status !== 200) {
				throw new Error(`NRAS responded with status ${response.status}`);
			}

			const tokens = response.data;
			if (!Array.isArray(tokens) || tokens.length < 1) {
				throw new Error("Invalid response format: expected array");
			}

			// 2. Parse the platform token (Index 0)
			// Expected format: [ ["JWT", "token..."], { "GPU-0": "token..." } ]
			// We look at the first element which should be ["JWT", "token"]
			const platformTokenEntry = tokens[0];
			if (
				!Array.isArray(platformTokenEntry) ||
				platformTokenEntry[0] !== "JWT"
			) {
				throw new Error("Invalid platform token format");
			}

			const platformJwt = platformTokenEntry[1];
			const platformClaims = this.decodeJwt(platformJwt);

			// 3. Check overall result
			const isValid = platformClaims["x-nvidia-overall-att-result"] === true;

			// 4. Extract GPU claims (from the second element if available, or from submods in platform token?)
			// The platform token has 'submods'. The second element in the array is detailed GPU tokens.
			// Let's grab the first GPU detail if available.
			let gpuClaims = {};
			if (tokens.length > 1 && typeof tokens[1] === "object") {
				const gpuTokens = tokens[1];
				const firstGpuKey = Object.keys(gpuTokens)[0]; // e.g., "GPU-0"
				if (firstGpuKey && typeof gpuTokens[firstGpuKey] === "string") {
					gpuClaims = this.decodeJwt(gpuTokens[firstGpuKey]);
				}
			}

			return {
				isValid,
				timestamp: Date.now(),
				hardwareType: "NVIDIA_CC",
				claims: {
					...platformClaims,
					...gpuClaims,
				},
				raw: tokens,
				error: isValid ? undefined : "Nvidia attestation result is false",
			};
		} catch (error: unknown) {
			const errorMessage =
				error instanceof Error ? error.message : String(error);
			return {
				isValid: false,
				timestamp: Date.now(),
				hardwareType: "NVIDIA_CC",
				claims: {},
				error: errorMessage || "Unknown error during Nvidia verification",
			};
		}
	}

	// biome-ignore lint/suspicious/noExplicitAny: JWT result is dynamic
	private decodeJwt(token: string): any {
		try {
			const parts = token.split(".");
			if (parts.length !== 3) {
				throw new Error("Invalid JWT format");
			}
			const payload = parts[1];
			if (!payload) {
				throw new Error("Payload missing");
			}
			const decoded = Buffer.from(payload, "base64").toString("utf-8");
			return JSON.parse(decoded);
		} catch (e) {
			console.error("Failed to decode JWT:", e);
			return {};
		}
	}
}
