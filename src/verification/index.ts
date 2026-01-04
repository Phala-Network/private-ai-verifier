import type { AttestationReport } from "../types";
import { IntelTdxVerifier } from "./intel";
import { NvidiaGpuVerifier } from "./nvidia";
import type { VerificationResult } from "./types";

export * from "./types";

export class VerificationManager {
	private intelVerifier = new IntelTdxVerifier();
	private nvidiaVerifier = new NvidiaGpuVerifier();

	async verifyReport(
		report: AttestationReport,
	): Promise<{ intel: VerificationResult; nvidia?: VerificationResult }> {
		if (!report.intel_quote) {
			return {
				intel: {
					isValid: false,
					timestamp: Date.now(),
					hardwareType: "UNKNOWN",
					claims: {},
					error: "Intel TDX quote is mandatory for verification",
				},
			};
		}

		const intelResult = await this.intelVerifier.verify(report.intel_quote);
		let nvidiaResult: VerificationResult | undefined;

		if (report.nvidia_payload) {
			// nvidia_payload in AttestationReport is string, but NvidiaGpuVerifier expects object
			// We need to parse it if it's a string
			// biome-ignore lint/suspicious/noExplicitAny: Payload can be any JSON object
			let payload: any;
			try {
				payload =
					typeof report.nvidia_payload === "string"
						? JSON.parse(report.nvidia_payload)
						: report.nvidia_payload;
			} catch {
				nvidiaResult = {
					isValid: false,
					timestamp: Date.now(),
					hardwareType: "NVIDIA_CC",
					claims: {},
					error: "Failed to parse nvidia_payload",
				};
			}

			if (!nvidiaResult) {
				if (!payload || typeof payload !== "object") {
					nvidiaResult = {
						isValid: false,
						timestamp: Date.now(),
						hardwareType: "NVIDIA_CC",
						claims: {},
						error: "nvidia_payload must be a JSON object",
					};
				} else {
					nvidiaResult = await this.nvidiaVerifier.verify(payload);
				}
			}
		}

		return {
			intel: intelResult,
			nvidia: nvidiaResult,
		};
	}
}
