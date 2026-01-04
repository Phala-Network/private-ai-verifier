import { getCollateralAndVerify } from "@phala/dcap-qvl";
import type { VerificationResult, Verifier } from "./types";

// Helper to convert Uint8Array/Buffer to hex string
function toHex(data: Uint8Array | number[]): string {
	return Buffer.from(data).toString("hex");
}

export class IntelTdxVerifier implements Verifier {
	async verify(quote: string | Buffer): Promise<VerificationResult> {
		const quoteBuffer = Buffer.isBuffer(quote)
			? quote
			: Buffer.from(quote as string, "hex");

		try {
			// parse to get basic info even if verification fails later (optional, but good for debugging)
			// const parsedParams = Quote.parse(quoteBuffer);

			// Verify
			const result = await getCollateralAndVerify(quoteBuffer);

			// Check status
			const isSuccess =
				result.status === "UpToDate" || result.status === "ConfigurationNeeded";

			if (!isSuccess) {
				return {
					isValid: false,
					timestamp: Date.now(),
					hardwareType: "INTEL_TDX",
					claims: {},
					raw: result,
					error: `Verification failed with status: ${result.status}`,
				};
			}

			// Extract claims
			const report = result.report;
			let claims: Record<string, string> = {};

			if (report.type === "td10") {
				const td10 = report.asTd10();
				if (td10) {
					claims = {
						mrSeam: toHex(td10.mrSeam),
						mrTd: toHex(td10.mrTd),
						rtMr0: toHex(td10.rtMr0),
						rtMr1: toHex(td10.rtMr1),
						rtMr2: toHex(td10.rtMr2),
						rtMr3: toHex(td10.rtMr3),
						teeTcbSvn: toHex(td10.teeTcbSvn),
						reportData: toHex(td10.reportData),
					};
				}
			} else if (report.type === "td15") {
				const td15 = report.asTd15();
				if (td15) {
					const base = td15.base;
					claims = {
						mrSeam: toHex(base.mrSeam),
						mrTd: toHex(base.mrTd),
						rtMr0: toHex(base.rtMr0),
						rtMr1: toHex(base.rtMr1),
						rtMr2: toHex(base.rtMr2),
						rtMr3: toHex(base.rtMr3),
						teeTcbSvn: toHex(base.teeTcbSvn),
						reportData: toHex(base.reportData),
						// Extra fields for TD15
						teeTcbSvn2: toHex(td15.teeTcbSvn2),
						mrServiceTd: toHex(td15.mrServiceTd),
					};
				}
			} else {
				return {
					isValid: false,
					timestamp: Date.now(),
					hardwareType: "INTEL_TDX",
					claims: {},
					raw: result,
					error: "Unsupported report type or failed to parse report data",
				};
			}

			// additional safety check if claims is empty logic-wise, though handled above
			if (Object.keys(claims).length === 0) {
				return {
					isValid: false,
					timestamp: Date.now(),
					hardwareType: "INTEL_TDX",
					claims: {},
					raw: result,
					error: "Failed to extract claims from report",
				};
			}

			return {
				isValid: true,
				timestamp: Date.now(),
				hardwareType: "INTEL_TDX",
				claims,
				raw: result,
			};
		} catch (error: unknown) {
			const errorMessage =
				error instanceof Error ? error.message : String(error);
			return {
				isValid: false,
				timestamp: Date.now(),
				hardwareType: "INTEL_TDX",
				claims: {},
				error: errorMessage || "Unknown error during verification",
			};
		}
	}
}
