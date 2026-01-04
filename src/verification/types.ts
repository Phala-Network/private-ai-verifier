export interface VerificationResult {
	isValid: boolean;
	timestamp: number;
	hardwareType: "INTEL_TDX" | "NVIDIA_CC" | "UNKNOWN";
	claims: {
		[key: string]: unknown;
	};
	raw?: any;
	error?: string;
}

export interface Verifier {
	verify(evidence: unknown): Promise<VerificationResult>;
}
