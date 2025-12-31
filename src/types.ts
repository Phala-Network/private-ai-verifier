export interface AttestationReport {
	intel_quote: string; // Hex string
	nvidia_payload?: string; // JSON string or Hex string
	raw?: any; // Original raw response
}

export interface VerificationResult {
	isValid: boolean;
	claims?: Record<string, any>;
	error?: string;
}

export interface ServiceProvider {
	name: string;
	fetchReport(modelId: string): Promise<AttestationReport>;
	listModels(): Promise<string[]>;
	// Verify method can be added later once we have generic verification logic
	// verify(report: AttestationReport): Promise<VerificationResult>;
}
