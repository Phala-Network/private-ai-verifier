import { VerificationManager } from "../src/verification/index";
import { INTEL_QUOTE_HEX, NVIDIA_PAYLOAD } from "./data";

async function main() {
	console.log("=== Verification Logic Integration Test ===\n");

	const manager = new VerificationManager();

	// Test 1: Intel TDX Verification
	console.log("--- Testing Intel TDX Verification ---");
	const intelReport = {
		intel_quote: INTEL_QUOTE_HEX,
	};

	try {
		console.log("Verifying Intel Quote...");
		const intelResult = await manager.verifyReport(intelReport);
		console.log("Intel Result:", intelResult);

		if (intelResult.isValid && intelResult.hardwareType === "INTEL_TDX") {
			console.log("✅ Intel TDX Verification Passed");
		} else {
			console.error("❌ Intel TDX Verification Failed");
		}
	} catch (e) {
		console.error("❌ Intel TDX Verification Threw Error:", e);
	}

	console.log("\n");

	// Test 2: Nvidia GPU Verification
	console.log("--- Testing Nvidia GPU Verification ---");
	const nvidiaReport = {
		intel_quote: "", // Empty to trigger nvidia path or just omit if type allows (it's string in type def)
		nvidia_payload: JSON.stringify(NVIDIA_PAYLOAD), // The manager parses JSON string
	};

	try {
		console.log("Verifying Nvidia Payload...");
		const nvidiaResult = await manager.verifyReport(nvidiaReport);
		// Don't print full raw token for nvidia as it is huge, just summary
		const { raw, ...nvidiaResultSummary } = nvidiaResult;
		console.log(
			"Nvidia Result (Summary):",
			JSON.stringify(nvidiaResultSummary, null, 2),
		);

		if (nvidiaResult.isValid && nvidiaResult.hardwareType === "NVIDIA_CC") {
			console.log("✅ Nvidia GPU Verification Passed");
		} else {
			console.error("❌ Nvidia GPU Verification Failed");
		}
	} catch (e) {
		console.error("❌ Nvidia GPU Verification Threw Error:", e);
	}

	console.log("\n=== Test Complete ===");
}

main().catch(console.error);
