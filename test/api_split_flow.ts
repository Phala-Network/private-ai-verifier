import { INTEL_QUOTE_HEX, NVIDIA_PAYLOAD } from "./data";

const API_URL = "http://localhost:3000";

async function main() {
	console.log("=== API Split Flow Integration Test ===\n");

	// 1. Mock Report Fetching (Since we can't reliably hit external providers in this test env without creds)
	// We will simulate what /report WOULD return by constructing the objects manually,
	// checking that they are valid inputs for /verify.

	console.log("--- Simulating 'GET /report' output ---");
	const intelReport = { intel_quote: INTEL_QUOTE_HEX };
	const nvidiaReport = { nvidia_payload: JSON.stringify(NVIDIA_PAYLOAD) };
	console.log("Generated Intel Report");
	console.log("Generated Nvidia Report");
	console.log("\n");

	// 2. Test POST /verify with Intel Report
	console.log("--- Testing POST /verify (Intel) ---");
	try {
		const res = await fetch(`${API_URL}/verify`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(intelReport),
		});

		if (res.status !== 200) {
			console.error(`❌ Request failed with status ${res.status}`);
			console.error(await res.text());
		} else {
			const result = await res.json();
			console.log("Verification Result:", result);
			if (result.isValid && result.hardwareType === "INTEL_TDX") {
				console.log("✅ Intel API Verification Passed");
			} else {
				console.error("❌ Intel API Verification Failed");
			}
		}
	} catch (e) {
		console.error("❌ Intel API Request Error:", e);
	}

	console.log("\n");

	// 3. Test POST /verify with Nvidia Report
	console.log("--- Testing POST /verify (Nvidia) ---");
	try {
		const res = await fetch(`${API_URL}/verify`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(nvidiaReport),
		});

		if (res.status !== 200) {
			console.error(`❌ Request failed with status ${res.status}`);
			console.error(await res.text());
		} else {
			const result = await res.json();
			// Summary for log
			const { raw, ...summary } = result;
			console.log("Verification Result (Summary):", summary);
			if (result.isValid && result.hardwareType === "NVIDIA_CC") {
				console.log("✅ Nvidia API Verification Passed");
			} else {
				console.error("❌ Nvidia API Verification Failed");
			}
		}
	} catch (e) {
		console.error("❌ Nvidia API Request Error:", e);
	}

	console.log("\n");

	// 4. Test Invalid Body
	console.log("--- Testing POST /verify (Invalid) ---");
	try {
		const res = await fetch(`${API_URL}/verify`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ foo: "bar" }),
		});

		const result = await res.json();
		console.log("Result:", result);
		if (result.isValid === false && result.hardwareType === "UNKNOWN") {
			console.log("✅ Invalid Input Handled Correctly");
		} else {
			console.error("❌ Invalid Input Handling Failed");
		}
	} catch (e) {
		console.error("❌ Invalid Request Error:", e);
	}

	console.log("\n=== Test Complete ===");
}

main();
