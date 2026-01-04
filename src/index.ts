import { RedpillProvider } from "./providers/redpill";
import { NearaiProvider } from "./providers/nearai";
import { TinfoilProvider } from "./providers/tinfoil";
import type { ServiceProvider, AttestationReport } from "./types";
import { VerificationManager } from "./verification/index";

const providers: Record<string, ServiceProvider> = {
	redpill: new RedpillProvider(),
	nearai: new NearaiProvider(),
	tinfoil: new TinfoilProvider(),
};

const verificationManager = new VerificationManager();

const server = Bun.serve({
	port: 3000,
	async fetch(req) {
		const url = new URL(req.url);

		// GET /report - Fetch the attestation report
		if (url.pathname === "/report") {
			const service = url.searchParams.get("service");
			const model = url.searchParams.get("model");

			if (!service || !model) {
				return new Response('Missing "service" or "model" query params', {
					status: 400,
				});
			}

			const provider = providers[service.toLowerCase()];
			if (!provider) {
				return new Response(
					`Unknown service: ${service}. Available: ${Object.keys(providers).join(", ")}`,
					{ status: 404 },
				);
			}

			try {
				const report = await provider.fetchReport(model);
				return Response.json(report, {
					headers: { "Content-Type": "application/json" },
				});
			} catch (err: unknown) {
				const errorMessage = err instanceof Error ? err.message : String(err);
				console.error(`Error processing ${service}/${model}:`, err);
				return new Response(`Error: ${errorMessage}`, { status: 500 });
			}
		}

		// POST /verify - Verify an attestation report
		if (url.pathname === "/verify" && req.method === "POST") {
			try {
				const body = await req.json();
				// Basic validation that it looks like a report (has intel_quote or nvidia_payload)
				// VerificationManager handles missing fields gracefully by returning INVALID/UNKNOWN,
				// so we can pass it directly.
				if (!body || typeof body !== "object") {
					return new Response("Invalid request body", { status: 400 });
				}

				const result = await verificationManager.verifyReport(
					body as AttestationReport,
				);
				return Response.json(result, {
					headers: { "Content-Type": "application/json" },
				});
			} catch (err: unknown) {
				const errorMessage = err instanceof Error ? err.message : String(err);
				console.error("Error verifying report:", err);
				return new Response(`Error: ${errorMessage}`, { status: 400 });
			}
		}

		if (url.pathname === "/providers") {
			return Response.json(Object.keys(providers), {
				headers: { "Content-Type": "application/json" },
			});
		}

		if (url.pathname === "/models") {
			const service = url.searchParams.get("service");
			if (!service) {
				return new Response('Missing "service" query param', { status: 400 });
			}

			const provider = providers[service.toLowerCase()];
			if (!provider) {
				return new Response(
					`Unknown service: ${service}. Available: ${Object.keys(providers).join(", ")}`,
					{ status: 404 },
				);
			}

			try {
				const models = await provider.listModels();
				return Response.json(models, {
					headers: { "Content-Type": "application/json" },
				});
			} catch (err: unknown) {
				const errorMessage = err instanceof Error ? err.message : String(err);
				console.error(`Error fetching models for ${service}:`, err);
				return new Response(`Error: ${errorMessage}`, { status: 500 });
			}
		}

		return new Response(
			"Confidential Service Verifier API\nUsage:\n  GET /report?service=<name>&model=<id> -> Fetch Report\n  POST /verify -> Verify Report JSON",
			{ status: 200 },
		);
	},
});

console.log(`Listening on http://localhost:${server.port} ...`);
