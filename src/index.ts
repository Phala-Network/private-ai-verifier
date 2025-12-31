import { RedpillProvider } from "./providers/redpill";
import { NearaiProvider } from "./providers/nearai";
import { TinfoilProvider } from "./providers/tinfoil";
import type { ServiceProvider } from "./types";

const providers: Record<string, ServiceProvider> = {
	redpill: new RedpillProvider(),
	nearai: new NearaiProvider(),
	tinfoil: new TinfoilProvider(),
};

const server = Bun.serve({
	port: 3000,
	async fetch(req) {
		const url = new URL(req.url);

		if (url.pathname === "/verify") {
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
			} catch (err: any) {
				console.error(`Error processing ${service}/${model}:`, err);
				return new Response(`Error: ${err.message}`, { status: 500 });
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
			} catch (err: any) {
				console.error(`Error fetching models for ${service}:`, err);
				return new Response(`Error: ${err.message}`, { status: 500 });
			}
		}

		return new Response(
			"Confidential Service Verifier API\nUsage: GET /verify?service=<name>&model=<id>",
			{ status: 200 },
		);
	},
});

console.log(`Listening on http://localhost:${server.port} ...`);
