import time
from typing import List
from .types import AttestationReport, VerificationResult
from .providers import TinfoilProvider, RedpillProvider, NearaiProvider
from .verifiers import NvidiaGpuVerifier, NearAICloudVerifier, RedpillVerifier


class TeeVerifier:
    def __init__(self):
        self.providers = {
            "tinfoil": TinfoilProvider(),
            "redpill": RedpillProvider(),
            "nearai": NearaiProvider(),
        }
        self.nvidia_verifier = NvidiaGpuVerifier()
        self.nearai_verifier = NearAICloudVerifier()
        self.redpill_verifier = RedpillVerifier()

    async def fetch_report(
        self, provider_name: str, model_id: str
    ) -> AttestationReport:
        provider = self.providers.get(provider_name.lower())
        if not provider:
            raise ValueError(f"Unknown provider: {provider_name}")
        return provider.fetch_report(model_id)

    async def verify(self, report: AttestationReport) -> VerificationResult:
        # Get provider from report
        provider_name = report.provider.lower()

        # Special handling for NearAI which has a complex multi-component report
        if provider_name == "nearai":
            if not report.raw:
                return VerificationResult(
                    model_verified=False,
                    provider=provider_name,
                    timestamp=time.time(),
                    hardware_type=["INTEL_TDX"],  # fallback
                    claims={},
                    error="Missing raw report data for NearAI verification",
                )
            return await self.nearai_verifier.verify(
                report.raw,
                request_nonce=report.request_nonce,
                model_id=report.model_id,
            )

        # Special handling for Redpill which uses PhalaCloudVerifier internally
        if provider_name == "redpill":
            if not report.raw:
                return VerificationResult(
                    model_verified=False,
                    provider=provider_name,
                    timestamp=time.time(),
                    hardware_type=["INTEL_TDX"],
                    claims={},
                    error="Missing raw report data for Redpill verification",
                )
            # Build report data with all required fields
            report_data = {
                **report.raw,
                "request_nonce": report.request_nonce,
                "nvidia_payload": report.nvidia_payload,
            }
            return await self.redpill_verifier.verify(report_data)

        provider = self.providers.get(provider_name)
        if not provider:
            # Fallback for reports that might have been saved before this change
            # or from other sources. Use a default IntelTdxVerifier which does
            # trivial verification (no policy).
            from .verifiers import IntelTdxVerifier

            intel_verifier = IntelTdxVerifier()
        else:
            intel_verifier = provider.get_verifier()

        # Wrap quote with metadata if available in raw
        quote_input = report.intel_quote
        if isinstance(report.raw, dict):
            quote_input = {
                "quote": report.intel_quote,
                "model_id": report.raw.get("model_id"),
                "repo": report.raw.get("repo"),
                "request_nonce": report.request_nonce,
                "signing_address": report.raw.get("signing_address"),
            }

        # 1. Verify Intel TDX Quote (Mandatory)
        intel_result = await intel_verifier.verify(quote_input)

        if not intel_result.model_verified:
            return intel_result

        # 2. Verify Nvidia CC Payload if present
        if report.nvidia_payload:
            nvidia_result = await self.nvidia_verifier.verify(report.nvidia_payload)

            # Combine claims
            combined_claims = {
                "intel": intel_result.claims,
                "nvidia": nvidia_result.claims,
            }

            if nvidia_result.model_verified:
                return VerificationResult(
                    model_verified=True,
                    provider=provider_name,
                    timestamp=time.time(),
                    hardware_type=["INTEL_TDX", "NVIDIA_CC"],
                    claims=combined_claims,
                    raw={"intel": intel_result.raw, "nvidia": nvidia_result.raw},
                )
            else:
                return VerificationResult(
                    model_verified=intel_result.model_verified,
                    provider=provider_name,
                    timestamp=time.time(),
                    hardware_type=["INTEL_TDX", "NVIDIA_CC"],
                    claims=combined_claims,
                    raw={"intel": intel_result.raw, "nvidia": nvidia_result.raw},
                    error=nvidia_result.error,
                )

        return intel_result

    async def verify_model(
        self, provider_name: str, model_id: str
    ) -> VerificationResult:
        """Fetch a report from a provider and verify it."""
        report = await self.fetch_report(provider_name, model_id)
        return await self.verify(report)

    def list_providers(self) -> List[str]:
        return list(self.providers.keys())

    async def list_models(self, provider_name: str) -> List[str]:
        provider = self.providers.get(provider_name.lower())
        if not provider:
            raise ValueError(f"Unknown provider: {provider_name}")
        return provider.list_models()
