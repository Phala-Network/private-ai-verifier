import time
from typing import Optional, Dict, Any, List
from .types import AttestationReport, VerificationResult, VerificationLevel
from .providers import TinfoilProvider, RedpillProvider, NearaiProvider
from .verifiers import NvidiaGpuVerifier, PhalaCloudVerifier


class TeeVerifier:
    def __init__(self):
        self.providers = {
            "tinfoil": TinfoilProvider(),
            "redpill": RedpillProvider(),
            "nearai": NearaiProvider(),
        }
        self.nvidia_verifier = NvidiaGpuVerifier()

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
            }

        # 1. Verify Intel TDX Quote (Mandatory)
        intel_result = await intel_verifier.verify(quote_input)

        if intel_result.level == VerificationLevel.NONE:
            return intel_result

        # 2. Verify Nvidia CC Payload if present
        if report.nvidia_payload:
            nvidia_result = await self.nvidia_verifier.verify(report.nvidia_payload)

            # Combine claims
            combined_claims = {
                "intel": intel_result.claims,
                "nvidia": nvidia_result.claims,
            }

            if nvidia_result.level == VerificationLevel.HARDWARE_TDX_CC:
                return VerificationResult(
                    level=VerificationLevel.HARDWARE_TDX_CC,
                    timestamp=time.time(),
                    hardware_type=["INTEL_TDX", "NVIDIA_CC"],
                    claims=combined_claims,
                    raw={"intel": intel_result.raw, "nvidia": nvidia_result.raw},
                )
            else:
                return VerificationResult(
                    level=VerificationLevel.HARDWARE_TDX,
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
