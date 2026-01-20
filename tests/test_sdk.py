import pytest
import asyncio
import json
from confidential_verifier.sdk import TeeVerifier
from confidential_verifier.types import AttestationReport
from .test_data import INTEL_QUOTE_HEX, NVIDIA_PAYLOAD


@pytest.mark.asyncio
async def test_verifiers():
    verifier = TeeVerifier()

    print("\n--- Testing Intel TDX Verification ---")
    print("\n--- Testing Intel TDX Verification ---")
    # Use default/generic IntelTdxVerifier directly
    from confidential_verifier.verifiers import IntelTdxVerifier

    intel_result = await IntelTdxVerifier().verify(INTEL_QUOTE_HEX)
    print(f"Model Verified: {intel_result.model_verified}")
    print(f"Error: {intel_result.error}")
    # print(f"Claims: {json.dumps(intel_result.claims, indent=2)}")

    print("\n--- Testing Nvidia CC Verification ---")
    # This calls Nvidia NRAS, which should work if the payload is valid and NRAS is up.
    nvidia_result = await verifier.nvidia_verifier.verify(NVIDIA_PAYLOAD)
    print(f"Model Verified: {nvidia_result.model_verified}")
    print(f"Error: {nvidia_result.error}")
    # print(f"Claims: {json.dumps(nvidia_result.claims, indent=2)}")

    print("\n--- Testing Combined Verification ---")
    # Use "generic" or unknown provider to test fallback to IntelTdxVerifier
    report = AttestationReport(
        provider="generic", intel_quote=INTEL_QUOTE_HEX, nvidia_payload=NVIDIA_PAYLOAD
    )
    combined_result = await verifier.verify(report)
    print(f"Overall Model Verified: {combined_result.model_verified}")
    print(f"Hardware Type: {combined_result.hardware_type}")
    if combined_result.error:
        print(f"Error: {combined_result.error}")


if __name__ == "__main__":
    asyncio.run(test_verifiers())
