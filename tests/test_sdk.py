import pytest
import asyncio
import json
from confidential_verifier.sdk import TeeVerifier
from confidential_verifier.types import AttestationReport, VerificationLevel
from .test_data import INTEL_QUOTE_HEX, NVIDIA_PAYLOAD


@pytest.mark.asyncio
async def test_verifiers():
    verifier = TeeVerifier()

    print("\n--- Testing Intel TDX Verification ---")
    # Note: This might fail if collateral cannot be fetched or quote is expired
    # but we are testing the integration.
    intel_result = await verifier.intel_verifier.verify(INTEL_QUOTE_HEX)
    print(f"Level: {intel_result.level}")
    print(f"Error: {intel_result.error}")
    # print(f"Claims: {json.dumps(intel_result.claims, indent=2)}")

    print("\n--- Testing Nvidia CC Verification ---")
    # This calls Nvidia NRAS, which should work if the payload is valid and NRAS is up.
    nvidia_result = await verifier.nvidia_verifier.verify(NVIDIA_PAYLOAD)
    print(f"Level: {nvidia_result.level}")
    print(f"Error: {nvidia_result.error}")
    # print(f"Claims: {json.dumps(nvidia_result.claims, indent=2)}")

    print("\n--- Testing Combined Verification ---")
    report = AttestationReport(
        intel_quote=INTEL_QUOTE_HEX, nvidia_payload=NVIDIA_PAYLOAD
    )
    combined_result = await verifier.verify(report)
    print(f"Overall Level: {combined_result.level}")
    print(f"Hardware Type: {combined_result.hardware_type}")
    if combined_result.error:
        print(f"Error: {combined_result.error}")


if __name__ == "__main__":
    asyncio.run(test_verifiers())
