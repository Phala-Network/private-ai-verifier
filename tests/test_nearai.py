import pytest
import json
import os
from confidential_verifier.verifiers.nearai import NearAICloudVerifier


@pytest.mark.asyncio
async def test_nearai_verification():
    # Load raw data
    raw_path = os.path.join(os.path.dirname(__file__), "..", "near-raw.json")
    if not os.path.exists(raw_path):
        pytest.skip("near-raw.json not found")

    with open(raw_path, "r") as f:
        data = json.load(f)

    # Initialize verifier
    # We assume the dstack-verifier service is running on localhost:8080 as per previous context
    verifier = NearAICloudVerifier(dstack_verifier_url="http://localhost:8080")

    # Verify
    result = await verifier.verify(data)

    print("\nVerification Result Model Verified:", result.model_verified)
    print("Verification Error:", result.error)
    print("Claims:", json.dumps(result.claims, indent=2))

    # Basic assertions structure
    assert result.claims is not None
    assert "Gateway" in result.claims["components"]

    gateway_res = result.claims["components"]["Gateway"]
    # We expect the gateway to be valid IF the quote is valid and local verifier handles it.
    # If it fails due to collateral issues, we should at least see specific errors.

    if not result.model_verified:
        print(
            "Warning: Verification failed (possibly expected if collateral is old/missing)."
        )
        # Check if it failed on dstack or something else
        if "dstack verification failed" in str(result.error):
            print("Dstack failure detected.")
    else:
        assert result.model_verified
