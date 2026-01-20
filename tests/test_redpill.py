import pytest
import asyncio
# PhalaCloudVerifier is internal - import directly from module
from confidential_verifier.verifiers.phala import PhalaCloudVerifier


@pytest.mark.asyncio
async def test_phala_live_verification():
    # Live app_id confirmed by user
    app_id = "0c92fd1f89abe33ab0c4ac7f86856f79217e9038"
    verifier = PhalaCloudVerifier(
        app_id,
        dstack_verifier_url="http://localhost:8080",
    )

    print(f"\nTesting live verification for App ID: {app_id}")

    # Port 8080 is mapped in dstack-verifier service
    # This will fetch attestation from Phala Cloud API and verify it locally.
    result = await verifier.verify()

    print(f"Verification result: {result.model_verified}")
    if result.error:
        print(f"Error: {result.error}")

    if "components" in result.claims:
        print("\nComponent Results:")
        for name, res in result.claims["components"].items():
            valid_str = "SUCCESS" if res["is_valid"] else "FAILED"
            compose_str = (
                "Verified" if res.get("compose_verified") else "Skipped/Failed"
            )
            print(f"  - {name}: {valid_str} (Compose Hash: {compose_str})")
            if not res["is_valid"]:
                print(f"    Reason: {res.get('reason')}")

    # Assertions for pytest
    assert (
        result.model_verified
    ), f"Verification failed with error: {result.error}"

    # Assert critical fields are present in claims
    assert "phala" in result.claims, "Missing 'phala' in result claims"
    phala_claims = result.claims["phala"]
    assert phala_claims.get("app_id") == app_id, "App ID mismatch in claims"
    assert "kms_info" in phala_claims, "Missing 'kms_info' in phala claims"

    print("\nOverall Verification Successful!")


if __name__ == "__main__":
    asyncio.run(test_phala_live_verification())
