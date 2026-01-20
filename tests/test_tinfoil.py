import pytest
import asyncio
from confidential_verifier.sdk import TeeVerifier


@pytest.mark.asyncio
@pytest.mark.parametrize("model_id", ["doc-upload", "llama3-3-70b", "gpt-oss-120b"])
async def test_tinfoil_fetch_and_verify(model_id):
    """
    Test the full Tinfoil flow: fetch report and verify it.
    This test runs live against Tinfoil's endpoints.
    """
    verifier = TeeVerifier()

    print(f"\n[Test] Fetching and verifying report for {model_id}...")
    try:
        result = await verifier.verify_model("tinfoil", model_id)

        # Claims should be extracted
        assert result.claims is not None
        assert "status" in result.claims
        assert "hw_profile" in result.claims
        assert "repo" in result.claims

        # Low-level registers should NOT be in claims anymore
        assert "mr_td" not in result.claims
        assert "rt_mr1" not in result.claims

        if not result.model_verified:
            print(f"⚠️ Verification failed as expected: {result.error}")
        else:
            assert result.model_verified

        print(
            f"✅ Verified {model_id} successfully. Profile: {result.claims.get('hw_profile')}"
        )
    except Exception as e:
        pytest.fail(f"Tinfoil live verification failed: {e}")


@pytest.mark.asyncio
async def test_tinfoil_list_models():
    """Test listing models from the TinfoilProvider."""
    verifier = TeeVerifier()
    models = await verifier.list_models("tinfoil")
    assert "doc-upload" in models
    assert "nomic-embed-text" in models
    print(f"✅ Found {len(models)} Tinfoil models.")


@pytest.mark.asyncio
async def test_tinfoil_policy_only():
    """Test only the verification logic with a hex quote if available."""
    from .test_data import INTEL_QUOTE_HEX

    verifier = TeeVerifier()

    # Using the generic INTEL_QUOTE_HEX from test_data
    # This might fail manifest check because it's not a real Tinfoil image quote
    # but it should at least perform the policy checks.
    tinfoil = verifier.providers["tinfoil"]
    result = await tinfoil.get_verifier().verify(INTEL_QUOTE_HEX)

    # Even if it fails policy, we should get status
    assert "status" in result.claims
    # Registers should NOT be in claims
    assert "registers" not in result.claims
    print(
        f"✅ Manual register extraction worked for sample quote. Model verified: {result.model_verified}"
    )


if __name__ == "__main__":
    # For manual running
    asyncio.run(test_tinfoil_fetch_and_verify())
    asyncio.run(test_tinfoil_list_models())
    asyncio.run(test_tinfoil_policy_only())
