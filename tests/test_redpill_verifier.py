import pytest
import secrets
from confidential_verifier.verifiers.redpill import RedpillVerifier


@pytest.mark.asyncio
async def test_redpill_verifier_report_data():
    verifier = RedpillVerifier()

    # 1. Generate nonce and address
    nonce_hex = secrets.token_hex(32)  # 64 chars
    signing_address_hex = "0x" + secrets.token_hex(20)  # 40 chars -> 20 bytes

    # 2. Construct valid report_data (64 bytes)
    # Address (20 bytes) + Padding (12 bytes) + Nonce (32 bytes)
    addr_bytes = bytes.fromhex(signing_address_hex[2:])
    addr_padded = addr_bytes.ljust(32, b"\x00")
    nonce_bytes = bytes.fromhex(nonce_hex)

    report_data_bytes = addr_padded + nonce_bytes
    report_data_hex = report_data_bytes.hex()

    # 3. Test _verify_report_data
    result = verifier._verify_report_data(
        report_data_hex, signing_address_hex, nonce_hex
    )
    assert result["valid"] is True
    assert result["address_match"] is True
    assert result["nonce_match"] is True

    # 4. Test Mismatch Nonce
    bad_nonce = secrets.token_hex(32)
    result = verifier._verify_report_data(
        report_data_hex, signing_address_hex, bad_nonce
    )
    assert result["valid"] is False
    assert result["nonce_match"] is False
    assert result["address_match"] is True

    # 5. Test Mismatch Address
    bad_addr = "0x" + secrets.token_hex(20)
    result = verifier._verify_report_data(report_data_hex, bad_addr, nonce_hex)
    assert result["valid"] is False
    assert result["address_match"] is False
    assert result["nonce_match"] is True

    # 6. Test Invalid Report Data Length
    result = verifier._verify_report_data("deadbeef", signing_address_hex, nonce_hex)
    assert result["valid"] is False
    assert "length" in result["error"]
