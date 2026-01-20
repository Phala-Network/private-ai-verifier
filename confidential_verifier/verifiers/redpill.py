from typing import Dict, Any, Union
from .intel import IntelTdxVerifier
from ..types import VerificationResult


class RedpillVerifier(IntelTdxVerifier):
    def _verify_report_data(
        self, tdx_report_data_hex: str, signing_address: str, request_nonce: str
    ) -> Dict[str, Any]:
        """
        Verify that TDX report data binds the signing address and request nonce.
        Report Data (64 bytes) = [Signing Address (20 bytes + 12 bytes padding)] + [Nonce (32 bytes)]
        """
        try:
            report_data = bytes.fromhex(tdx_report_data_hex)
            if len(report_data) != 64:
                return {
                    "valid": False,
                    "error": f"Invalid report_data length: {len(report_data)}",
                }

            # extracted parts
            embedded_address_bytes = report_data[:32]
            embedded_nonce_bytes = report_data[32:]

            # Expected address
            if signing_address.startswith("0x"):
                signing_address = signing_address[2:]
            signing_address_bytes = bytes.fromhex(signing_address)
            # Pad to 32 bytes (right padding with zeros as per observation/reference)
            expected_address_bytes = signing_address_bytes.ljust(32, b"\x00")

            address_match = embedded_address_bytes == expected_address_bytes

            # Expected nonce (assuming nonce is 32 bytes hex string)
            # The nonce in JSON is hex string.
            expected_nonce_bytes = bytes.fromhex(request_nonce)
            nonce_match = embedded_nonce_bytes == expected_nonce_bytes

            return {
                "valid": address_match and nonce_match,
                "address_match": address_match,
                "nonce_match": nonce_match,
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    async def verify(self, quote: Union[str, Dict[str, Any]]) -> VerificationResult:
        # 1. Base verification
        result = await super().verify(quote)

        # If base fails, return result
        if not result.model_verified:
            return result

        # 2. Check nonce/address if available in quote input
        request_nonce = None
        signing_address = None

        if isinstance(quote, dict):
            request_nonce = quote.get("request_nonce")
            signing_address = quote.get("signing_address")

        report_data_hex = result.claims.get("report_data")
        if not report_data_hex:
            # Try finding in raw if not in claims
            # Or manually check if IntelTdxVerifier missed it?
            # Usually strict verifier should have it.
            pass

        if report_data_hex and request_nonce and signing_address:
            check = self._verify_report_data(
                report_data_hex, signing_address, request_nonce
            )
            if not check["valid"]:
                return VerificationResult(
                    model_verified=False,
                    timestamp=result.timestamp,
                    hardware_type=["INTEL_TDX"],
                    claims=result.claims,
                    raw=result.raw,
                    error=f"Report data mismatch: {check.get('error') or 'Address/Nonce mismatch'}",
                )

            # Update claims to indicate nonce verification passed
            result.claims["nonce_verified"] = True
            result.claims["signing_address_verified"] = True
            result.claims["request_nonce"] = request_nonce
            result.claims["signing_address"] = signing_address

        return result
