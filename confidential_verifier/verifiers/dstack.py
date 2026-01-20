import json
import logging
from typing import Any, Dict, Optional
import requests
from .base import Verifier

logger = logging.getLogger(__name__)


def verify_report_data(
    tdx_report_data_hex: str, signing_address: str, request_nonce: str
) -> Dict[str, Any]:
    """
    Verify that TDX report data binds the signing address and request nonce.
    Report Data (64 bytes) = [Signing Address (20 bytes + 12 bytes padding)] + [Nonce (32 bytes)]

    This is a shared helper used by dstack-based verifiers (Redpill, NearAI).
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


class DstackVerifier(Verifier):
    def __init__(
        self,
        service_url: Optional[str] = None,
    ):
        self.service_url = service_url or "http://localhost:8080"

    def verify(self, quote: str, event_log: str, vm_config: str) -> Dict[str, Any]:
        """Verifies the dstack TEE environment using the dstack-verifier service."""
        logger.info(f"Verifying with dstack-verifier service at {self.service_url}")
        try:
            payload = {
                "quote": quote,
                "event_log": event_log,
                "vm_config": vm_config,
            }
            response = requests.post(f"{self.service_url}/verify", json=payload)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to verify with dstack-verifier service: {e}")
            return {"is_valid": False, "reason": str(e)}
