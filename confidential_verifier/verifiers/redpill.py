import logging
import time
import json
import requests
from typing import Dict, Any, Optional, List
from .base import Verifier
from .phala import PhalaCloudVerifier
from .dstack import verify_report_data
from ..types import VerificationResult

logger = logging.getLogger(__name__)


class RedpillVerifier(Verifier):
    """
    Verifier for Redpill models.

    Redpill models are Phala Cloud apps, so this verifier uses PhalaCloudVerifier
    internally to verify the dstack TEE environment (App/KMS/Gateway components).
    Additionally verifies nvidia GPU attestation and report data binding.
    """

    def __init__(self, dstack_verifier_url: Optional[str] = None):
        self.dstack_verifier_url = dstack_verifier_url

    @staticmethod
    def _extract_report_data_from_quote(intel_quote: str) -> Optional[str]:
        """
        Extract report_data (64 bytes) from TDX quote for nonce/address binding check.
        The Redpill intel_quote contains the nonce/address that was passed to the API.
        """
        try:
            quote_bytes = bytes.fromhex(intel_quote)
            # Header is 48 bytes, body starts at 48, report_data is at offset 520-584 in body
            body = quote_bytes[48 : 48 + 584]
            report_data = body[520:584]
            return report_data.hex()
        except Exception:
            return None

    @staticmethod
    def get_redpill_models() -> List[Dict[str, Any]]:
        """Fetches running models from Redpill API."""
        url = "https://api.redpill.ai/v1/models"
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("data", [])
        except Exception as e:
            logger.warning(f"Failed to fetch Redpill models: {e}")
            return []

    def _get_app_id_for_model(self, model_id: str) -> Optional[str]:
        """Look up the Phala app_id for a given Redpill model_id."""
        models = self.get_redpill_models()
        for model in models:
            if model.get("id") == model_id:
                return model.get("metadata", {}).get("appid")
        return None

    async def verify(self, report_data: Dict[str, Any]) -> VerificationResult:
        """
        Verify a Redpill model attestation report.

        Args:
            report_data: Raw attestation report from Redpill API containing:
                - model_id or model: The model identifier
                - intel_quote: TDX quote (optional, for report data verification)
                - nvidia_payload: GPU attestation payload
                - signing_address: Address for report data binding
                - request_nonce: Nonce for report data binding

        Returns:
            VerificationResult with verification status and claims.
        """
        try:
            # 1. Extract model_id and look up app_id
            model_id = report_data.get("model_id") or report_data.get("model")
            if not model_id:
                return VerificationResult(
                    model_verified=False,
                    timestamp=time.time(),
                    hardware_type=[],
                    claims={},
                    error="Missing model_id in report data",
                )

            app_id = self._get_app_id_for_model(model_id)
            if not app_id:
                return VerificationResult(
                    model_verified=False,
                    timestamp=time.time(),
                    hardware_type=[],
                    claims={"model_id": model_id},
                    error=f"Could not find Phala app_id for model {model_id}",
                )

            # 2. Parse nvidia_payload if it's a string
            nvidia_payload = report_data.get("nvidia_payload")
            if isinstance(nvidia_payload, str):
                try:
                    nvidia_payload = json.loads(nvidia_payload)
                except Exception as e:
                    logger.warning(f"Failed to parse nvidia_payload: {e}")
                    nvidia_payload = None

            # 3. Use PhalaCloudVerifier for TEE infrastructure verification
            phala_verifier = PhalaCloudVerifier(
                app_id=app_id,
                dstack_verifier_url=self.dstack_verifier_url,
            )
            result = await phala_verifier.verify(nvidia_payload=nvidia_payload)

            # Add model info to claims
            result.claims["model_id"] = model_id
            result.claims["app_id"] = app_id

            # If TEE verification failed, return early
            if not result.model_verified:
                return result

            # 4. Verify report data binding (nonce/address) against the Redpill intel_quote
            # The intel_quote from Redpill API contains the nonce/address that was passed to it
            request_nonce = report_data.get("request_nonce")
            signing_address = report_data.get("signing_address")
            intel_quote = report_data.get("intel_quote")

            # Extract report_data from the Redpill intel_quote
            report_data_hex = None
            if intel_quote:
                report_data_hex = self._extract_report_data_from_quote(intel_quote)

            if report_data_hex and request_nonce and signing_address:
                rd_check = verify_report_data(
                    report_data_hex, signing_address, request_nonce
                )
                result.claims["report_data_check"] = rd_check

                if not rd_check["valid"]:
                    return VerificationResult(
                        model_verified=False,
                        timestamp=result.timestamp,
                        hardware_type=result.hardware_type,
                        claims=result.claims,
                        raw=result.raw,
                        error=f"Report data binding failed: {rd_check.get('error') or 'Address/Nonce mismatch'}",
                    )

                result.claims["nonce_verified"] = True
                result.claims["signing_address_verified"] = True
                result.claims["request_nonce"] = request_nonce
                result.claims["signing_address"] = signing_address

            return result

        except Exception as e:
            logger.exception("Redpill verification failed")
            return VerificationResult(
                model_verified=False,
                timestamp=time.time(),
                hardware_type=[],
                claims={},
                error=str(e),
            )
