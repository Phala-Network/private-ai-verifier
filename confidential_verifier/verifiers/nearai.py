from typing import Dict, Optional, Any
import json
import hashlib
import logging
import time
from .dstack import DstackVerifier
from ..types import VerificationResult
from .nvidia import NvidiaGpuVerifier

logger = logging.getLogger(__name__)


class NearAICloudVerifier:
    def __init__(self, dstack_verifier_url: str = "http://localhost:8080"):
        self.dstack_verifier = DstackVerifier(service_url=dstack_verifier_url)
        self.nvidia_verifier = NvidiaGpuVerifier()

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

    def _verify_compose_hash(self, app_compose: str, expected_hash: str) -> bool:
        if not app_compose:
            return False

        # Calculate SHA256 of the raw app_compose string
        calculated_hash = hashlib.sha256(app_compose.encode("utf-8")).hexdigest()
        return calculated_hash.lower() == expected_hash.lower()

    async def _verify_component(
        self,
        name: str,
        attestation_data: Dict[str, Any],
        request_nonce: Optional[str] = None,
    ) -> Dict[str, Any]:

        results = {"name": name, "is_valid": False, "details": {}, "errors": []}

        try:
            quote = attestation_data.get("intel_quote")
            # Event log might be a JSON object or string, dstack verifier expects string if it's not None
            event_log = attestation_data.get("event_log")
            if isinstance(event_log, (dict, list)):
                event_log = json.dumps(event_log)

            info = attestation_data.get("info", {})
            tcb_info = info.get("tcb_info", {})
            if isinstance(tcb_info, str):
                try:
                    tcb_info = json.loads(tcb_info)
                except:
                    pass

            app_compose = tcb_info.get("app_compose")
            vm_config = info.get("vm_config")  # From gateway_attestation.info.vm_config
            if not vm_config:
                # Try tcb_info if not in info
                vm_config = tcb_info.get("vm_config")

            if isinstance(vm_config, (dict, list)):
                vm_config = json.dumps(vm_config)

            # 1. Dstack Verification (Quote, Event Log, OS Image)
            # Make the call Synchronous
            dstack_result = self.dstack_verifier.verify(
                quote=quote, event_log=event_log, vm_config=vm_config
            )

            # If dstack returns "is_valid": False, check if we can proceed? Usually no.
            results["details"]["dstack"] = dstack_result

            is_valid_dstack = dstack_result.get("is_valid", False)
            if not is_valid_dstack:
                results["errors"].append(
                    f"Dstack verification failed: {dstack_result.get('reason', 'unknown')}"
                )

            # 2. Compose Hash Verification
            reported_compose_hash = info.get("compose_hash")
            # If dstack verified quote, we might want to verify compose hash even if dstack failed?
            # Dstack failure might be due to collateral but integrity might be ok?
            # No, if dstack fails integrity check (quote invalid), then everything is suspect.
            # But let's proceed to check other things for diagnostic.

            compose_verified = False
            if app_compose and reported_compose_hash:
                compose_verified = self._verify_compose_hash(
                    app_compose, reported_compose_hash
                )
                if not compose_verified:
                    results["errors"].append("Compose hash mismatch")
            elif app_compose:
                # Optional warning
                pass

            results["details"]["compose_verified"] = compose_verified

            # 3. Report Data Verification (Nonce & Address)
            signing_address = attestation_data.get("signing_address")

            # Try to get report data from dstack result if available
            report_data_hex = dstack_result.get("report_data")

            # If not available from dstack (e.g. failure or not returned), try to parse manually using IntelTdxVerifier logic?
            # For robustness, let's assume if dstack failed, report_data might be untrusted.
            # But here we want to see if it binds correctly even if collateral is missing.
            # We can use IntelTdxVerifier()._parse_quote() logic if it was public.
            # Assuming we rely on dstack_result for now.

            if report_data_hex and request_nonce and signing_address:
                rd_result = self._verify_report_data(
                    report_data_hex, signing_address, request_nonce
                )
                results["details"]["report_data_check"] = rd_result
                if not rd_result["valid"]:
                    results["errors"].append(
                        f"Report data check failed: {rd_result.get('error') or 'mismatch'}"
                    )

            # 4. GPU Verification
            nvidia_payload = attestation_data.get("nvidia_payload")
            if nvidia_payload:
                if isinstance(nvidia_payload, str):
                    try:
                        nvidia_payload = json.loads(nvidia_payload)
                    except:
                        pass

                gpu_nonce = nvidia_payload.get("nonce")
                if request_nonce and gpu_nonce:
                    if request_nonce.lower() != gpu_nonce.lower():
                        results["errors"].append(
                            f"GPU nonce mismatch: expected {request_nonce}, got {gpu_nonce}"
                        )

                # Nvidia verifier is async
                gpu_result = await self.nvidia_verifier.verify(nvidia_payload)
                try:
                    gpu_details = gpu_result.model_dump()
                except AttributeError:
                    gpu_details = gpu_result.dict()  # Fallback

                results["details"]["gpu"] = gpu_details

                if not gpu_result.model_verified:
                    results["errors"].append(
                        f"GPU verification failed: {gpu_result.error}"
                    )

            results["is_valid"] = (len(results["errors"]) == 0) and is_valid_dstack

        except Exception as e:
            logger.exception(f"Error verifying component {name}")
            results["errors"].append(str(e))

        return results

    async def verify(
        self, report_data: Dict[str, Any], request_nonce: Optional[str] = None
    ) -> VerificationResult:
        component_results = {}

        gateway_data = report_data.get("gateway_attestation")
        if not gateway_data:
            return VerificationResult(
                model_verified=False,
                error="Missing gateway_attestation",
                timestamp=time.time(),
                hardware_type=[],
                claims={},
            )

        if not request_nonce:
            request_nonce = gateway_data.get("request_nonce")

        gateway_res = await self._verify_component(
            "Gateway", gateway_data, request_nonce
        )
        component_results["Gateway"] = gateway_res

        model_attestations = report_data.get("model_attestations", [])
        for i, model_data in enumerate(model_attestations):
            name = f"Model-{i}"
            model_res = await self._verify_component(name, model_data, request_nonce)
            component_results[name] = model_res

        all_valid = all(C.get("is_valid", False) for C in component_results.values())
        errors = [
            err for C in component_results.values() for err in C.get("errors", [])
        ]

        model_verified = all_valid
        # Always list detected hardware
        hardware_types = ["intel_tdx"]

        has_gpu = False
        for C in component_results.values():
            if "gpu" in C.get("details", {}):
                has_gpu = True

        if model_verified and has_gpu:
            hardware_types.append("nvidia_gpu")

        # Basic claims structure
        claims = {
            "components": component_results,
            "request_nonce": request_nonce,
            "signing_address": gateway_data.get("signing_address"),
        }

        return VerificationResult(
            model_verified=model_verified,
            error="; ".join(errors) if errors else None,
            claims=claims,
            hardware_type=hardware_types,
            timestamp=time.time(),
        )
