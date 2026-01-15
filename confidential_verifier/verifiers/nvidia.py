import requests
import base64
import json
import time
from typing import Dict, Any
from ..types import VerificationResult, VerificationLevel
from .base import Verifier


class NvidiaGpuVerifier(Verifier):
    def __init__(self):
        self.nras_url = "https://nras.attestation.nvidia.com/v3/attest/gpu"

    async def verify(self, payload: Dict[str, Any]) -> VerificationResult:
        try:
            response = requests.post(
                self.nras_url,
                json=payload,
                headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                },
            )

            if response.status_code != 200:
                raise Exception(f"NRAS responded with status {response.status_code}")

            tokens = response.json()
            if not isinstance(tokens, list) or len(tokens) < 1:
                raise Exception("Invalid response format: expected array")

            # Platform token at index 0
            platform_entry = tokens[0]
            if not isinstance(platform_entry, list) or platform_entry[0] != "JWT":
                raise Exception("Invalid platform token format")

            platform_jwt = platform_entry[1]
            platform_claims = self._decode_jwt(platform_jwt)

            is_valid = platform_claims.get("x-nvidia-overall-att-result") is True

            gpu_claims = {}
            if len(tokens) > 1 and isinstance(tokens[1], dict):
                gpu_tokens = tokens[1]
                if gpu_tokens:
                    first_gpu_key = list(gpu_tokens.keys())[0]
                    gpu_jwt = gpu_tokens[first_gpu_key]
                    if isinstance(gpu_jwt, str):
                        gpu_claims = self._decode_jwt(gpu_jwt)

            claims = {**platform_claims, **gpu_claims}

            return VerificationResult(
                level=(
                    VerificationLevel.HARDWARE_TDX_CC
                    if is_valid
                    else VerificationLevel.HARDWARE_TDX
                ),
                timestamp=time.time(),
                hardware_type=["NVIDIA_CC"],
                claims=claims,
                raw=tokens,
                error=None if is_valid else "Nvidia attestation result is false",
            )

        except Exception as e:
            return VerificationResult(
                level=VerificationLevel.NONE,
                timestamp=time.time(),
                hardware_type=["NVIDIA_CC"],
                claims={},
                error=str(e),
            )

    def _decode_jwt(self, token: str) -> Dict[str, Any]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {}

            payload_b64 = parts[1]
            # Add padding if needed
            missing_padding = len(payload_b64) % 4
            if missing_padding:
                payload_b64 += "=" * (4 - missing_padding)

            decoded = base64.b64decode(payload_b64).decode("utf-8")
            return json.loads(decoded)
        except Exception as e:
            print(f"Failed to decode JWT: {e}")
            return {}
