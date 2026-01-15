import dcap_qvl
import time
import json
from typing import Any, Dict
from ..types import VerificationResult, VerificationLevel
from .base import Verifier


class IntelTdxVerifier(Verifier):
    async def verify(self, quote: Any) -> VerificationResult:
        if isinstance(quote, str):
            quote_bytes = bytes.fromhex(quote)
        elif isinstance(quote, bytes):
            quote_bytes = quote
        else:
            raise ValueError("Quote must be hex string or bytes")

        try:
            result = await dcap_qvl.get_collateral_and_verify(quote_bytes)

            is_success = result.status in [
                "UpToDate",
                "SWHardeningNeeded",
                "ConfigurationNeeded",
                "ConfigurationAndSWHardeningNeeded",
                # "OutOfDate",
                # "OutOfDateConfigurationNeeded",
                # "Revoked",
            ]

            # Extract claims from to_json()
            result_json = json.loads(result.to_json())
            claims = {
                "status": result.status,
                "advisory_ids": getattr(result, "advisory_ids", []),
            }

            report = result_json.get("report", {})
            if "TD10" in report:
                claims.update(report["TD10"])
            elif "TD15" in report:
                claims.update(report["TD15"])

            if not is_success:
                return VerificationResult(
                    level=VerificationLevel.NONE,
                    timestamp=time.time(),
                    hardware_type=["INTEL_TDX"],
                    claims=claims,
                    raw=result_json,
                    error=f"Verification failed with status: {result.status}",
                )

            return VerificationResult(
                level=VerificationLevel.HARDWARE_TDX,
                timestamp=time.time(),
                hardware_type=["INTEL_TDX"],
                claims=claims,
                raw=result_json,
            )

        except Exception as e:
            return VerificationResult(
                level=VerificationLevel.NONE,
                timestamp=time.time(),
                hardware_type=["INTEL_TDX"],
                claims={},
                error=str(e),
            )
