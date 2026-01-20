import dcap_qvl
import time
import json
from typing import Any, Dict
from ..types import VerificationResult
from .base import Verifier


class IntelTdxVerifier(Verifier):
    async def verify(self, quote: Any) -> VerificationResult:
        model_id = None
        repo = None
        if isinstance(quote, str):
            quote_bytes = bytes.fromhex(quote)
        elif isinstance(quote, bytes):
            quote_bytes = quote
        elif isinstance(quote, dict):
            quote_hex = quote.get("quote", "")
            quote_bytes = (
                bytes.fromhex(quote_hex) if isinstance(quote_hex, str) else quote_hex
            )
            model_id = quote.get("model_id")
            repo = quote.get("repo")
        else:
            raise ValueError("Quote must be hex string, bytes, or dict")

        try:
            result = await dcap_qvl.get_collateral_and_verify(quote_bytes)
            res = self._format_result(result)
            if model_id:
                res.claims["model_id"] = model_id
            if repo:
                res.claims["repo"] = repo
            return res
        except Exception as e:
            # Best effort: manual parse for registers if verification fails
            claims = self._manual_parse_tdx(quote_bytes)
            if model_id:
                claims["model_id"] = model_id
            if repo:
                claims["repo"] = repo
            return VerificationResult(
                model_verified=False,
                timestamp=time.time(),
                hardware_type=["INTEL_TDX"],
                claims=claims,
                error=f"Verification failed: {e}",
            )

    def _format_result(self, result: Any) -> VerificationResult:
        is_success = result.status in [
            "UpToDate",
            "SWHardeningNeeded",
            "ConfigurationNeeded",
            "ConfigurationAndSWHardeningNeeded",
            # "OutOfDate",
            # "OutOfDateConfigurationNeeded",
            # "Revoked",
        ]

        result_json = json.loads(result.to_json())
        claims = {
            "status": result.status,
            "advisory_ids": getattr(result, "advisory_ids", []),
        }

        report = result_json.get("report", {})
        report_data = {}
        if "TD10" in report:
            report_data = report["TD10"]
        elif "TD15" in report:
            report_data = report["TD15"]

        if report_data:
            claims.update(report_data)
            claims["registers"] = [
                report_data.get("mr_td", ""),
                report_data.get("rt_mr0", ""),
                report_data.get("rt_mr1", ""),
                report_data.get("rt_mr2", ""),
                report_data.get("rt_mr3", ""),
            ]

        if not is_success:
            return VerificationResult(
                model_verified=False,
                timestamp=time.time(),
                hardware_type=["INTEL_TDX"],
                claims=claims,
                raw=result_json,
                error=f"Verification failed with status: {result.status}",
            )

        return VerificationResult(
            model_verified=True,
            timestamp=time.time(),
            hardware_type=["INTEL_TDX"],
            claims=claims,
            raw=result_json,
        )

    def _manual_parse_tdx(self, quote_bytes: bytes) -> Dict[str, Any]:
        """Manually extract TDX V4 fields from quote bytes."""
        try:
            # Header is 48 bytes. Body starts at 48.
            body = quote_bytes[48 : 48 + 584]
            return {
                "tee_tcb_svn": body[0:16].hex(),
                "mr_seam": body[16:64].hex(),
                "mr_signer_seam": body[64:112].hex(),
                "seam_attributes": body[112:120].hex(),
                "td_attributes": body[120:128].hex(),
                "xfam": body[128:136].hex(),
                "mr_td": body[136:184].hex(),
                "mr_config_id": body[184:232].hex(),
                "mr_owner": body[232:280].hex(),
                "mr_owner_config": body[280:328].hex(),
                "rt_mr0": body[328:376].hex(),
                "rt_mr1": body[376:424].hex(),
                "rt_mr2": body[424:472].hex(),
                "rt_mr3": body[472:520].hex(),
                "report_data": body[520:584].hex(),
                "registers": [
                    body[136:184].hex(),
                    body[328:376].hex(),
                    body[376:424].hex(),
                    body[424:472].hex(),
                    body[472:520].hex(),
                ],
            }
        except Exception:
            return {}
