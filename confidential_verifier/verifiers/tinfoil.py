import time
import requests
import json
import base64
from typing import Any, List, Dict
from .intel import IntelTdxVerifier
from ..types import VerificationResult

# Hardcoded Tinfoil Policy Values
# derived from https://github.com/tinfoilsh/verifier/blob/main/attestation/tdx.go

# Accepted MR_SEAM values (TDX Module hash) for Tinfoil's environment
ACCEPTED_MR_SEAMS = [
    "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6",
    # Newer TDX module version
    "685f891ea5c20e8fa27b151bf34bf3b50fbaf7143cc53662727cbdb167c0ad8385f1f6f3571539a91e104a1c96d75e04",
]

# Expected TdAttributes: Debug must be disabled (bit 1 off) among other flags
EXPECTED_TD_ATTRIBUTES = "0000001000000000"

# Expected XFAM (Extended Features available to Guest)
# Matches Tinfoil's QEMU configuration for TDX guests
EXPECTED_XFAM = "e702060000000000"

# Zero constants for validation
ZERO_48 = "00" * 48
RTMR3_ZERO = "00" * 48


class TinfoilTdxVerifier(IntelTdxVerifier):
    async def verify(self, quote: Any) -> VerificationResult:
        # Use a temporary dict for policy check that contains low-level info
        # because the base IntelTdxVerifier._format_result already removed them from result.claims
        # Wait, if I call super().verify(quote), and it succeeds, it returns a result with clean claims.
        # But tinfoil needs those claims to check policy.

        # Let's override verify to do manual parse for policy check first or use the raw result if we had it.
        # Actually, let's just use the manual parse for now to get the fields needed for policy.
        if isinstance(quote, str):
            quote_bytes = bytes.fromhex(quote)
        elif isinstance(quote, bytes):
            quote_bytes = quote
        elif isinstance(quote, dict):
            quote_hex = quote.get("quote", "")
            quote_bytes = (
                bytes.fromhex(quote_hex) if isinstance(quote_hex, str) else quote_hex
            )
        else:
            raise ValueError("Quote must be hex string, bytes, or dict")

        internal_claims = self._manual_parse_tdx(quote_bytes)

        # Now call base verify to get the official verification status
        result = await super().verify(quote)
        result.provider = "tinfoil"

        # The base verifier might have set repo if it was in the quote dict
        repo = internal_claims.get("repo") or (
            quote.get("repo") if isinstance(quote, dict) else None
        )
        reasons = []

        # 1. Hardware Policy (MrSeam, Attributes, Xfam, Zero fields)
        self._check_hardware_policy(internal_claims, reasons)

        # 2. Manifest Comparison (Golden Values)
        if repo:
            try:
                await self._check_manifest_policy(internal_claims, repo, reasons)
                # If hw_profile was found, add it to the final result claims
                if "hw_profile" in internal_claims:
                    result.claims["hw_profile"] = internal_claims["hw_profile"]
                result.claims["repo"] = repo
            except Exception as e:
                reasons.append(f"Manifest check failed: {e}")

        if reasons:
            result.model_verified = False
            result.error = (
                (result.error + "; " if result.error else "")
                + "Policy violation: "
                + ", ".join(reasons)
            )

        return result

    def _check_hardware_policy(self, claims: Dict[str, Any], reasons: List[str]):
        mr_seam = claims.get("mr_seam", "")
        if mr_seam not in ACCEPTED_MR_SEAMS:
            reasons.append(f"Invalid MrSeam: {mr_seam}")

        if claims.get("td_attributes", "") != EXPECTED_TD_ATTRIBUTES:
            reasons.append(f"Invalid TdAttributes: {claims.get('td_attributes')}")

        if claims.get("xfam", "") != EXPECTED_XFAM:
            reasons.append(f"Invalid Xfam: {claims.get('xfam')}")

        if claims.get("mr_owner", "") != ZERO_48:
            reasons.append("mr_owner is not zero")

        if claims.get("mr_owner_config", "") != ZERO_48:
            reasons.append("mr_owner_config is not zero")

        # RTMR3 must be zero
        rtmr3 = claims.get("rt_mr3", "")
        if rtmr3 and rtmr3 != RTMR3_ZERO:
            reasons.append("RTMR3 is not zeroed")

    async def _check_manifest_policy(
        self, claims: Dict[str, Any], repo: str, reasons: List[str]
    ):
        # 1. Fetch Image measurements (RTMR1, RTMR2)
        golden_image = self._fetch_golden_measurements(repo)

        actual_rtmr1 = claims.get("rt_mr1")
        actual_rtmr2 = claims.get("rt_mr2")

        if golden_image.get("rtmr1") != actual_rtmr1:
            reasons.append(
                f"RTMR1 mismatch: expected {golden_image.get('rtmr1')}, got {actual_rtmr1}"
            )

        if golden_image.get("rtmr2") != actual_rtmr2:
            reasons.append(
                f"RTMR2 mismatch: expected {golden_image.get('rtmr2')}, got {actual_rtmr2}"
            )

        # 2. Fetch Hardware measurements (MRTD, RTMR0) and match profile
        hw_profiles = self._fetch_hardware_measurements()

        actual_mrtd = claims.get("mr_td")
        actual_rtmr0 = claims.get("rt_mr0")

        found_profile = False
        for profile_name, values in hw_profiles.items():
            if (
                values.get("mrtd") == actual_mrtd
                and values.get("rtmr0") == actual_rtmr0
            ):
                found_profile = True
                claims["hw_profile"] = profile_name
                break

        if not found_profile:
            reasons.append(
                f"No matching hardware profile found for MRTD={actual_mrtd[:8]}... RTMR0={actual_rtmr0[:8]}..."
            )

    def _fetch_golden_measurements(self, repo: str) -> Dict[str, str]:
        # Tinfoil's image attestations: SnpTdxMultiPlatformV1
        bundle = self._fetch_sigstore_bundle(repo)
        payload = self._extract_payload(bundle)

        if (
            payload.get("predicateType")
            == "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
        ):
            tdx = payload.get("predicate", {}).get("tdx_measurement", {})
            return {
                "rtmr1": tdx.get("rtmr1"),
                "rtmr2": tdx.get("rtmr2"),
            }
        return {}

    def _fetch_hardware_measurements(self) -> Dict[str, Dict[str, str]]:
        repo = "tinfoilsh/hardware-measurements"
        bundle = self._fetch_sigstore_bundle(repo)
        payload = self._extract_payload(bundle)

        profiles = {}
        if (
            payload.get("predicateType")
            == "https://tinfoil.sh/predicate/hardware-measurements/v1"
        ):
            predicate = payload.get("predicate", {})
            for name, values in predicate.items():
                profiles[name] = {
                    "mrtd": values.get("mrtd"),
                    "rtmr0": values.get("rtmr0"),
                }
        return profiles

    def _fetch_sigstore_bundle(self, repo: str) -> Dict[str, Any]:
        try:
            url_latest = (
                f"https://api-github-proxy.tinfoil.sh/repos/{repo}/releases/latest"
            )
            resp = requests.get(url_latest, timeout=10)
            resp.raise_for_status()
            tag = resp.json().get("tag_name")

            url_hash = f"https://api-github-proxy.tinfoil.sh/{repo}/releases/download/{tag}/tinfoil.hash"
            resp_hash = requests.get(url_hash, timeout=10)
            resp_hash.raise_for_status()
            digest = resp_hash.text.strip()

            url_attestation = f"https://gh-attestation-proxy.tinfoil.sh/repos/{repo}/attestations/sha256:{digest}"
            resp_att = requests.get(url_attestation, timeout=10)
            resp_att.raise_for_status()
            att_data = resp_att.json()

            if "attestations" in att_data and len(att_data["attestations"]) > 0:
                return att_data["attestations"][0].get("bundle", {})
        except Exception as e:
            print(f"Warning: Failed to fetch Sigstore bundle for {repo}: {e}")
        return {}

    def _extract_payload(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        try:
            payload_b64 = bundle.get("dsseEnvelope", {}).get("payload")
            if payload_b64:
                return json.loads(base64.b64decode(payload_b64).decode("utf-8"))
        except:
            pass
        return {}
