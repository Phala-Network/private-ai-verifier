# Intel Trust Authority (ITA) Support

This project supports remote appraisal of Intel TDX quotes using the Intel Trust Authority (ITA) API. This provides a cloud-based alternative or supplement to local DCAP QVL verification.

## Overview

When enabled, the `IntelTdxVerifier` (and its derivatives for Tinfoil, Redpill, and NearAI) will automatically send the TDX quote to Intel's Appraisal API. The result is a signed JWT token containing various claims about the TEE's state, which are then included in the `VerificationResult`.

## Configuration

To enable ITA support, you must obtain an API key from the [Intel Trust Authority Portal](https://portal.trustauthority.intel.com/) and set it in your environment:

1. Sign up at the [Intel Trust Authority Portal](https://portal.trustauthority.intel.com/login).
2. Create an API Key.
3. Copy `.env.example` to `.env`.
4. Set `INTEL_TRUST_AUTHORITY_API_KEY` with your key.

```bash
INTEL_TRUST_AUTHORITY_API_KEY="your-api-key-here"
```

## Usage

The ITA verification is performed automatically by `IntelTdxVerifier` if the API key is present.

```python
from confidential_verifier.verifiers import IntelTdxVerifier

verifier = IntelTdxVerifier()
result = await verifier.verify(quote_hex)

if "intel_trust_authority" in result.claims:
    ita_claims = result.claims["intel_trust_authority"]
    print(f"ITA Appraisal Status: {ita_claims.get('tdx', {}).get('attester_tcb_status')}")
```

## Sample Result

The `intel_trust_authority` claim in the `VerificationResult` contains the decoded JWT claims from Intel.

```json
"intel_trust_authority": {
  "appraisal": { "method": "default", "ver": 2 },
  "eat_profile": "https://portal.trustauthority.intel.com/eat_profile.html",
  "intuse": "generic",
  "tdx": {
    "attester_advisory_ids": [ ... ],
    "attester_tcb_date": "2025-05-14T00:00:00Z",
    "attester_tcb_status": "UpToDate",
    "attester_type": "TDX",
    "dbgstat": "disabled",
    "pce_svn": 13,
    "sgx_tcb_comp_svn": "...",
    "tdx_collateral": {
      "fmspc": "...",
      "qeidcerthash": "...",
      "qeidcrlhash": "...",
      "qeidhash": "...",
      "quotehash": "...",
      "tcbevaluationdatanumber": 20,
      "tcbinfocerthash": "...",
      "tcbinfocrlhash": "...",
      "tcbinfohash": "..."
    },
    "tdx_is_debuggable": false,
    "tdx_mrconfigid": "...",
    "tdx_mrowner": "...",
    "tdx_mrownerconfig": "...",
    "tdx_mrseam": "...",
    "tdx_mrsignerseam": "...",
    "tdx_mrtd": "...",
    "tdx_report_data": "...",
    "tdx_rtmr0": "...",
    "tdx_rtmr1": "...",
    "tdx_rtmr2": "...",
    "tdx_rtmr3": "...",
    "tdx_seam_attributes": "...",
    "tdx_seamsvn": 267,
    "tdx_td_attributes": "...",
    "tdx_td_attributes_debug": false,
    "tdx_td_attributes_key_locker": false,
    "tdx_td_attributes_perfmon": false,
    "tdx_td_attributes_protection_keys": false,
    "tdx_td_attributes_septve_disable": true,
    "tdx_tee_tcb_svn": "...",
    "tdx_xfam": "..."
  },
  "ver": "2.0.0",
  "verifier_instance_ids": [ "..." ],
  "exp": 1770106064,
  "jti": "...",
  "iat": 1770105764,
  "iss": "https://portal.trustauthority.intel.com",
  "nbf": 1770105764
}
```

## References

- [Intel Trust Authority Introduction](https://docs.trustauthority.intel.com/main/articles/articles/ita/introduction.html)
- [Intel Trust Authority Documentation Portal](https://docs.trustauthority.intel.com/)
