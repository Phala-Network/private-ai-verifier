# Tinfoil Verification

This document details the verification process for Tinfoil attestations, which includes both specialized hardware policies and automated manifest comparison.

## Multi-Platform Support

Tinfoil runs enclaves on **both** Intel TDX and AMD SEV-SNP hardware. The hardware type depends on the specific enclave:

| Endpoint Pattern | Hardware | Examples |
|-----------------|----------|----------|
| `*.inf*.tinfoil.sh` | Intel TDX | `llama3-3-70b.inf9.tinfoil.sh` |
| `router.inf*.tinfoil.sh` | AMD SEV-SNP | `router.inf6.tinfoil.sh` |
| `inference.tinfoil.sh` | AMD SEV-SNP | Central router |
| `*.tinfoil.functions.tinfoil.sh` | AMD SEV-SNP | `websearch.tinfoil.functions.tinfoil.sh` |

The `TinfoilVerifier` automatically detects the attestation format and applies the appropriate verification logic.

## Verification Flow

Tinfoil verification includes:

1.  **Hardware Attestation**: Validates that the workload runs in a genuine TEE (SEV-SNP or TDX)
2.  **Manifest Comparison**: Compares software measurements against "Golden Values" from Sigstore

### AMD SEV-SNP Verification

For SEV-SNP attestations, the verifier:

1. Parses the SEV-SNP attestation report
2. Extracts the measurement (48 bytes at offset 0x90)
3. Compares against Sigstore golden values
4. Returns `HARDWARE_AMD_SEV_SNP` in hardware_type

### Intel TDX Verification

For TDX attestations, the verifier enforces strict hardware policy checks:

- **MR_SEAM**: The measurement of the Intel TDX Module hash
- **TdAttributes**: Ensures debug mode is disabled
- **XFAM (Extended Features)**: Validates CPU features match Tinfoil's baseline
- **Zero Fields**: Ensures `MrOwner`, `MrOwnerConfig`, and `RTMR3` are zeroed

## Automated Manifest Comparison

Both platforms use Sigstore for software verification:

#### Sigstore Transparency Log

Tinfoil uses Sigstore to publish and sign "Golden Values" of their software releases. This allows the verifier to independently prove that the measurements match officially signed releases.

- **GitHub Proxy**: `api-github-proxy.tinfoil.sh` (fetches release tags and digests)
- **Attestation Proxy**: `gh-attestation-proxy.tinfoil.sh` (fetches Sigstore bundles)

#### Predicate Formats

- **`snp-tdx-multiplatform/v1`**: Contains measurements for both SEV-SNP and TDX
- **`sev-snp-guest/v2`**: SEV-SNP specific measurements
- **`tdx-guest/v2`**: Intel TDX specific measurements

## Data Collection & External APIs

1.  **Enclave Endpoints** (`https://{enclave}/.well-known/tinfoil-attestation`):
    - Direct attestation from specific enclaves (e.g., `llama3-3-70b.inf9.tinfoil.sh`)
    - Returns gzipped attestation report
    - Hardware type varies by enclave (TDX or SEV-SNP)
2.  **Router Endpoints**:
    - `inference.tinfoil.sh` - Central router (SEV-SNP)
    - `router.inf6.tinfoil.sh` - Alternative router (SEV-SNP)
3.  **Tinfoil GitHub Proxy** (`https://api-github-proxy.tinfoil.sh`):
    - Fetches latest release tags and the `tinfoil.hash` file
4.  **Sigstore Attestation Proxy** (`https://gh-attestation-proxy.tinfoil.sh`):
    - Fetches signed Sigstore bundles for application images

## Usage

```python
from confidential_verifier import TeeVerifier

verifier = TeeVerifier()

# Verify any Tinfoil model (auto-detects SEV-SNP or TDX)
result = await verifier.verify_model("tinfoil", "llama3-3-70b")

if result.model_verified:
    print(f"Verified!")
    print(f"Hardware: {result.hardware_type}")  # ['AMD_SEV_SNP'] or ['INTEL_TDX']
    print(f"Profile: {result.claims.get('hw_profile')}")
```

## Result Structure

```json
{
  "model_verified": true,
  "provider": "tinfoil",
  "hardware_type": ["AMD_SEV_SNP"],
  "claims": {
    "attestation_type": "sev-snp",
    "measurement": "abc123...",
    "repo": "tinfoilsh/confidential-llama3-3-70b"
  }
}
```

## References

- **Tinfoil Verifier Source**: [tinfoilsh/verifier](https://github.com/tinfoilsh/verifier)
- **Tinfoil Verification Docs**: [How to Verify](https://docs.tinfoil.sh/verification/how-to-verify)
- **AMD SEV-SNP**: [AMD SEV Documentation](https://www.amd.com/en/developer/sev.html)
