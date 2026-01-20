# Tinfoil Verification

This document details the verification process for Tinfoil attestations, which includes both specialized hardware policies and automated manifest comparison.

## Verification Flow

Tinfoil verification extends standard Intel TDX verification with two additional layers of security checks:

1.  **Hardware Policy Check**: Validates that the TEE is running in Tinfoil's specific, secure environment.
2.  **Manifest Comparison**: Compares the software measurements in the attestation against the expected "Golden Values" published in Tinfoil's transparency log (Sigstore).

### 1. Hardware Policy Check

The verifier enforces strict checks on the platform's configuration to ensure it matches Tinfoil's secure baseline.

- **MR_SEAM**: The measurement of the Intel TDX Module hash. This must match a known, secure version of the Intel TDX firmware to ensure no vulnerabilities in the TEE management layer itself.
- **TdAttributes**: Ensures debug mode is disabled (`0x0000001000000000`). A debuggable enclave is not secure as its memory can be inspected by the host.
- **XFAM (Extended Features)**: Validates the CPU features (like AVX, AMX) available to the guest match Tinfoil's secure baseline (`0xe702060000000000`).
- **Zero Fields**: Ensures sensitive fields like `MrOwner`, `MrOwnerConfig`, and `RTMR3` are strictly zeroed out. `RTMR3` is often used for custom OS/runtime measurements; enforcing it as zero ensures a "pure" environment without side-loaded untrusted code.

### 2. Automated Manifest Comparison

To verify that the code running inside the TEE is exactly what Tinfoil released, the SDK automatically fetches "Golden Values" from Tinfoil's transparency log.

#### Sigstore Transparency Log

Tinfoil uses Sigstore to publish and sign "Golden Values" of their software releases and hardware profiles. This allows the verifier to independently prove that the measurements in the hardware quote match a version of the software that was officially signed and released by Tinfoil.

- **GitHub Proxy**: `api-github-proxy.tinfoil.sh` (fetches release tags and digests)
- **Attestation Proxy**: `gh-attestation-proxy.tinfoil.sh` (fetches Sigstore bundles)

#### Image Verification (RTMR1 & RTMR2)

For each model (e.g., `doc-upload`), the verifier:

1.  Identifies the corresponding GitHub repository (e.g., `tinfoilsh/confidential-doc-upload`).
2.  Fetches the latest release attestation bundle.
3.  Extracts the `snp-tdx-multiplatform/v1` predicate.
4.  Compares the `rtmr1` (user-space application) and `rtmr2` (kernel/initrd) in the quote against the values in the manifest.

#### Hardware Profile Verification (MRTD & RTMR0)

Tinfoil publishes global hardware measurements for its fleet. The verifier:

1.  Fetches the `hardware-measurements` bundle from `tinfoilsh/hardware-measurements`.
2.  Extracts known profiles (e.g., `medium_0d`).
3.  Checks if the quote's `MR_TD` (Build measurement) and `RT_MR0` (Firmware measurement) match any known validated profile.

## Data Collection & External APIs

Tinfoil verification is highly transparent and relies on public proxies to fetch signed measurements:

1.  **Enclave Host** (`https://{model-enclave-host}/.well-known/tinfoil-attestation`):
    - Fetches the gzipped TDX quote directly from the running service.
2.  **Tinfoil GitHub Proxy** (`https://api-github-proxy.tinfoil.sh`):
    - Fetches latest release tags and the `tinfoil.hash` file containing the SHA256 digest of the release artifact.
3.  **Sigstore Attestation Proxy** (`https://gh-attestation-proxy.tinfoil.sh`):
    - Fetches the signed Sigstore bundles for both the application image (`repo`) and the global hardware profiles (`tinfoilsh/hardware-measurements`).
4.  **Intel PCS (via Dstack/QVL)**:
    - Standard Intel TDX verification also involves reaching out to Intel's Provisioning Certification Service to validate the hardware collateral.

## Usage

These checks are performed automatically when you verify a report from the `tinfoil` provider.

```python
verifier = TeeVerifier()
result = await verifier.verify_model("tinfoil", "doc-upload")

if result.model_verified:
    print(f"Verified! Hardware Profile: {result.claims.get('hw_profile')}")
```

## References

- **Tinfoil Verifier Source**: [tinfoilsh/verifier](https://github.com/tinfoilsh/verifier)
- **Tinfoil Verification Docs**: [How to Verify](https://docs.tinfoil.sh/verification/how-to-verify)
