# Tinfoil Verification

This document details the verification process for Tinfoil attestations, which includes both specialized hardware policies and automated manifest comparison.

## Verification Flow

Tinfoil verification extends standard Intel TDX verification with two additional layers of security checks:

1.  **Hardware Policy Check**: Validates that the TEE is running in Tinfoil's specific, secure environment.
2.  **Manifest Comparison**: Compares the software measurements in the attestation against the expected "Golden Values" published in Tinfoil's transparency log (Sigstore).

### 1. Hardware Policy Check

The verifier enforces strict checks on the platform's configuration to ensure it matches Tinfoil's secure baseline.

- **MR_SEAM**: The measurement of the TDX Module. Must match one of Tinfoil's accepted TDX module versions.
- **TdAttributes**: Ensures debug mode is disabled (`0x0000001000000000`).
- **XFAM (Extended Features)**: Validates the CPU features available to the guest match Tinfoil's QEMU configuration (`0xe702060000000000`).
- **Zero Fields**: Ensures sensitive fields like `MrOwner`, `MrOwnerConfig`, and `RTMR3` are strictly zeroed out.

### 2. Automated Manifest Comparison

To verify that the code running inside the TEE is exactly what Tinfoil released, the SDK automatically fetches "Golden Values" from Tinfoil's transparency log.

#### Sigstore Integration

The verifier connects to Tinfoil's proxies to securely fetch attestation bundles:

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
3.  Checks if the quote's `MRTD` (Build measurement) and `RTMR0` (Firmware measurement) match any known validated profile.

## Usage

These checks are performed automatically when you verify a report from the `tinfoil` provider.

```python
verifier = TeeVerifier()
result = await verifier.verify_model("tinfoil", "doc-upload")

if result.model_verified:
    print(f"Verified! Hardware Profile: {result.claims.get('hw_profile')}")
```
