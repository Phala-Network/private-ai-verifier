# NearAI Verification

The NearAI verification process is designed to validate the integrity of both the NearAI Cloud Gateway and the specific AI Models running within Trusted Execution Environments (TEEs).

## Overview

Unlike single-service verifiers, the NearAI attestation report is a composite structure containing:

1.  **Gateway Attestation**: Verifies the NearAI Cloud infrastructure routing the request.
2.  **Model Attestations**: Verification for one or more AI models involved in the request.

The `NearAICloudVerifier` handles this complexity by iterating through each component and performing a suite of checks.

## Verification Process

For each component (Gateway and Models), the SDK performs the following checks:

### 1. Dstack TEE Verification

We use the `dstack-verifier` to validate the fundamental TEE properties:

- **Intel TDX Quote**: Verifies the hardware signature against Intel's root of trust.
- **Event Log**: Replays the TCG event log to ensure boot integrity.
- **VM Config**: Validates that the virtual machine configuration matches the expected state.

### 2. Report Data Binding

This is a critical cryptographic link between the service's identity and the client's specific request. The TEE's "Report Data" (64 bytes) is used as a commitment field that binds:

- **Signing Address**: The Ethereum-style address used by the gateway or model service to sign its API responses.
- **Request Nonce**: A unique random value provided by the client to prevent replay attacks.

By embedding these into the hardware-signed report, the verifier can guarantee that the response was signed by the specific code running inside the TEE and that the report is fresh (not a replay of an old report).

The check ensures:

```
report_data[0:32] == padding(signing_address)
report_data[32:64] == request_nonce
```

### 3. Compose Hash Verification

To ensure the correct application software is running:

- The valid `app_compose` (Docker Compose manifest) is extracted from the TCB Info. This manifest defines the exact container images (using content-addressable digests), environment variables, and volumes.
- Its SHA256 hash is calculated.
- This hash is compared against the `compose_hash` reported by the secure environment.

This ensures that the model hasn't been tampered with and is running the exact configuration claimed by the provider.

### 4. GPU Verification

For Model components, we verify the **Nvidia H100** attestation:

- Extracts the `nvidia_payload` (signed JWTs from the GPU).
- Verifies the chain of trust using Nvidia's Remote Attestation Service (NRAS).
- Ensures the GPU's localized nonce matches the request nonce.

## Usage

To use NearAI verification, simply specify the `nearai` provider:

```python
from confidential_verifier import TeeVerifier

verifier = TeeVerifier()

# Fetch a report (this includes Gateway + Model data)
report = await verifier.fetch_report("nearai", "deepseek-ai/DeepSeek-V3.1")

# Verify
result = await verifier.verify(report)

if result.model_verified:
    print("Success: Gateway (TDX) and Model (TDX + GPU) are verified.")
```

## Result Structure

The `verification_result.claims` will contain a structured breakdown:

```json
{
  "components": {
    "Gateway": { "is_valid": true, ... },
    "Model-0": {
      "is_valid": true,
      "details": { "gpu": { ... } }
    }
  }
}
```

## Data Collection & External APIs

During the verification process, the SDK interacts with the following service points:

1.  **NearAI Cloud API** (`https://cloud-api.near.ai/v1`):
    - Fetches the composite `AttestationReport` containing Gateway and Model quotes.
    - Requires a client-generated `nonce` for cryptographic binding.
2.  **Dstack Verifier Service** (Local or Remote):
    - Used to verify Intel TDX quotes and replay event logs.
    - Communicates via `POST /verify` to the configured `dstack_verifier_url`.
3.  **Nvidia Remote Attestation Service (NRAS)** (`https://nras.attestation.nvidia.com`):
    - Used to verify the GPU's signed JWT tokens.
    - Validates the hardware identity and security state of the Nvidia H100 GPU.

## References

- **NearAI Cloud Verifier**: [nearai-cloud-verifier](https://github.com/nearai/nearai-cloud-verifier)
- **NearAI Verification Documentation**: [Verification Overview](https://docs.near.ai/cloud/verification)
