# Redpill (Phala Cloud) Verification

This guide explains how to verify Redpill models hosted on Phala Cloud.

## Overview

Redpill models run as secure apps on Phala Cloud, powered by the [dstack](https://dstack.ai) SDK. Verification involves checking:

1.  **Dstack TEE Environment**: Ensures the app is running in a secure Intel TDX enclave with the expected configuration.
2.  **GPU Attestation**: Ensures the Nvidia H100 GPU is genuine and trusted (if applicable).
3.  **App Integrity**: Verifies the application identity (`app_id`) and configuration.

## Provider Resale Verification

Redpill acts as a distribution layer for multiple TEE providers. Depending on the model, Redpill may delegate the core verification logic to the original provider's verifier:

- **Tinfoil Models**: Redpill uses the `TinfoilTdxVerifier` to check hardware policies and Sigstore-based manifest golden values.
- **NearAI Models**: Redpill uses the `NearAICloudVerifier` to verify the composite Gateway + Model attestation structure.
- **Phala Native Models**: Uses the native `PhalaCloudVerifier` logic.

The SDK automatically detects the provider and applies the correct verification strategy.

## Verification Process

The `PhalaCloudVerifier` implements the following steps:

1.  **Fetch System Info**: Retrieves the attestation data from Phala Cloud API using the App ID.
    - Endpoint: `https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations`
2.  **Dstack Verification**:
    - Extracts the Intel TDX Quote, Event Log, and VM Config.
    - Uses the `dstack-verifier` tool (Rust binary) to verify the TEE status and replay the event log. The `app_id` is a unique identifier derived from the application's configuration and image; the verifier ensures the hardware report matches this `app_id`.
    - Checks that the TCB (Trusted Computing Base) is up-to-date.
3.  **Nonce Verification** (Replay Protection):
    - The client generates a random 32-byte `nonce` for each request.
    - The TEE embeds this nonce (along with the signing address) into the TDX Report Data.
    - The verifier confirms that the `report_data` cryptographically binds the nonce and address, ensuring the report is fresh and intended for this specific request.
4.  **GPU Verification**:
    - Checks if the app has an assigned GPU.
    - Fetches the Nvidia Attestation Report from the Redpill API.
    - Verifies the Nvidia Remote Attestation Service (NRAS) token and checks for the `x-nvidia-overall-att-result` claim.

## Usage

### Using the Python SDK

You can verify a Redpill App by its App ID.

```python
import asyncio
from confidential_verifier.sdk import TeeVerifier

async def main():
    verifier = TeeVerifier()

    # App ID for the Redpill model (e.g., Llama 3)
    app_id = "bfe88926c2826cf14a819ef0ae7558cac3bf024c"

    print(f"Verifying App: {app_id}...")
    result = await verifier.verify_phala_app(app_id)

    if result.model_verified:
        print("Verification Successful!")
        print("Hardware:", result.hardware_type)
        print("Claims:", result.claims.keys())
    else:
        print("Verification Failed!")
        print("Error:", result.error)

if __name__ == "__main__":
    asyncio.run(main())
```

### Prerequisites

The verification relies on the `dstack-verifier` binary. The SDK will attempt to build it automatically using `cargo` if it is not found. Ensure `rust` and `cargo` are installed in your environment.

## Data Collection & External APIs

The Redpill verification flow collects data from several sources:

1.  **Redpill API** (`https://api.redpill.ai/v1`):
    - Fetches the initial attestation report and model metadata.
2.  **Phala Cloud API** (`https://cloud-api.phala.network/api/v1`):
    - Fetches detailed system information for the specific `app_id`, including Intel TDX quotes and event logs.
3.  **Dstack Verifier Service**:
    - Processes the hardware quotes retrieved from Phala Cloud.
4.  **Nvidia NRAS**:
    - Verifies GPU tokens if the model is running on an H100 instance.
5.  **Tinfoil/NearAI APIs**:
    - If the model is resold, the SDK hits the respective provider's APIs (e.g., Tinfoil Sigstore proxies) as part of the delegated verification.

A successful verification returns a result with the following claims:

- **dstack**: Details from the dstack verification (quote status, event log verification, app info).
- **phala_system_info**: Metadata about the Phala Cloud app instance.
- **nvidia**: (Optional) Claims from the Nvidia GPU attestation, including GPU identifiers and security status.

## References

- **Redpill Verification Guide**: [Redpill Developers](https://docs.redpill.ai/developers/guides/verification)
- **Phala Private AI Verification**: [Phala Docs](https://docs.phala.com/phala-cloud/confidential-ai/verify/overview)
- **Dstack Trust Center**: [Phala-Network/trust-center](https://github.com/Phala-Network/trust-center)
