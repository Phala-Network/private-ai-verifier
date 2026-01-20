# Redpill (Phala Cloud) Verification

This guide explains how to verify Redpill models hosted on Phala Cloud.

## Overview

Redpill models run as secure apps on Phala Cloud, powered by the [dstack](https://dstack.ai) SDK. Verification involves checking:

1.  **Dstack TEE Environment**: Ensures the app is running in a secure Intel TDX enclave with the expected configuration.
2.  **GPU Attestation**: Ensures the Nvidia H100 GPU is genuine and trusted (if applicable).
3.  **App Integrity**: Verifies the application identity and configuration.

## Verification Process

The `PhalaCloudVerifier` implements the following steps:

1.  **Fetch System Info**: Retrieves the attestation data from Phala Cloud API using the App ID.
    - Endpoint: `https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations`
2.  **Dstack Verification**:
    - Extracts the Intel TDX Quote, Event Log, and VM Config.
    - Uses the `dstack-verifier` tool (Rust binary) to verify the TEE status and replay the event log.
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

    if result.is_valid:
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

## Claims Structure

A successful verification returns a result with the following claims:

- **dstack**: Details from the dstack verification (quote status, event log verification, app info).
- **phala_system_info**: Metadata about the Phala Cloud app instance.
- **nvidia**: (Optional) Claims from the Nvidia GPU attestation, including GPU identifiers and security status.
