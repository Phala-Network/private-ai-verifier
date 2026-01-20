# Confidential Service Verifier Python SDK

A pure Python SDK for fetching and verifying TEE (Trusted Execution Environment) hardware attestation reports from various providers like Tinfoil, Redpill, and Near AI. Supports both Intel TDX and Nvidia CC (Confidential Computing) GPU attestation.

## 1. Dependencies and Pre-requisites

To ensure reliable verification, the following dependencies are required:

- **Python Runtime (`uv`)**: We use [uv](https://github.com/astral-sh/uv) for modern, fast Python dependency management.
- **Docker**: Required for running the `dstack-verifier` service.
- **DStack Verifier**: The verification process for Redpill and Near AI apps relies on `dstack-verifier`, which uses **QEMU** internally. QEMU is essential to stably reproduce ACPI table contents and other low-level boot measurements required for TDX quote verification.

### Setup

```bash
# 1. Start the dstack-verifier service
docker compose up -d

# 2. Sync dependencies
uv sync
```

## 2. Configuration

For **Tinfoil** verification, the SDK requires an enclave configuration file.

> [!IMPORTANT]
> Always ensure you are using the latest `tinfoil_config.yml`. The SDK looks for this file in `config/tinfoil_config.yml`.

To update the config:

```bash
# Fetch latest config
uv run scripts/update_config.py
```

## 3. Quick Test via Server

The SDK includes a FastAPI server for testing and easy integration. This is the fastest way to verify models.

### Run the Server

```bash
PYTHONPATH=. uv run python server/main.py
```

### Quick Verification Check

You can use `curl` to verify any supported model.

**Example: Verifying a Tinfoil Model**

```bash
curl "http://localhost:8000/verify-model?provider=tinfoil&model_id=kimi-k2-thinking"
```

**Example Output:**

```json
{
  "model_verified": true,
  "provider": "tinfoil",
  "timestamp": 1768923695.4072542,
  "hardware_type": ["INTEL_TDX"],
  "model_id": "kimi-k2-thinking",
  "claims": {
    "status": "UpToDate",
    "hw_profile": "large_1d_new"
  },
  "error": null
}
```

## 4. SDK Usage and Sample Outputs

The SDK provides a clean API for programmatic verification.

### Sample Code (Python)

```python
import asyncio
from confidential_verifier import TeeVerifier

async def main():
    verifier = TeeVerifier()

    # Verify a model directly (fetches + verifies)
    # Supports "redpill", "nearai", "tinfoil"
    result = await verifier.verify_model("redpill", "meta-llama/llama-3.3-70b-instruct")

    print(f"Model Verified: {result.model_verified}")
    print(f"Hardware: {result.hardware_type}")

    if result.model_verified:
        print(f"Claims: {result.claims}")
    else:
        print(f"Error: {result.error}")

if __name__ == "__main__":
    asyncio.run(main())
```

### Sample Outputs

#### NearAI

```json
{
  "model_verified": true,
  "provider": "nearai",
  "hardware_type": ["INTEL_TDX", "NVIDIA_CC"],
  "model_id": "openai/gpt-oss-120b",
  "request_nonce": "7299aba5...",
  "signing_address": "0x5c49f3...",
  "claims": {
    "components": {
      "gateway": { "is_valid": true, "tcb_status": "UpToDate" },
      "model": { "is_valid": true, "tcb_status": "UpToDate" }
    },
    "nvidia": { "x-nvidia-overall-att-result": true }
  }
}
```

#### Redpill

```json
{
  "model_verified": true,
  "provider": "redpill",
  "hardware_type": ["INTEL_TDX", "NVIDIA_CC"],
  "model_id": "phala/gpt-oss-20b",
  "claims": {
    "phala": { "model_provider": "phala" },
    "nvidia": { "x-nvidia-overall-att-result": true }
  }
}
```

#### Tinfoil

```json
{
  "model_verified": true,
  "provider": "tinfoil",
  "timestamp": 1768923695.4072542,
  "hardware_type": ["INTEL_TDX"],
  "model_id": "kimi-k2-thinking",
  "request_nonce": null,
  "signing_address": null,
  "claims": {
    "status": "UpToDate",
    "advisory_ids": [],
    "repo": "tinfoilsh/confidential-kimi-k2-thinking",
    "hw_profile": "large_1d_new"
  },
  "error": null
}
```

## Documentation

- [Tinfoil Verification Details](docs/tinfoil_verification.md)
- [Redpill Verification Details](docs/redpill_verification.md)
- [NearAI Verification Details](docs/nearai_verification.md)

## Features

- **Multi-Provider Support**: Tinfoil, Redpill, and Near AI.
- **Hardware Verification**: Intel TDX and Nvidia CC (GPU).
- **Phala Cloud Integration**: Native support for dstack apps on Phala.
- **Resale Verification**: Correctly verifies models resold between providers.
- **Automated Manifests**: Sigstore integration for Tinfoil.
