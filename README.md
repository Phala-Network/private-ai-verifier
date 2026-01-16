# Confidential Service Verifier Python SDK

A pure Python SDK for fetching and verifying TEE (Trusted Execution Environment) hardware attestation reports from various providers like Tinfoil, Redpill, and Near AI. Supports both Intel TDX and Nvidia CC (Confidential Computing) GPU attestation.

## Features

- **Multi-Provider Support**: Fetch reports from Tinfoil, Redpill, and Near AI.
- **Hardware Verification**:
  - **Intel TDX**: Using the `dcap-qvl` Python package.
  - **Nvidia CC**: Using Nvidia's NRAS (Nvidia Remote Attestation Service).
- **Clear Verification Levels**: Easily distinguish between failed, TDX-only, and TDX + GPU successful attestations.
- **`uv` Ready**: Managed with `uv` for modern, fast Python dependency management.
- **Built-in Server**: Includes a FastAPI server for testing and easy integration.

## Documentation

- [Tinfoil Verification Details](docs/tinfoil_verification.md): Explains hardware policy checks and automated Sigstore manifest comparison.

## Installation

Ensure you have `uv` installed. Then:

```bash
cd python-sdk
uv sync
```

## SDK Usage

The SDK provides a clean API with separate `fetch_report()` and `verify()` steps.

```python
import asyncio
from confidential_verifier import TeeVerifier

async def main():
    verifier = TeeVerifier()

    # 1. Fetch a report from a provider
    report = await verifier.fetch_report("redpill", "meta-llama/Llama-3.3-70B-Instruct")

    # 2. Verify the report
    result = await verifier.verify(report)

    print(f"Verification Level: {result.level}")
    if result.level == "HARDWARE_TDX_CC":
        print("Success: Both TDX and Nvidia CC are verified!")
    elif result.level == "HARDWARE_TDX":
        print("Success: TDX verified (no GPU or GPU verification failed).")
    else:
        print(f"Failed: {result.error}")

if __name__ == "__main__":
    asyncio.run(main())
```

### Verification Levels

- `NONE`: Verification failed.
- `HARDWARE_TDX`: Intel TDX hardware verification passed.
- `HARDWARE_TDX_CC`: Both Intel TDX and Nvidia CC (GPU) hardware verification passed.

## API Server

The SDK includes a FastAPI server that mirrors the functionality of the original TypeScript version.

### Run the Server

```bash
PYTHONPATH=. uv run python server/main.py
```

The server will be available at `http://0.0.0.0:8000`.

### Endpoints

- `GET /providers`: List available TEE providers.
- `GET /models?provider=<name>`: List supported models for a provider.
- `GET /fetch-report?provider=<name>&model_id=<id>`: Fetch an attestation report.
- `POST /verify`: Verify a JSON-encoded `AttestationReport`.

## Testing

Run the included test suite to verify the SDK against hardcoded test data:

```bash
PYTHONPATH=. uv run python -m tests.test_sdk
```

## Configuration

For **Tinfoil**, you may need to download the enclave configuration. The SDK looks for `tinfoil_config.yml` in the `python-sdk/config/` or the root `src/config/` directory.
