# Private AI Verifier

A unified API to fetch and verify attestation reports from various private AI providers (Redpill, Near AI, Tinfoil).

## Setup

1.  **Install dependencies**:

    ```bash
    bun install
    ```

2.  **Setup Tinfoil Configuration**:

    You must download the Tinfoil configuration file before running the server.

    ```bash
    bun run config:tinfoil
    ```

3.  **Start the server**:

    ```bash
    bun start
    ```

    For development with auto-reload:

    ```bash
    bun dev
    ```

    The server listens on `http://localhost:3000`.

## API Endpoints

### 1. List Providers

Get a list of supported service providers.

- **Endpoint**: `GET /providers`
- **Example**:

  ```bash
  curl http://localhost:3000/providers
  # Output: ["redpill", "nearai", "tinfoil"]
  ```

### 2. List Models

Get a list of available models for a specific service provider.

- **Endpoint**: `GET /models?service=<provider_name>`
- **Example**:

  ```bash
  curl "http://localhost:3000/models?service=redpill"
  curl "http://localhost:3000/models?service=tinfoil"
  ```

### 3. Verify Attestation

Fetch the attestation report for a specific model.

- **Endpoint**: `GET /verify`
- **Query Params**:
  - `service`: `redpill`, `nearai`, or `tinfoil`
  - `model`: Model ID (e.g., `openai/gpt-oss-120b`)

**Examples**:

```bash
# Redpill
curl "http://localhost:3000/verify?service=redpill&model=openai/gpt-oss-120b"

# Near AI
curl "http://localhost:3000/verify?service=nearai&model=deepseek-ai/DeepSeek-V3.1"

# Tinfoil
curl "http://localhost:3000/verify?service=tinfoil&model=gpt-oss-120b"
```

## Attestation Collection Mechanism

### 1. Redpill

- **Request**:

  ```http
  GET https://api.redpill.ai/v1/attestation/report?model={model_id}
  ```

- **Response Sample**:
  ```json
  {
    "intel_quote": "04000200...",
    "nvidia_payload": "{\"nonce\": \"...\", ...}",
    "metadata": { ... }
  }
  ```

### 2. Near AI

- **Request**:

  ```http
  GET https://cloud-api.near.ai/v1/attestation/report?model={model_id}&nonce={nonce}&signing_algo=ecdsa
  ```

- **Response Sample**:
  ```json
  {
    "model_attestations": [
      {
        "signing_address": "0x123...",
        "intel_quote": "04000200...",
        "nvidia_payload": "..."
      }
    ]
  }
  ```

### 3. Tinfoil

- **Request**:

  ```http
  GET https://{enclave-host}/.well-known/tinfoil-attestation
  ```

  _(Note: Hostname is determined by the model, e.g., `gpt-oss-120b.inf5.tinfoil.sh`)_

- **Response Sample**:

  ```json
  {
    "format": "https://tinfoil.sh/predicate/tdx-guest/v2",
    "body": "H4sIAAAAAAAA..." // Base64 encoded Gzipped data
  }
  ```

- **Verification details**:
  - The `body` must be Base64-decoded and then Gunzipped to get the raw **Intel TDX Quote**.
  - **GPU Verification**: Tinfoil does not expose a separate Nvidia report. The Enclave code (verified by the TDX Quote) is responsible for local GPU verification.
