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
  curl "http://localhost:3000/models?service=nearai"
  curl "http://localhost:3000/models?service=tinfoil"
  ```

### 3. Fetch Attestation Report

Fetch the raw attestation report for a specific model.

- **Endpoint**: `GET /report`
- **Query Params**:
  - `service`: `redpill`, `nearai`, or `tinfoil`
  - `model`: Model ID (e.g., `openai/gpt-oss-120b`)

**Examples**:

```bash
# Redpill
curl "http://localhost:3000/report?service=redpill&model=openai/gpt-oss-120b"

# Near AI
curl "http://localhost:3000/report?service=nearai&model=deepseek-ai/DeepSeek-V3.1"

# Tinfoil
curl "http://localhost:3000/report?service=tinfoil&model=gpt-oss-120b"
```

### 4. Verify Attestation Report

Verify the validity of a fetched attestation report. The Intel TDX quote is mandatory; the Nvidia GPU payload is optional.

- **Endpoint**: `POST /verify`
- **Body**: The JSON attestation report object (obtained from `/report` or compatible source).
- **Response**: A standardized object containing a mandatory `intel` field and an optional `nvidia` field.

**Example**:

```bash
# 1. Fetch report and save to file
curl "http://localhost:3000/report?service=redpill&model=openai/gpt-oss-120b" > report.json

# 2. Verify the report
curl -X POST -H "Content-Type: application/json" -d @report.json http://localhost:3000/verify
```

**Standardized Response Format**:

The result maintains independence between CPU and GPU verification results:

```json
{
  "intel": {
    "isValid": true,
    "timestamp": 1767507476806,
    "hardwareType": "INTEL_TDX",
    "claims": {
        "mrTd": "...",
        "rtMr0": "...",
        "reportData": "..."
    },
    "raw": { ... }
  },
  "nvidia": {
    "isValid": true,
    "timestamp": 1767507477198,
    "hardwareType": "NVIDIA_CC",
    "claims": {
        "x-nvidia-overall-att-result": true,
        "ueid": "..."
    },
    "raw": [ ... ]
  }
}
```

If only Intel is present or verified, the `nvidia` field will be absent. If `intel_quote` is missing from the request, the `intel` object will contain an error status.

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
  - **Predicate Documentation**: More details about the Tinfoil attestation format can be found at [https://docs.tinfoil.sh/verification/predicate](https://docs.tinfoil.sh/verification/predicate).
