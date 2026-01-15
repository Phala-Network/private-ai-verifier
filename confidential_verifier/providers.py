import requests
import base64
import gzip
import yaml
import os
import secrets
from typing import List, Dict, Any, Optional
from .types import AttestationReport


class ServiceProvider:
    def fetch_report(self, model_id: str) -> AttestationReport:
        raise NotImplementedError

    def list_models(self) -> List[str]:
        raise NotImplementedError


class TinfoilProvider(ServiceProvider):
    def __init__(self, config_path: Optional[str] = None):
        if not config_path:
            # Default path relative to this file
            config_path = os.path.join(
                os.path.dirname(__file__), "../config/tinfoil_config.yml"
            )
            # Fallback to current working directory
            if not os.path.exists(config_path):
                config_path = "config/tinfoil_config.yml"

        self.config_path = config_path
        self._cache = None

    def _get_model_map(self) -> Dict[str, str]:
        if self._cache is not None:
            return self._cache

        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)

            model_map = {}
            models = config.get("models", {})
            for name, data in models.items():
                enclaves = data.get("enclaves", [])
                if enclaves:
                    model_map[name] = enclaves[0]

            self._cache = model_map
            return model_map
        except Exception as e:
            print(f"Failed to load Tinfoil config from {self.config_path}: {e}")
            raise Exception("Failed to load Tinfoil configuration")

    def fetch_report(self, model_id: str) -> AttestationReport:
        model_map = self._get_model_map()
        host = model_map.get(model_id)

        if not host:
            if "." in model_id:
                host = model_id
            else:
                raise Exception(f"Unknown Tinfoil model: {model_id}")

        url = f"https://{host}/.well-known/tinfoil-attestation"
        print(f"[Tinfoil] Fetching from {url}")

        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        expected_prefix = "https://tinfoil.sh/predicate/tdx-guest/"
        fmt = data.get("format", "")
        if not fmt.startswith(expected_prefix):
            raise Exception(
                f"Unsupported Tinfoil attestation format: {fmt or 'missing'}"
            )

        body = data.get("body")
        if not body:
            raise Exception("Tinfoil response missing body")

        compressed_quote = base64.b64decode(body)
        quote_bytes = gzip.decompress(compressed_quote)

        return AttestationReport(
            intel_quote=quote_bytes.hex(), nvidia_payload=None, raw=data
        )

    def list_models(self) -> List[str]:
        return list(self._get_model_map().keys())


class RedpillProvider(ServiceProvider):
    def __init__(self):
        self.api_base = "https://api.redpill.ai/v1"

    def fetch_report(self, model_id: str) -> AttestationReport:
        url = f"{self.api_base}/attestation/report"
        print(f"[Redpill] Fetching from {url} for model {model_id}")

        response = requests.get(url, params={"model": model_id})
        response.raise_for_status()
        data = response.json()

        if "intel_quote" not in data:
            raise Exception("Redpill report missing intel_quote")

        nvidia_payload = data.get("nvidia_payload")
        if isinstance(nvidia_payload, str):
            try:
                import json

                nvidia_payload = json.loads(nvidia_payload)
            except:
                pass

        return AttestationReport(
            intel_quote=data["intel_quote"],
            nvidia_payload=nvidia_payload,
            raw=data,
        )

    def list_models(self) -> List[str]:
        url = f"{self.api_base}/models"
        print(f"[Redpill] Fetching models from {url}")
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        models = data if isinstance(data, list) else data.get("data", [])
        return [m["id"] for m in models]


class NearaiProvider(ServiceProvider):
    def __init__(self):
        self.api_base = "https://cloud-api.near.ai/v1"

    def fetch_report(self, model_id: str) -> AttestationReport:
        nonce = secrets.token_hex(32)
        params = {"model": model_id, "signing_algo": "ecdsa", "nonce": nonce}

        url = f"{self.api_base}/attestation/report"
        print(f"[Near] Fetching report for {model_id} with nonce {nonce[:8]}...")

        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        attestations = data.get("model_attestations", [])
        if not attestations or not isinstance(attestations, list):
            raise Exception("Near report missing model_attestations")

        first = attestations[0]
        nvidia_payload = first.get("nvidia_payload")
        if isinstance(nvidia_payload, str):
            try:
                import json

                nvidia_payload = json.loads(nvidia_payload)
            except:
                pass

        return AttestationReport(
            intel_quote=first["intel_quote"],
            nvidia_payload=nvidia_payload,
            raw=data,
        )

    def list_models(self) -> List[str]:
        url = f"{self.api_base}/model/list"
        print(f"[Near] Fetching models from {url}")
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        models = data if isinstance(data, list) else data.get("models", [])
        return [m if isinstance(m, str) else m.get("modelId") for m in models]
