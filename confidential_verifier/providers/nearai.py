import requests
import secrets
from typing import List, Dict, Any
from .base import ServiceProvider
from ..types import AttestationReport


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
            provider="nearai",
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
