import requests
from typing import List, Dict, Any
from .base import ServiceProvider
from ..types import AttestationReport


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
            provider="redpill",
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
