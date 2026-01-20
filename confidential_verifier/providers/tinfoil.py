import requests
import base64
import gzip
import yaml
import os
from typing import List, Dict, Any, Optional
from .base import ServiceProvider
from ..types import AttestationReport
from ..verifiers import TinfoilTdxVerifier, Verifier


class TinfoilProvider(ServiceProvider):
    def __init__(self, config_path: Optional[str] = None):
        if not config_path:
            config_path = os.path.join(
                os.path.dirname(__file__), "../../config/tinfoil_config.yml"
            )
            if not os.path.exists(config_path):
                config_path = "config/tinfoil_config.yml"

        self.config_path = config_path
        self._cache = None

    def get_verifier(self) -> Verifier:
        return TinfoilTdxVerifier()

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

        # Get repo from config
        repo = None
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)
                repo = config.get("models", {}).get(model_id, {}).get("repo")
        except:
            pass

        data["repo"] = repo
        data["model_id"] = model_id

        return AttestationReport(
            provider="tinfoil",
            model_id=model_id,
            intel_quote=quote_bytes.hex(),
            nvidia_payload=None,
            raw=data,
        )

    def list_models(self) -> List[str]:
        return list(self._get_model_map().keys())
