import json
import logging
from typing import Any, Dict, Optional
import requests
from .base import Verifier

logger = logging.getLogger(__name__)


class DstackVerifier(Verifier):
    def __init__(
        self,
        service_url: Optional[str] = None,
    ):
        self.service_url = service_url or "http://localhost:8080"

    def verify(self, quote: str, event_log: str, vm_config: str) -> Dict[str, Any]:
        """Verifies the dstack TEE environment using the dstack-verifier service."""
        logger.info(f"Verifying with dstack-verifier service at {self.service_url}")
        try:
            payload = {
                "quote": quote,
                "event_log": event_log,
                "vm_config": vm_config,
            }
            response = requests.post(f"{self.service_url}/verify", json=payload)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to verify with dstack-verifier service: {e}")
            return {"is_valid": False, "reason": str(e)}
