from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class AttestationReport(BaseModel):
    provider: str  # e.g., "tinfoil", "redpill"
    intel_quote: str  # Hex string
    request_nonce: Optional[str] = None
    nvidia_payload: Optional[Dict[str, Any]] = None
    raw: Optional[Any] = None


class VerificationResult(BaseModel):
    model_verified: bool
    timestamp: float
    hardware_type: List[str]  # e.g., ["INTEL_TDX", "NVIDIA_CC"]
    claims: Dict[str, Any]
    raw: Optional[Any] = None
    error: Optional[str] = None
