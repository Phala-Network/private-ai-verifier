from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class AttestationReport(BaseModel):
    provider: str  # e.g., "tinfoil", "redpill", "nearai"
    model_id: Optional[str] = None
    intel_quote: str  # Hex string
    request_nonce: Optional[str] = None
    nvidia_payload: Optional[Dict[str, Any]] = None
    raw: Optional[Any] = None


# Hardware Types
HARDWARE_INTEL_TDX = "INTEL_TDX"
HARDWARE_NVIDIA_CC = "NVIDIA_CC"


class VerificationResult(BaseModel):
    model_verified: bool
    provider: str
    timestamp: float
    hardware_type: List[str]  # e.g., ["INTEL_TDX", "NVIDIA_CC"]
    model_id: Optional[str] = None
    request_nonce: Optional[str] = None
    signing_address: Optional[str] = None
    claims: Dict[str, Any]
    error: Optional[str] = None
    raw: Optional[Any] = None
