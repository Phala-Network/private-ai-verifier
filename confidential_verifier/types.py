from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class VerificationLevel(str, Enum):
    NONE = "NONE"
    HARDWARE_TDX = "HARDWARE_TDX"
    HARDWARE_TDX_CC = "HARDWARE_TDX_CC"


class AttestationReport(BaseModel):
    intel_quote: str  # Hex string
    nvidia_payload: Optional[Dict[str, Any]] = None
    raw: Optional[Any] = None


class VerificationResult(BaseModel):
    level: VerificationLevel
    timestamp: float
    hardware_type: List[str]  # e.g., ["INTEL_TDX", "NVIDIA_CC"]
    claims: Dict[str, Any]
    raw: Optional[Any] = None
    error: Optional[str] = None
