from .intel import IntelTdxVerifier
from .nvidia import NvidiaGpuVerifier
from .tinfoil import TinfoilTdxVerifier, TinfoilVerifier
from .base import Verifier
from .dstack import DstackVerifier, verify_report_data
from .redpill import RedpillVerifier
from .nearai import NearAICloudVerifier
from .chutes import ChutesVerifier

# Helper verifiers (internal, basic verification primitives)
# - IntelTdxVerifier: Raw Intel TDX quote verification
# - NvidiaGpuVerifier: Nvidia GPU attestation via NRAS
# - DstackVerifier: Dstack TEE verification via external service

# User-facing verifiers (what users should call)
# - TinfoilVerifier: Unified verifier for TDX + SEV-SNP with Sigstore manifest
# - TinfoilTdxVerifier: Legacy TDX verifier (use TinfoilVerifier instead)
# - RedpillVerifier: Full Phala app verification for Redpill models
# - NearAICloudVerifier: Multi-component (Gateway + Models) verification
# - ChutesVerifier: Intel TDX + NVIDIA CC with E2E public key binding

__all__ = [
    "Verifier",
    "IntelTdxVerifier",
    "NvidiaGpuVerifier",
    "TinfoilVerifier",
    "TinfoilTdxVerifier",
    "DstackVerifier",
    "RedpillVerifier",
    "NearAICloudVerifier",
    "ChutesVerifier",
    "verify_report_data",
]
