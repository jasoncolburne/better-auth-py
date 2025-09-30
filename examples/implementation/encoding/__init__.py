"""Encoding reference implementation package.

This package provides reference implementations of encoding primitives
for the better-auth protocol, including base64 encoding, timestamp formatting,
token compression/encoding, and identity verification.
"""

from .base64 import Base64
from .identity import IdentityVerifier
from .timestamper import Rfc3339Nano
from .token_encoder import TokenEncoder

__all__ = [
    "Base64",
    "IdentityVerifier",
    "Rfc3339Nano",
    "TokenEncoder",
]
