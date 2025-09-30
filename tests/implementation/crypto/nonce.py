"""Nonce generator implementation.

This module provides the Noncer class for generating cryptographic nonces.
"""

import base64

from better_auth.interfaces.crypto import INoncer

from .entropy import get_entropy


class Noncer(INoncer):
    """Nonce generator that implements INoncer.

    Generates 128-bit nonces with CESR encoding (prefix: "0A").
    """

    async def generate128(self) -> str:
        """Generate a nonce with 128 bits of entropy.

        The nonce is CESR-encoded with the "0A" prefix for 128-bit nonces.

        Returns:
            A CESR-encoded nonce string starting with "0A".
        """
        entropy = await get_entropy(16)  # 16 bytes = 128 bits

        # Pad with 2 zero bytes at the beginning for proper base64 alignment
        padded = bytes([0, 0]) + entropy
        base64_str = base64.urlsafe_b64encode(padded).decode("ascii").rstrip("=")

        # Remove the first 2 characters (from padding) and add CESR prefix
        return f"0A{base64_str[2:]}"