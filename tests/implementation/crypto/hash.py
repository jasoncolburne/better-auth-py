"""Hash utilities implementation.

This module provides the Hasher class for cryptographic hashing operations.
"""

import base64

from better_auth.interfaces.crypto import IHasher

from .blake3 import Blake3


class Hasher(IHasher):
    """Hasher that uses Blake3 and implements IHasher.

    Produces CESR-encoded hashes with the "E" prefix for Blake3-256.
    """

    async def sum(self, message: str) -> str:
        """Compute the hash of a message.

        The message is UTF-8 encoded, hashed with Blake3, and returned
        as a CESR-encoded string with the "E" prefix.

        Args:
            message: The message to hash.

        Returns:
            A CESR-encoded hash string starting with "E".
        """
        message_bytes = message.encode("utf-8")
        hash_bytes = await Blake3.sum256(message_bytes)

        # Pad with 1 zero byte at the beginning for proper base64 alignment
        padded = bytes([0]) + hash_bytes
        base64_str = base64.urlsafe_b64encode(padded).decode("ascii").rstrip("=")

        # Remove the first character (from padding) and add CESR prefix
        return f"E{base64_str[1:]}"
