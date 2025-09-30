"""Blake3 hasher implementation.

This module provides the Blake3 hashing utility class.
"""

import blake3


class Blake3:
    """Blake3 hasher utility class."""

    @staticmethod
    async def sum256(data: bytes) -> bytes:
        """Compute the Blake3 hash of the input data.

        Args:
            data: The bytes to hash.

        Returns:
            The 32-byte Blake3 hash.
        """
        hasher = blake3.blake3(data)
        return hasher.digest()