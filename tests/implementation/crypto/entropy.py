"""Entropy generation utilities.

This module provides functions for generating cryptographically secure random bytes.
"""

import secrets


async def get_entropy(length: int) -> bytes:
    """Generate cryptographically secure random bytes.

    Args:
        length: The number of random bytes to generate.

    Returns:
        A bytes object containing the requested amount of random data.
    """
    return secrets.token_bytes(length)