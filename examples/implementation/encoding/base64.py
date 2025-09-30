"""Base64 encoding utilities.

This module provides URL-safe base64 encoding/decoding utilities.
"""

import base64


class Base64:
    """Base64 encoding utilities for URL-safe base64 operations.

    This class provides static methods to encode bytes to base64url strings
    and decode base64url strings back to bytes. The encoding uses URL-safe
    characters (replacing + with - and / with _).
    """

    @staticmethod
    def encode(data: bytes) -> str:
        """Encode bytes to a URL-safe base64 string.

        Encodes the input bytes using base64url encoding (RFC 4648 Section 5),
        which replaces + with - and / with _.

        Args:
            data: The bytes to encode.

        Returns:
            A URL-safe base64 encoded string.
        """
        # Use urlsafe_b64encode which automatically does the replacement
        encoded = base64.urlsafe_b64encode(data).decode("ascii")
        return encoded

    @staticmethod
    def decode(base64_str: str) -> bytes:
        """Decode a URL-safe base64 string to bytes.

        Decodes a base64url encoded string back to bytes. Handles both
        standard base64 and URL-safe base64 encoding.

        Args:
            base64_str: The base64 string to decode.

        Returns:
            The decoded bytes.
        """
        # urlsafe_b64decode handles both standard and URL-safe base64
        return base64.urlsafe_b64decode(base64_str)
