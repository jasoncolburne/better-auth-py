"""Network I/O interfaces for better-auth.

This module defines protocols for network communication.
"""

from __future__ import annotations

from typing import Protocol


class INetwork(Protocol):
    """Interface for network operations."""

    async def send_request(self, path: str, message: str) -> str:
        """Send a network request and return the response.

        Args:
            path: The path to send the request to.
            message: The message to send.

        Returns:
            The network response as a string.
        """
        ...
