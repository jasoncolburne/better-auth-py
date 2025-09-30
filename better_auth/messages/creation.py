"""Account creation message types for better-auth.

This module defines the request and response message types for creating
new user accounts with authentication credentials.
"""

from __future__ import annotations

from typing import Any, Dict

from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ServerResponse


class CreationRequest(ClientRequest[Dict[str, Any]]):
    """Request message for creating a new user account.

    This message contains the initial authentication credentials for a new user,
    including device information, identity, public key, recovery hash, and
    rotation hash.

    The request payload structure is:
    {
        "authentication": {
            "device": "<device_id>",
            "identity": "<identity>",
            "publicKey": "<public_key>",
            "recoveryHash": "<recovery_hash>",
            "rotationHash": "<rotation_hash>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and authentication data.
        signature: Optional cryptographic signature.
    """

    def __init__(
        self,
        request: Dict[str, Any],
        nonce: str
    ) -> None:
        """Initialize a creation request.

        Args:
            request: Dictionary containing the authentication data with keys:
                - authentication: Dict containing device, identity, publicKey,
                  recoveryHash, and rotationHash.
            nonce: The nonce for replay protection.
        """
        super().__init__(request, nonce)

    @staticmethod
    def parse(message: str) -> CreationRequest:
        """Parse a serialized creation request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new CreationRequest instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ClientRequest._parse(message, CreationRequest)


class CreationResponse(ServerResponse[Dict[str, Any]]):
    """Response message for account creation.

    This message confirms successful account creation. The response payload
    is an empty dictionary.

    Attributes:
        payload: Dictionary containing access metadata and empty response.
        signature: Optional cryptographic signature.
    """

    def __init__(
        self,
        response: Dict[str, Any],
        response_key_hash: str,
        nonce: str
    ) -> None:
        """Initialize a creation response.

        Args:
            response: Empty dictionary response payload.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__(response, response_key_hash, nonce)

    @staticmethod
    def parse(message: str) -> CreationResponse:
        """Parse a serialized creation response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new CreationResponse instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, CreationResponse)