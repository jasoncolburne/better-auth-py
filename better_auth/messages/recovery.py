"""Account recovery message types for better-auth.

This module defines the request and response message types for recovering
access to an account using a recovery key.
"""

from __future__ import annotations

from typing import Any, Dict

from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ServerResponse


class RecoverAccountRequest(ClientRequest[Dict[str, Any]]):
    """Request message for recovering account access.

    This message initiates account recovery by providing authentication
    credentials including the recovery key, along with new device credentials.

    The request payload structure is:
    {
        "authentication": {
            "device": "<device_id>",
            "identity": "<identity>",
            "publicKey": "<new_public_key>",
            "recoveryKey": "<recovery_key>",
            "rotationHash": "<new_rotation_hash>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and authentication data.
        signature: Optional cryptographic signature.
    """

    def __init__(self, request: Dict[str, Any], nonce: str) -> None:
        """Initialize a recover account request.

        Args:
            request: Dictionary containing authentication data with keys:
                - authentication: Dict containing device, identity, publicKey,
                  recoveryKey, and rotationHash.
            nonce: The nonce for replay protection.
        """
        super().__init__(request, nonce)

    @staticmethod
    def parse(message: str) -> RecoverAccountRequest:
        """Parse a serialized recover account request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RecoverAccountRequest instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ClientRequest._parse(message, RecoverAccountRequest)


class RecoverAccountResponse(ServerResponse[Dict[str, Any]]):
    """Response message for account recovery.

    This message confirms successful account recovery. The response payload
    is an empty dictionary.

    Attributes:
        payload: Dictionary containing access metadata and empty response.
        signature: Optional cryptographic signature.
    """

    def __init__(self, response: Dict[str, Any], response_key_hash: str, nonce: str) -> None:
        """Initialize a recover account response.

        Args:
            response: Empty dictionary response payload.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__(response, response_key_hash, nonce)

    @staticmethod
    def parse(message: str) -> RecoverAccountResponse:
        """Parse a serialized recover account response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new RecoverAccountResponse instance with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, RecoverAccountResponse)
