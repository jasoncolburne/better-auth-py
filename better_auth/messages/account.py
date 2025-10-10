"""Account management message types for better-auth.

This module defines the request and response message types for account
operations including creation and recovery.
"""

from __future__ import annotations

from typing import Any, Dict

from better_auth.messages.request import ClientRequest
from better_auth.messages.response import ServerResponse


class CreateAccountRequest(ClientRequest[Dict[str, Any]]):
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

    def __init__(self, request: Dict[str, Any], nonce: str) -> None:
        """Initialize a creation request.

        Args:
            request: Dictionary containing the authentication data with keys:
                - authentication: Dict containing device, identity, publicKey,
                  recoveryHash, and rotationHash.
            nonce: The nonce for replay protection.
        """
        super().__init__(request, nonce)

    @staticmethod
    def parse(message: str) -> CreateAccountRequest:
        """Parse a serialized creation request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new CreateAccountRequest instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ClientRequest._parse(message, CreateAccountRequest)


class CreateAccountResponse(ServerResponse[Dict[str, Any]]):
    """Response message for account creation.

    This message confirms successful account creation. The response payload
    is an empty dictionary.

    Attributes:
        payload: Dictionary containing access metadata and empty response.
        signature: Optional cryptographic signature.
    """

    def __init__(self, response: Dict[str, Any], response_key_hash: str, nonce: str) -> None:
        """Initialize a creation response.

        Args:
            response: Empty dictionary response payload.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__(response, response_key_hash, nonce)

    @staticmethod
    def parse(message: str) -> CreateAccountResponse:
        """Parse a serialized creation response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new CreateAccountResponse instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, CreateAccountResponse)


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
            "recoveryHash": "<recovery_hash>",
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
                  recoveryHash, recoveryKey, and rotationHash.
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


class DeleteAccountRequest(ClientRequest[Dict[str, Any]]):
    """Request message for deleting an account.

    This message contains the authentication credentials to authorize account deletion.

    The request payload structure is:
    {
        "authentication": {
            "device": "<device_id>",
            "identity": "<identity>",
            "publicKey": "<public_key>",
            "rotationHash": "<rotation_hash>"
        }
    }

    Attributes:
        payload: Dictionary containing access metadata and authentication data.
        signature: Optional cryptographic signature.
    """

    def __init__(self, request: Dict[str, Any], nonce: str) -> None:
        """Initialize a delete account request.

        Args:
            request: Dictionary containing the authentication data with keys:
                - authentication: Dict containing device, identity, publicKey,
                  and rotationHash.
            nonce: The nonce for replay protection.
        """
        super().__init__(request, nonce)

    @staticmethod
    def parse(message: str) -> DeleteAccountRequest:
        """Parse a serialized delete account request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new DeleteAccountRequest instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ClientRequest._parse(message, DeleteAccountRequest)


class DeleteAccountResponse(ServerResponse[Dict[str, Any]]):
    """Response message for account deletion.

    This message confirms successful account deletion. The response payload
    is an empty dictionary.

    Attributes:
        payload: Dictionary containing access metadata and empty response.
        signature: Optional cryptographic signature.
    """

    def __init__(self, response: Dict[str, Any], response_key_hash: str, nonce: str) -> None:
        """Initialize a delete account response.

        Args:
            response: Empty dictionary response payload.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__(response, response_key_hash, nonce)

    @staticmethod
    def parse(message: str) -> DeleteAccountResponse:
        """Parse a serialized delete account response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new DeleteAccountResponse instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, DeleteAccountResponse)
