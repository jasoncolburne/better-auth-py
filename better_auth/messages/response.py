"""Server response message classes for better-auth.

This module defines the generic ServerResponse class and the concrete
ScannableResponse class for server responses with signature support.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Generic, Optional, Type, TypeVar

from better_auth.messages.message import SignableMessage


# Type variable for the response payload type
T = TypeVar('T')


class ServerResponse(SignableMessage, Generic[T]):
    """Generic server response message with signature support.

    ServerResponse wraps any response payload with access control metadata
    (nonce and response key hash) and provides cryptographic signing capabilities.

    The payload structure is:
    {
        "access": {
            "nonce": "<nonce>",
            "responseKeyHash": "<hash>"
        },
        "response": <T>
    }

    Type Parameters:
        T: The type of the response payload.

    Attributes:
        payload: Dictionary containing access metadata and response data.
        signature: Optional cryptographic signature.
    """

    def __init__(self, response: T, response_key_hash: str, nonce: str) -> None:
        """Initialize a server response.

        Args:
            response: The response payload.
            response_key_hash: Hash of the response key for verification.
            nonce: The nonce for replay protection.
        """
        super().__init__()

        access: Dict[str, str] = {
            "nonce": nonce,
            "responseKeyHash": response_key_hash,
        }

        self.payload: Dict[str, Any] = {
            "access": access,
            "response": response,
        }

    @staticmethod
    def _parse(
        message: str,
        constructor: Callable[[Any, str, str], T]
    ) -> T:
        """Parse a serialized server response message.

        This is an internal method used by subclasses to implement their
        own parse methods with proper type information.

        Args:
            message: The serialized JSON message string.
            constructor: A constructor function that takes (response,
                response_key_hash, nonce) and returns an instance of the
                appropriate ServerResponse subclass.

        Returns:
            A new instance of the ServerResponse subclass with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        json_data = json.loads(message)

        response_data = json_data["payload"]["response"]
        response_key_hash = json_data["payload"]["access"]["responseKeyHash"]
        nonce = json_data["payload"]["access"]["nonce"]
        signature = json_data.get("signature")

        result = constructor(response_data, response_key_hash, nonce)
        result.signature = signature

        return result


class ScannableResponse(ServerResponse[Dict[str, Any]]):
    """Concrete server response for scannable operations.

    ScannableResponse is used for responses that can be scanned or displayed
    as QR codes. It uses an empty dictionary as the response payload type.
    """

    @staticmethod
    def parse(message: str) -> ScannableResponse:
        """Parse a serialized scannable response message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new ScannableResponse instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        return ServerResponse._parse(message, ScannableResponse)