"""Client request message classes for better-auth.

This module defines the generic ClientRequest class that wraps client
requests with access control information (nonce) and signature support.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Generic, Optional, Type, TypeVar

from better_auth.messages.message import SignableMessage


# Type variable for the request payload type
T = TypeVar("T")


class ClientRequest(SignableMessage, Generic[T]):
    """Generic client request message with signature support.

    ClientRequest wraps any request payload with access control metadata
    (nonce) and provides cryptographic signing capabilities.

    The payload structure is:
    {
        "access": {
            "nonce": "<nonce>"
        },
        "request": <T>
    }

    Type Parameters:
        T: The type of the request payload.

    Attributes:
        payload: Dictionary containing access metadata and request data.
        signature: Optional cryptographic signature.
    """

    def __init__(self, request: T, nonce: str) -> None:
        """Initialize a client request.

        Args:
            request: The request payload.
            nonce: The nonce for replay protection.
        """
        super().__init__()

        access: Dict[str, str] = {
            "nonce": nonce,
        }

        self.payload: Dict[str, Any] = {
            "access": access,
            "request": request,
        }

    @staticmethod
    def _parse(message: str, constructor: Callable[[Any, str], T]) -> T:
        """Parse a serialized client request message.

        This is an internal method used by subclasses to implement their
        own parse methods with proper type information.

        Args:
            message: The serialized JSON message string.
            constructor: A constructor function that takes (request, nonce)
                and returns an instance of the appropriate ClientRequest subclass.

        Returns:
            A new instance of the ClientRequest subclass with the parsed data
            and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        json_data = json.loads(message)

        request_data = json_data["payload"]["request"]
        nonce = json_data["payload"]["access"]["nonce"]
        signature = json_data.get("signature")

        result = constructor(request_data, nonce)
        result.signature = signature

        return result
