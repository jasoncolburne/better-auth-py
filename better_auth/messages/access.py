"""Access token and request message types for better-auth.

This module defines the AccessToken class for cryptographically signed tokens
and the AccessRequest class for authenticated API requests.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Generic, TypeVar

from better_auth.interfaces.crypto import IVerifier
from better_auth.interfaces.encoding import ITimestamper, ITokenEncoder
from better_auth.interfaces.storage import IServerTimeLockStore, IVerificationKeyStore
from better_auth.messages.message import SignableMessage


# Type variable for generic attributes
T = TypeVar("T")


class AccessToken(SignableMessage, Generic[T]):
    """Cryptographically signed access token with metadata and attributes.

    AccessToken contains identity information, cryptographic keys, timestamps,
    and custom attributes. It can be signed, verified, and serialized for
    transmission.

    The token structure includes:
    - serverIdentity: Server identity string
    - identity: User identity string
    - publicKey: Current public key for verification
    - rotationHash: Hash for key rotation
    - issuedAt: Token issuance timestamp
    - expiry: Token expiration timestamp
    - refreshExpiry: Refresh window expiration timestamp
    - attributes: Custom attributes of type T

    Attributes:
        server_identity: The server's identity string.
        identity: The user's identity string.
        public_key: The public key for signature verification.
        rotation_hash: Hash for key rotation verification.
        issued_at: ISO 8601 timestamp when token was issued.
        expiry: ISO 8601 timestamp when token expires.
        refresh_expiry: ISO 8601 timestamp for refresh window expiration.
        attributes: Custom attributes of generic type T.
        signature: Cryptographic signature of the token.
    """

    def __init__(
        self,
        server_identity: str,
        identity: str,
        public_key: str,
        rotation_hash: str,
        issued_at: str,
        expiry: str,
        refresh_expiry: str,
        attributes: T,
    ) -> None:
        """Initialize an access token.

        Args:
            server_identity: The server's identity string.
            identity: The user's identity string.
            public_key: The public key for signature verification.
            rotation_hash: Hash for key rotation verification.
            issued_at: ISO 8601 timestamp when token was issued.
            expiry: ISO 8601 timestamp when token expires.
            refresh_expiry: ISO 8601 timestamp for refresh window expiration.
            attributes: Custom attributes of generic type T.
        """
        super().__init__()
        self.server_identity = server_identity
        self.identity = identity
        self.public_key = public_key
        self.rotation_hash = rotation_hash
        self.issued_at = issued_at
        self.expiry = expiry
        self.refresh_expiry = refresh_expiry
        self.attributes = attributes

    @staticmethod
    async def parse(
        message: str, token_encoder: ITokenEncoder
    ) -> AccessToken[T]:
        """Parse a serialized access token.

        The token format is: <signature><encoded_token_json>
        where the signature length is determined by token_encoder.signature_length().

        Args:
            message: The serialized token string.
            token_encoder: Encoder for decoding the token portion.

        Returns:
            A new AccessToken instance with the parsed data and signature.

        Raises:
            Exception: If decoding fails or required fields are missing.
        """
        signature_length = token_encoder.signature_length(message)
        signature = message[:signature_length]
        rest = message[signature_length:]

        token_string = await token_encoder.decode(rest)
        json_data = json.loads(token_string)

        token = AccessToken[T](
            server_identity=json_data["serverIdentity"],
            identity=json_data["identity"],
            public_key=json_data["publicKey"],
            rotation_hash=json_data["rotationHash"],
            issued_at=json_data["issuedAt"],
            expiry=json_data["expiry"],
            refresh_expiry=json_data["refreshExpiry"],
            attributes=json_data["attributes"],
        )

        token.signature = signature

        return token

    def compose_payload(self) -> str:
        """Compose the token payload into a JSON string for signing.

        Returns:
            The JSON-serialized token payload.
        """
        return json.dumps(
            {
                "serverIdentity": self.server_identity,
                "identity": self.identity,
                "publicKey": self.public_key,
                "rotationHash": self.rotation_hash,
                "issuedAt": self.issued_at,
                "expiry": self.expiry,
                "refreshExpiry": self.refresh_expiry,
                "attributes": self.attributes,
            },
            separators=(",", ":"),
            sort_keys=False,
        )

    async def serialize_token(self, token_encoder: ITokenEncoder) -> str:
        """Serialize the token for transmission.

        The serialized format is: <signature><encoded_token_json>

        Args:
            token_encoder: Encoder for encoding the token portion.

        Returns:
            The serialized token string.

        Raises:
            RuntimeError: If signature is missing.
        """
        if self.signature is None:
            raise RuntimeError("missing signature")

        token = await token_encoder.encode(self.compose_payload())
        return self.signature + token

    async def verify_token(
        self, verifier: IVerifier, public_key: str, timestamper: ITimestamper
    ) -> None:
        """Verify the token signature and validity period.

        Checks:
        1. Cryptographic signature is valid
        2. Token was not issued in the future
        3. Token has not expired

        Args:
            verifier: Verifier for signature verification.
            public_key: Public key to verify against.
            timestamper: Timestamper for time validation.

        Raises:
            RuntimeError: If signature verification fails.
            Exception: If token is from the future or has expired.
        """
        await self.verify(verifier, public_key)

        now = timestamper.now()
        issued_at = timestamper.parse(self.issued_at)
        expiry = timestamper.parse(self.expiry)

        if now < issued_at:
            raise Exception("token from future")

        if now > expiry:
            raise Exception("token expired")


class AccessRequest(SignableMessage, Generic[T]):
    """Authenticated request with access token and signature.

    AccessRequest wraps any request payload with access control information
    including a nonce, timestamp, and access token. The entire request is
    signed by the client's private key.

    The request structure is:
    {
        "access": {
            "nonce": "<nonce>",
            "timestamp": "<timestamp>",
            "token": "<access_token>"
        },
        "request": <T>
    }

    Type Parameters:
        T: The type of the request payload.

    Attributes:
        payload: Dictionary containing access metadata and request data.
        signature: Cryptographic signature of the request.
    """

    def __init__(self, payload: Dict[str, Any]) -> None:
        """Initialize an access request.

        Args:
            payload: Dictionary containing access and request data with keys:
                - access: Dict containing nonce, timestamp, and token.
                - request: Request payload of generic type T.
        """
        super().__init__()
        self.payload = payload

    def compose_payload(self) -> str:
        """Compose the payload into a JSON string for signing.

        Returns:
            The JSON-serialized payload.
        """
        return json.dumps(self.payload, separators=(",", ":"), sort_keys=False)

    async def _verify(
        self,
        nonce_store: IServerTimeLockStore,
        verifier: IVerifier,
        access_key_store: IVerificationKeyStore,
        token_encoder: ITokenEncoder,
        timestamper: ITimestamper,
    ) -> tuple[str, T]:
        """Verify the access request and extract identity and attributes.

        This method performs comprehensive verification:
        1. Parses and verifies the access token
        2. Verifies the request signature using the token's public key
        3. Validates the request timestamp is not stale or from the future
        4. Reserves the nonce to prevent replay attacks

        Args:
            nonce_store: Store for nonce replay protection.
            verifier: Verifier for request signature verification.
            access_key_store: Store for accessing server verification keys.
            token_encoder: Encoder for decoding the access token.
            timestamper: Timestamper for time validation.

        Returns:
            A tuple of (identity, attributes) extracted from the access token.

        Raises:
            Exception: If verification fails at any stage.
            Exception: If request is stale or from the future.
            Exception: If nonce has already been used.
        """
        # Parse and verify the access token
        access_token = await AccessToken.parse(
            self.payload["access"]["token"], token_encoder
        )

        # Get the verification key for the server identity
        verification_key = await access_key_store.get(access_token.server_identity)

        # Verify token signature and validity
        await access_token.verify_token(verification_key.verifier(), await verification_key.public(), timestamper)

        # Verify request signature using the client's public key from the token
        await self.verify(verifier, access_token.public_key)

        # Validate timestamp
        now = timestamper.now()
        access_time = timestamper.parse(self.payload["access"]["timestamp"])
        expiry = timestamper.parse(self.payload["access"]["timestamp"])

        # Add lifetime to expiry
        expiry = datetime.fromtimestamp(
            expiry.timestamp() + nonce_store.lifetime_in_seconds, tz=timezone.utc
        )

        if now > expiry:
            raise Exception("stale request")

        if now < access_time:
            raise Exception("request from future")

        # Reserve nonce to prevent replay
        await nonce_store.reserve(self.payload["access"]["nonce"])

        return (access_token.identity, access_token.attributes)

    @staticmethod
    def parse(message: str) -> AccessRequest[T]:
        """Parse a serialized access request message.

        Args:
            message: The serialized JSON message string.

        Returns:
            A new AccessRequest instance with the parsed data and signature.

        Raises:
            json.JSONDecodeError: If the message is not valid JSON.
            KeyError: If required fields are missing from the message.
        """
        json_data = json.loads(message)
        result = AccessRequest[T](json_data["payload"])
        result.signature = json_data.get("signature")
        return result
