"""Server implementation for the BetterAuth protocol.

This module provides the BetterAuthServer class for handling account creation,
device linking, key rotation, authentication, token refresh, and account recovery,
as well as the AccessVerifier class for verifying authenticated requests.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TypeVar

from better_auth.exceptions import (
    AuthenticationError,
)
from better_auth.interfaces.crypto import (
    IHasher,
    ISigningKey,
    IVerificationKey,
    IVerifier,
)
from better_auth.interfaces.encoding import (
    IIdentityVerifier,
    ITimestamper,
    ITokenEncoder,
)
from better_auth.interfaces.storage import (
    IServerAuthenticationKeyStore,
    IServerAuthenticationNonceStore,
    IServerRecoveryHashStore,
    IServerTimeLockStore,
    IVerificationKeyStore,
)
from better_auth.messages import (
    AccessRequest,
    AccessToken,
    CreationRequest,
    CreationResponse,
    FinishAuthenticationRequest,
    FinishAuthenticationResponse,
    LinkContainer,
    LinkDeviceRequest,
    LinkDeviceResponse,
    RecoverAccountRequest,
    RecoverAccountResponse,
    RefreshAccessTokenRequest,
    RefreshAccessTokenResponse,
    RotateAuthenticationKeyRequest,
    RotateAuthenticationKeyResponse,
    StartAuthenticationRequest,
    StartAuthenticationResponse,
    UnlinkDeviceRequest,
    UnlinkDeviceResponse,
)

# Type variable for custom token attributes
T = TypeVar("T")
U = TypeVar("U")


@dataclass
class KeyPairConfig:
    """Configuration for server key pairs.

    Attributes:
        response: Signing key for response messages.
        access: Signing key for access tokens.
    """

    response: ISigningKey
    access: ISigningKey


@dataclass
class CryptoConfig:
    """Configuration for cryptographic operations.

    Attributes:
        hasher: Hash function implementation.
        key_pair: Server signing key pair.
        verifier: Signature verification implementation.
    """

    hasher: IHasher
    key_pair: KeyPairConfig
    verifier: IVerifier


@dataclass
class EncodingConfig:
    """Configuration for encoding and time operations.

    Attributes:
        identity_verifier: Verifies identity strings against cryptographic material.
        timestamper: Provides timestamp parsing and formatting.
        token_encoder: Encodes and decodes access tokens.
    """

    identity_verifier: IIdentityVerifier
    timestamper: ITimestamper
    token_encoder: ITokenEncoder


@dataclass
class ExpiryConfig:
    """Configuration for token expiration periods.

    Attributes:
        access_in_minutes: Access token lifetime in minutes.
        refresh_in_hours: Refresh token lifetime in hours.
    """

    access_in_minutes: int
    refresh_in_hours: int


@dataclass
class AccessStoreConfig:
    """Configuration for access-related storage.

    Attributes:
        key_hash: Time-locked store for access key hashes.
    """

    key_hash: IServerTimeLockStore


@dataclass
class AuthenticationStoreConfig:
    """Configuration for authentication-related storage.

    Attributes:
        key: Store for authentication keys.
        nonce: Store for authentication nonces.
    """

    key: IServerAuthenticationKeyStore
    nonce: IServerAuthenticationNonceStore


@dataclass
class RecoveryStoreConfig:
    """Configuration for recovery-related storage.

    Attributes:
        hash: Store for recovery hashes.
    """

    hash: IServerRecoveryHashStore


@dataclass
class StoreConfig:
    """Configuration for server-side storage interfaces.

    Attributes:
        access: Access-related storage.
        authentication: Authentication-related storage.
        recovery: Recovery-related storage.
    """

    access: AccessStoreConfig
    authentication: AuthenticationStoreConfig
    recovery: RecoveryStoreConfig


@dataclass
class BetterAuthServerConfig:
    """Configuration for BetterAuthServer.

    Attributes:
        crypto: Cryptographic operation configuration.
        encoding: Encoding and time operation configuration.
        expiry: Token expiration configuration.
        store: Storage interface configuration.
    """

    crypto: CryptoConfig
    encoding: EncodingConfig
    expiry: ExpiryConfig
    store: StoreConfig


class BetterAuthServer:
    """Server implementation for the BetterAuth protocol.

    BetterAuthServer handles:
    - Account creation with device registration
    - Additional device linking
    - Authentication key rotation
    - Two-phase authentication (start/finish)
    - Access token refresh
    - Account recovery using recovery keys

    All responses are cryptographically signed by the server's response key.
    Access tokens are signed by the server's access key.

    Attributes:
        _config: Server configuration containing crypto, encoding, expiry, and storage.
    """

    def __init__(self, config: BetterAuthServerConfig) -> None:
        """Initialize the BetterAuth server.

        Args:
            config: Server configuration with all required dependencies.
        """
        self._config = config


    async def create_account(self, message: str) -> str:
        """Create a new account with initial device registration.

        This method:
        1. Parses and verifies the creation request
        2. Verifies the identity string matches the cryptographic material
        3. Validates the device hash
        4. Registers the recovery hash
        5. Registers the authentication key
        6. Returns a signed response

        Args:
            message: Serialized CreationRequest from the client.

        Returns:
            Serialized CreationResponse signed by the server.

        Raises:
            InvalidMessageError: If the message is malformed.
            VerificationError: If signature or identity verification fails.
            AuthenticationError: If the device hash is invalid.
        """
        request = CreationRequest.parse(message)
        await request.verify(
            self._config.crypto.verifier,
            request.payload["request"]["authentication"]["publicKey"],
        )

        identity = request.payload["request"]["authentication"]["identity"]

        await self._config.encoding.identity_verifier.verify(
            identity,
            request.payload["request"]["authentication"]["publicKey"],
            request.payload["request"]["authentication"]["rotationHash"],
            request.payload["request"]["authentication"]["recoveryHash"],
        )

        device_hash = await self._config.crypto.hasher.sum(
            request.payload["request"]["authentication"]["publicKey"]
        )

        if device_hash != request.payload["request"]["authentication"]["device"]:
            raise AuthenticationError("malformed device")

        await self._config.store.recovery.hash.register(
            identity, request.payload["request"]["authentication"]["recoveryHash"]
        )

        await self._config.store.authentication.key.register(
            identity,
            request.payload["request"]["authentication"]["device"],
            request.payload["request"]["authentication"]["publicKey"],
            request.payload["request"]["authentication"]["rotationHash"],
            False,
        )

        response = CreationResponse(
            {}, await self._config.crypto.key_pair.response.identity(), request.payload["access"]["nonce"]
        )

        await response.sign(self._config.crypto.key_pair.response)

        return await response.serialize()

    async def link_device(self, message: str) -> str:
        """Link a new device to an existing account.

        This method:
        1. Parses and verifies the link device request
        2. Rotates the authentication key for the requesting device
        3. Retrieves the requesting device's public key
        4. Verifies the link container signature
        5. Validates identity consistency
        6. Registers the new device
        7. Returns a signed response

        Args:
            message: Serialized LinkDeviceRequest from the client.

        Returns:
            Serialized LinkDeviceResponse signed by the server.

        Raises:
            InvalidMessageError: If the message is malformed.
            VerificationError: If signature verification fails.
            AuthenticationError: If identities don't match.
        """
        request = LinkDeviceRequest.parse(message)

        await request.verify(
            self._config.crypto.verifier,
            request.payload["request"]["authentication"]["publicKey"],
        )

        link_container = LinkContainer(request.payload["request"]["link"]["payload"])
        link_container.signature = request.payload["request"]["link"]["signature"]

        await link_container.verify(
            self._config.crypto.verifier,
            link_container.payload["authentication"]["publicKey"],
        )

        if (
            link_container.payload["authentication"]["identity"]
            != request.payload["request"]["authentication"]["identity"]
        ):
            raise AuthenticationError("mismatched identities")

        await self._config.store.authentication.key.rotate(
            request.payload["request"]["authentication"]["identity"],
            request.payload["request"]["authentication"]["device"],
            request.payload["request"]["authentication"]["publicKey"],
            request.payload["request"]["authentication"]["rotationHash"],
        )

        await self._config.store.authentication.key.register(
            link_container.payload["authentication"]["identity"],
            link_container.payload["authentication"]["device"],
            link_container.payload["authentication"]["publicKey"],
            link_container.payload["authentication"]["rotationHash"],
            True,
        )

        response = LinkDeviceResponse(
            {}, await self._config.crypto.key_pair.response.identity(), request.payload["access"]["nonce"]
        )

        await response.sign(self._config.crypto.key_pair.response)

        return await response.serialize()

    async def unlink_device(self, message: str) -> str:
        """Unlink a device from an existing account.

        This method:
        1. Parses and verifies the unlink device request
        2. Rotates the authentication key for the requesting device
        3. Retrieves the requesting device's public key
        4. Revokes the device
        5. Returns a signed response

        Args:
            message: Serialized UnlinkDeviceRequest from the client.

        Returns:
            Serialized UnlinkDeviceResponse signed by the server.

        Raises:
            InvalidMessageError: If the message is malformed.
            VerificationError: If signature verification fails.
        """
        request = UnlinkDeviceRequest.parse(message)

        await request.verify(
            self._config.crypto.verifier, request.payload["request"]["authentication"]["publicKey"]
        )

        await self._config.store.authentication.key.rotate(
            request.payload["request"]["authentication"]["identity"],
            request.payload["request"]["authentication"]["device"],
            request.payload["request"]["authentication"]["publicKey"],
            request.payload["request"]["authentication"]["rotationHash"],
        )

        await self._config.store.authentication.key.revoke_device(
            request.payload["request"]["authentication"]["identity"],
            request.payload["request"]["link"]["device"],
        )

        response = UnlinkDeviceResponse(
            {}, await self._config.crypto.key_pair.response.identity(), request.payload["access"]["nonce"]
        )

        await response.sign(self._config.crypto.key_pair.response)

        return await response.serialize()

    async def rotate_authentication_key(self, message: str) -> str:
        """Rotate the authentication key for a device.

        This method:
        1. Parses and verifies the rotation request
        2. Rotates the authentication key in storage
        3. Returns a signed response

        Note: This operation is currently replayable and should be fixed
        in future versions.

        Args:
            message: Serialized RotateAuthenticationKeyRequest from the client.

        Returns:
            Serialized RotateAuthenticationKeyResponse signed by the server.

        Raises:
            InvalidMessageError: If the message is malformed.
            VerificationError: If signature verification fails.
        """
        request = RotateAuthenticationKeyRequest.parse(message)
        await request.verify(
            self._config.crypto.verifier,
            request.payload["request"]["authentication"]["publicKey"],
        )

        await self._config.store.authentication.key.rotate(
            request.payload["request"]["authentication"]["identity"],
            request.payload["request"]["authentication"]["device"],
            request.payload["request"]["authentication"]["publicKey"],
            request.payload["request"]["authentication"]["rotationHash"],
        )

        response = RotateAuthenticationKeyResponse(
            {}, await self._config.crypto.key_pair.response.identity(), request.payload["access"]["nonce"]
        )

        await response.sign(self._config.crypto.key_pair.response)

        return await response.serialize()

    async def start_authentication(self, message: str) -> str:
        """Start the authentication process by generating a nonce.

        This is the first phase of two-phase authentication. The server
        generates a nonce that must be signed by the client to prove
        possession of their private key.

        Args:
            message: Serialized StartAuthenticationRequest from the client.

        Returns:
            Serialized StartAuthenticationResponse with nonce, signed by the server.

        Raises:
            InvalidMessageError: If the message is malformed.
        """
        request = StartAuthenticationRequest.parse(message)

        nonce = await self._config.store.authentication.nonce.generate(
            request.payload["request"]["authentication"]["identity"]
        )

        response = StartAuthenticationResponse(
            {
                "authentication": {
                    "nonce": nonce,
                },
            },
            await self._config.crypto.key_pair.response.identity(),
            request.payload["access"]["nonce"],
        )

        await response.sign(self._config.crypto.key_pair.response)

        return await response.serialize()

    async def finish_authentication(self, message: str, attributes: T) -> str:
        """Finish the authentication process and issue an access token.

        This is the second phase of two-phase authentication. The server:
        1. Validates the nonce from the first phase
        2. Verifies the client's signature
        3. Issues a signed access token with the provided attributes

        Args:
            message: Serialized FinishAuthenticationRequest from the client.
            attributes: Custom attributes to embed in the access token.

        Returns:
            Serialized FinishAuthenticationResponse with access token, signed by the server.

        Raises:
            InvalidMessageError: If the message is malformed.
            VerificationError: If signature verification fails.
            AuthenticationError: If nonce validation fails.
        """
        request = FinishAuthenticationRequest.parse(message)
        identity = await self._config.store.authentication.nonce.validate(
            request.payload["request"]["authentication"]["nonce"]
        )

        authentication_public_key = await self._config.store.authentication.key.public(
            identity, request.payload["request"]["authentication"]["device"]
        )
        await request.verify(self._config.crypto.verifier, authentication_public_key)

        now = self._config.encoding.timestamper.now()
        later = self._config.encoding.timestamper.parse(now)
        even_later = self._config.encoding.timestamper.parse(now)

        later += timedelta(minutes=self._config.expiry.access_in_minutes)
        even_later += timedelta(hours=self._config.expiry.refresh_in_hours)

        issued_at = self._config.encoding.timestamper.format(now)
        expiry = self._config.encoding.timestamper.format(later)
        refresh_expiry = self._config.encoding.timestamper.format(even_later)

        access_token = AccessToken[T](
            await self._config.crypto.key_pair.access.identity(),
            identity,
            request.payload["request"]["access"]["publicKey"],
            request.payload["request"]["access"]["rotationHash"],
            issued_at,
            expiry,
            refresh_expiry,
            attributes,
        )

        await access_token.sign(self._config.crypto.key_pair.access)
        token = await access_token.serialize_token(self._config.encoding.token_encoder)

        response = FinishAuthenticationResponse(
            {
                "access": {
                    "token": token,
                },
            },
            await self._config.crypto.key_pair.response.identity(),
            request.payload["access"]["nonce"],
        )

        await response.sign(self._config.crypto.key_pair.response)

        return await response.serialize()

    async def refresh_access_token(self, message: str) -> str:
        """Refresh an access token before it expires.

        This method:
        1. Parses and verifies the refresh request
        2. Verifies the existing access token
        3. Validates the key rotation hash
        4. Checks the refresh window hasn't expired
        5. Reserves the access key hash to prevent reuse
        6. Issues a new access token with extended expiry

        Args:
            message: Serialized RefreshAccessTokenRequest from the client.

        Returns:
            Serialized RefreshAccessTokenResponse with new token, signed by the server.

        Raises:
            InvalidMessageError: If the message is malformed.
            VerificationError: If signature or token verification fails.
            AuthenticationError: If hash mismatch or refresh expired.
        """
        request = RefreshAccessTokenRequest.parse(message)
        await request.verify(
            self._config.crypto.verifier, request.payload["request"]["access"]["publicKey"]
        )

        token_string = request.payload["request"]["access"]["token"]
        token = await AccessToken.parse(
            token_string,
            self._config.encoding.token_encoder,
        )
        await token.verify_token(
            self._config.crypto.verifier,
            await self._config.crypto.key_pair.access.public(),
            self._config.encoding.timestamper,
        )

        hash_value = await self._config.crypto.hasher.sum(
            request.payload["request"]["access"]["publicKey"]
        )
        if hash_value != token.rotation_hash:
            raise AuthenticationError("hash mismatch")

        now = self._config.encoding.timestamper.now()
        refresh_expiry = self._config.encoding.timestamper.parse(token.refresh_expiry)

        if now > refresh_expiry:
            raise AuthenticationError("refresh has expired")

        await self._config.store.access.key_hash.reserve(hash_value)

        later = self._config.encoding.timestamper.parse(now)
        later += timedelta(minutes=self._config.expiry.access_in_minutes)

        issued_at = self._config.encoding.timestamper.format(now)
        expiry = self._config.encoding.timestamper.format(later)

        access_token = AccessToken(
            await self._config.crypto.key_pair.access.identity(),
            token.identity,
            request.payload["request"]["access"]["publicKey"],
            request.payload["request"]["access"]["rotationHash"],
            issued_at,
            expiry,
            token.refresh_expiry,
            token.attributes,
        )

        await access_token.sign(self._config.crypto.key_pair.access)
        serialized_token = await access_token.serialize_token(self._config.encoding.token_encoder)

        response = RefreshAccessTokenResponse(
            {
                "access": {
                    "token": serialized_token,
                },
            },
            await self._config.crypto.key_pair.response.identity(),
            request.payload["access"]["nonce"],
        )

        await response.sign(self._config.crypto.key_pair.response)

        return await response.serialize()

    async def recover_account(self, message: str) -> str:
        """Recover an account using the recovery key.

        This method:
        1. Parses and verifies the recovery request
        2. Validates the recovery key hash
        3. Revokes all existing devices
        4. Registers a new device with the account
        5. Returns a signed response

        Args:
            message: Serialized RecoverAccountRequest from the client.

        Returns:
            Serialized RecoverAccountResponse signed by the server.

        Raises:
            InvalidMessageError: If the message is malformed.
            VerificationError: If signature verification fails.
            AuthenticationError: If recovery hash validation fails.
        """
        request = RecoverAccountRequest.parse(message)
        await request.verify(
            self._config.crypto.verifier,
            request.payload["request"]["authentication"]["recoveryKey"],
        )

        hash_value = await self._config.crypto.hasher.sum(
            request.payload["request"]["authentication"]["recoveryKey"]
        )
        await self._config.store.recovery.hash.rotate(
            request.payload["request"]["authentication"]["identity"],
            hash_value,
            request.payload["request"]["authentication"]["recoveryHash"],
        )

        await self._config.store.authentication.key.revoke_devices(
            request.payload["request"]["authentication"]["identity"]
        )

        await self._config.store.authentication.key.register(
            request.payload["request"]["authentication"]["identity"],
            request.payload["request"]["authentication"]["device"],
            request.payload["request"]["authentication"]["publicKey"],
            request.payload["request"]["authentication"]["rotationHash"],
            True,
        )

        response = RecoverAccountResponse(
            {}, await self._config.crypto.key_pair.response.identity(), request.payload["access"]["nonce"]
        )

        await response.sign(self._config.crypto.key_pair.response)

        return await response.serialize()


@dataclass
class AccessVerifierCryptoConfig:
    """Configuration for access verifier cryptographic operations.

    Attributes:
        access_key_store: Store for accessing verification keys by identity.
        verifier: Signature verification implementation.
    """

    access_key_store: IVerificationKeyStore
    verifier: IVerifier


@dataclass
class AccessVerifierEncodingConfig:
    """Configuration for access verifier encoding operations.

    Attributes:
        token_encoder: Encodes and decodes access tokens.
        timestamper: Provides timestamp parsing and formatting.
    """

    token_encoder: ITokenEncoder
    timestamper: ITimestamper


@dataclass
class AccessVerifierStoreConfig:
    """Configuration for access verifier storage.

    Attributes:
        nonce: Time-locked store for nonces.
    """

    nonce: IServerTimeLockStore


@dataclass
class AccessVerifierStorageConfig:
    """Configuration for access verifier storage interfaces.

    Attributes:
        access: Access-related storage.
    """

    access: AccessVerifierStoreConfig


@dataclass
class AccessVerifierConfig:
    """Configuration for AccessVerifier.

    Attributes:
        crypto: Cryptographic operation configuration.
        encoding: Encoding operation configuration.
        store: Storage interface configuration.
    """

    crypto: AccessVerifierCryptoConfig
    encoding: AccessVerifierEncodingConfig
    store: AccessVerifierStorageConfig


class AccessVerifier:
    """Verifier for authenticated access requests.

    AccessVerifier validates incoming access requests by:
    - Verifying the access token signature
    - Checking token expiration
    - Verifying the request signature
    - Validating the nonce to prevent replay attacks

    This class is typically used by API endpoints to authenticate
    incoming requests.

    Attributes:
        _config: Verifier configuration with crypto, encoding, and storage.
    """

    def __init__(self, config: AccessVerifierConfig) -> None:
        """Initialize the access verifier.

        Args:
            config: Verifier configuration with all required dependencies.
        """
        self._config = config

    async def verify(self, message: str) -> tuple[str, U]:
        """Verify an authenticated access request.

        This method performs comprehensive verification of an access request:
        1. Parses the request message
        2. Verifies the access token signature and expiration
        3. Verifies the request signature
        4. Validates the timestamp
        5. Reserves the nonce to prevent replay attacks

        Args:
            message: Serialized AccessRequest from the client.

        Returns:
            A tuple of (identity, attributes) where:
                - identity: The user's identity string from the token
                - attributes: Custom attributes from the token of type U

        Raises:
            InvalidMessageError: If the message is malformed.
            VerificationError: If signature verification fails.
            AuthenticationError: If token is expired or nonce is invalid.
        """
        request = AccessRequest.parse(message)
        return await request._verify(
            self._config.store.access.nonce,
            self._config.crypto.verifier,
            self._config.crypto.access_key_store,
            self._config.encoding.token_encoder,
            self._config.encoding.timestamper,
        )
