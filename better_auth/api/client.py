"""BetterAuth client implementation.

This module provides the main BetterAuthClient class for interacting with
a BetterAuth server. The client handles account creation, device linking,
authentication, key rotation, and access token management.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from better_auth.exceptions import AuthenticationError, VerificationError
from better_auth.interfaces import (
    IAuthenticationPaths,
    IClientRotatingKeyStore,
    IClientValueStore,
    IHasher,
    INetwork,
    INoncer,
    ISigningKey,
    ITimestamper,
    IVerificationKey,
)
from better_auth.messages import (
    AccessRequest,
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
    ScannableResponse,
    StartAuthenticationRequest,
    StartAuthenticationResponse,
)


@dataclass
class PublicKeyConfig:
    """Configuration for public keys.

    Attributes:
        response: Verification key for server responses.
    """

    response: IVerificationKey


@dataclass
class CryptoConfig:
    """Configuration for cryptographic operations.

    Attributes:
        hasher: Interface for hashing operations.
        noncer: Interface for nonce generation.
        public_key: Public key configuration.
    """

    hasher: IHasher
    noncer: INoncer
    public_key: PublicKeyConfig


@dataclass
class EncodingConfig:
    """Configuration for encoding operations.

    Attributes:
        timestamper: Interface for timestamp operations.
    """

    timestamper: ITimestamper


@dataclass
class IOConfig:
    """Configuration for I/O operations.

    Attributes:
        network: Interface for network communication.
    """

    network: INetwork


@dataclass
class IdentifierStoreConfig:
    """Configuration for identifier storage.

    Attributes:
        device: Store for device identifier.
        identity: Store for identity identifier.
    """

    device: IClientValueStore
    identity: IClientValueStore


@dataclass
class KeyStoreConfig:
    """Configuration for key storage.

    Attributes:
        access: Store for access keys (rotating).
        authentication: Store for authentication keys (rotating).
    """

    access: IClientRotatingKeyStore
    authentication: IClientRotatingKeyStore


@dataclass
class TokenStoreConfig:
    """Configuration for token storage.

    Attributes:
        access: Store for access tokens.
    """

    access: IClientValueStore


@dataclass
class StoreConfig:
    """Configuration for all storage operations.

    Attributes:
        identifier: Configuration for identifier storage.
        key: Configuration for key storage.
        token: Configuration for token storage.
    """

    identifier: IdentifierStoreConfig
    key: KeyStoreConfig
    token: TokenStoreConfig


@dataclass
class BetterAuthClientConfig:
    """Complete configuration for BetterAuthClient.

    Attributes:
        crypto: Cryptographic operation configuration.
        encoding: Encoding operation configuration.
        io: I/O operation configuration.
        paths: Authentication path configuration.
        store: Storage operation configuration.
    """

    crypto: CryptoConfig
    encoding: EncodingConfig
    io: IOConfig
    paths: IAuthenticationPaths
    store: StoreConfig


class BetterAuthClient:
    """Client for interacting with BetterAuth server.

    This class provides all client-side operations for the BetterAuth protocol,
    including account creation, device linking, authentication, key rotation,
    and authenticated requests.

    The client uses dependency injection for all external operations (crypto,
    storage, network) to maintain flexibility and testability.

    Example:
        ```python
        # Configure the client
        config: BetterAuthClientConfig = {
            "crypto": {
                "hasher": my_hasher,
                "noncer": my_noncer,
                "publicKey": {"response": my_verification_key}
            },
            "encoding": {"timestamper": my_timestamper},
            "io": {"network": my_network},
            "paths": my_paths,
            "store": {
                "identifier": {
                    "device": device_store,
                    "identity": identity_store
                },
                "key": {
                    "access": access_key_store,
                    "authentication": auth_key_store
                },
                "token": {"access": token_store}
            }
        }

        # Create client
        client = BetterAuthClient(config)

        # Create an account
        await client.create_account(recovery_hash)

        # Authenticate
        await client.authenticate()

        # Make authenticated requests
        response = await client.make_access_request("/api/data", {"query": "value"})
        ```

    Attributes:
        args: Complete configuration dictionary containing all dependencies.
    """

    def __init__(self, args: BetterAuthClientConfig) -> None:
        """Initialize the BetterAuth client.

        Args:
            args: Complete configuration dictionary containing crypto, encoding,
                I/O, paths, and storage configurations.
        """
        self.args = args

    async def identity(self) -> str:
        """Get the stored identity identifier.

        Returns:
            The identity identifier as a string.

        Raises:
            StorageError: If no identity has been stored.
        """
        return await self.args.store.identifier.identity.get()

    async def device(self) -> str:
        """Get the stored device identifier.

        Returns:
            The device identifier as a string.

        Raises:
            StorageError: If no device has been stored.
        """
        return await self.args.store.identifier.device.get()

    async def _verify_response(self, response: Any, public_key_hash: str) -> None:
        """Verify a server response signature and key hash.

        This internal method verifies that:
        1. The server's public key hash matches the expected hash
        2. The response signature is valid

        Args:
            response: The response object (must have verify method).
            public_key_hash: The expected hash of the server's public key.

        Raises:
            VerificationError: If hash mismatch or signature verification fails.
        """
        public_key = await self.args.crypto.public_key.response.public()
        hash_value = await self.args.crypto.hasher.sum(public_key)

        if hash_value != public_key_hash:
            raise VerificationError("hash mismatch")

        verifier = self.args.crypto.public_key.response.verifier()
        await response.verify(verifier, public_key)

    async def create_account(self, recovery_hash: str) -> None:
        """Create a new account with the BetterAuth server.

        This method:
        1. Initializes authentication keys with the recovery hash
        2. Generates a device identifier from the public key
        3. Creates and signs a creation request
        4. Sends the request to the server
        5. Verifies the response
        6. Stores the identity and device identifiers

        Args:
            recovery_hash: Hash of the recovery key for account recovery.

        Raises:
            VerificationError: If response verification fails.
            AuthenticationError: If nonce mismatch occurs.
            StorageError: If storage operations fail.
            NetworkError: If network communication fails.
        """
        # Initialize authentication keys with recovery hash
        identity, public_key, rotation_hash = await self.args.store.key.authentication.initialize(
            recovery_hash
        )
        device = await self.args.crypto.hasher.sum(public_key)

        # Generate nonce for replay protection
        nonce = await self.args.crypto.noncer.generate128()

        # Create and sign the request
        request = CreationRequest(
            {
                "authentication": {
                    "device": device,
                    "identity": identity,
                    "publicKey": public_key,
                    "recoveryHash": recovery_hash,
                    "rotationHash": rotation_hash,
                }
            },
            nonce,
        )

        await request.sign(await self.args.store.key.authentication.signer())
        message = await request.serialize()

        # Send request and parse response
        reply = await self.args.io.network.send_request(self.args.paths.register.create, message)

        response = CreationResponse.parse(reply)
        await self._verify_response(response, response.payload["access"]["responseKeyHash"])

        # Verify nonce matches
        if response.payload["access"]["nonce"] != nonce:
            raise AuthenticationError("incorrect nonce")

        # Store identity and device
        await self.args.store.identifier.identity.store(identity)
        await self.args.store.identifier.device.store(device)

    async def generate_link_container(self, identity: str) -> str:
        """Generate a link container for device linking (new device side).

        This method is called on a new device to generate a link container
        that can be scanned or transmitted to an existing device for linking.

        The link container can be encoded as a QR code. Use a 61x61 module
        layout with a 53x53 module code, centered, at approximately 244x244px.

        Steps:
        1. Initialize authentication keys for this device
        2. Generate device identifier
        3. Store identity and device
        4. Create and sign link container
        5. Serialize for transmission

        Args:
            identity: The identity identifier to link to.

        Returns:
            Serialized link container as a string (suitable for QR encoding).

        Raises:
            StorageError: If storage operations fail.
        """
        # Initialize authentication keys (no recovery hash needed for linking)
        _, public_key, rotation_hash = await self.args.store.key.authentication.initialize()
        device = await self.args.crypto.hasher.sum(public_key)

        # Store identity and device
        await self.args.store.identifier.identity.store(identity)
        await self.args.store.identifier.device.store(device)

        # Create and sign link container
        link_container = LinkContainer(
            {
                "authentication": {
                    "device": device,
                    "identity": identity,
                    "publicKey": public_key,
                    "rotationHash": rotation_hash,
                }
            }
        )

        await link_container.sign(await self.args.store.key.authentication.signer())

        return await link_container.serialize()

    async def link_device(self, link_container: str) -> None:
        """Link a new device to the account (existing device side).

        This method is called on an existing device to authorize a new device
        by processing its link container (typically scanned as a QR code).

        Steps:
        1. Parse the link container from the new device
        2. Create and sign a link device request
        3. Send to server for authorization
        4. Verify the response

        Args:
            link_container: Serialized link container from the new device.

        Raises:
            VerificationError: If response verification fails.
            AuthenticationError: If nonce mismatch occurs.
            InvalidMessageError: If link container is malformed.
            StorageError: If storage operations fail.
            NetworkError: If network communication fails.
        """
        # Parse the link container
        container = LinkContainer.parse(link_container)
        nonce = await self.args.crypto.noncer.generate128()

        # Rotate authentication key
        public_key, rotation_hash = await self.args.store.key.authentication.rotate()

        # Create and sign the request
        request = LinkDeviceRequest(
            {
                "authentication": {
                    "device": await self.args.store.identifier.device.get(),
                    "identity": await self.args.store.identifier.identity.get(),
                    "publicKey": public_key,
                    "rotationHash": rotation_hash,
                },
                "link": {
                    "payload": container.payload,
                    "signature": container.signature,
                },
            },
            nonce,
        )

        await request.sign(await self.args.store.key.authentication.signer())
        message = await request.serialize()

        # Send request and parse response
        reply = await self.args.io.network.send_request(self.args.paths.register.link, message)

        response = LinkDeviceResponse.parse(reply)
        await self._verify_response(response, response.payload["access"]["responseKeyHash"])

        # Verify nonce matches
        if response.payload["access"]["nonce"] != nonce:
            raise AuthenticationError("incorrect nonce")

    async def rotate_authentication_key(self) -> None:
        """Rotate the authentication key for this device.

        This method performs key rotation for the authentication key, which
        should be done periodically for security. The server will update its
        records with the new key.

        Steps:
        1. Generate new authentication key and rotation hash
        2. Create and sign rotation request
        3. Send to server
        4. Verify response

        Raises:
            VerificationError: If response verification fails.
            AuthenticationError: If nonce mismatch occurs.
            StorageError: If storage operations fail.
            NetworkError: If network communication fails.
        """
        # Rotate keys
        public_key, rotation_hash = await self.args.store.key.authentication.rotate()
        nonce = await self.args.crypto.noncer.generate128()

        # Create and sign the request
        request = RotateAuthenticationKeyRequest(
            {
                "authentication": {
                    "device": await self.args.store.identifier.device.get(),
                    "identity": await self.args.store.identifier.identity.get(),
                    "publicKey": public_key,
                    "rotationHash": rotation_hash,
                }
            },
            nonce,
        )

        await request.sign(await self.args.store.key.authentication.signer())
        message = await request.serialize()

        # Send request and parse response
        reply = await self.args.io.network.send_request(
            self.args.paths.rotate.authentication, message
        )

        response = RotateAuthenticationKeyResponse.parse(reply)
        await self._verify_response(response, response.payload["access"]["responseKeyHash"])

        # Verify nonce matches
        if response.payload["access"]["nonce"] != nonce:
            raise AuthenticationError("incorrect nonce")

    async def authenticate(self) -> None:
        """Authenticate with the server and obtain an access token.

        This method performs a two-phase authentication:

        Phase 1 (Start):
        1. Send identity to server
        2. Receive authentication challenge (nonce)

        Phase 2 (Finish):
        1. Initialize access keys
        2. Sign challenge with authentication key
        3. Send device info and access public key
        4. Receive and store access token

        Raises:
            VerificationError: If response verification fails.
            AuthenticationError: If nonce mismatch occurs.
            StorageError: If storage operations fail.
            NetworkError: If network communication fails.
        """
        # Phase 1: Start authentication
        start_nonce = await self.args.crypto.noncer.generate128()

        start_request = StartAuthenticationRequest(
            {
                "access": {"nonce": start_nonce},
                "request": {
                    "authentication": {"identity": await self.args.store.identifier.identity.get()}
                },
            }
        )

        start_message = await start_request.serialize()
        start_reply = await self.args.io.network.send_request(
            self.args.paths.authenticate.start, start_message
        )

        start_response = StartAuthenticationResponse.parse(start_reply)
        await self._verify_response(
            start_response, start_response.payload["access"]["responseKeyHash"]
        )

        # Verify start nonce matches
        if start_response.payload["access"]["nonce"] != start_nonce:
            raise AuthenticationError("incorrect nonce")

        # Phase 2: Finish authentication
        # Initialize access keys
        _, current_key, next_key_hash = await self.args.store.key.access.initialize()
        finish_nonce = await self.args.crypto.noncer.generate128()

        finish_request = FinishAuthenticationRequest(
            {
                "access": {
                    "publicKey": current_key,
                    "rotationHash": next_key_hash,
                },
                "authentication": {
                    "device": await self.args.store.identifier.device.get(),
                    "nonce": start_response.payload["response"]["authentication"]["nonce"],
                },
            },
            finish_nonce,
        )

        await finish_request.sign(await self.args.store.key.authentication.signer())
        finish_message = await finish_request.serialize()
        finish_reply = await self.args.io.network.send_request(
            self.args.paths.authenticate.finish, finish_message
        )

        finish_response = FinishAuthenticationResponse.parse(finish_reply)
        await self._verify_response(
            finish_response,
            finish_response.payload["access"]["responseKeyHash"],
        )

        # Verify finish nonce matches
        if finish_response.payload["access"]["nonce"] != finish_nonce:
            raise AuthenticationError("incorrect nonce")

        # Store the access token
        await self.args.store.token.access.store(
            finish_response.payload["response"]["access"]["token"]
        )

    async def refresh_access_token(self) -> None:
        """Refresh the access token.

        This method rotates the access key and obtains a new access token.
        Should be called before the current token expires or when token
        refresh is needed.

        Steps:
        1. Rotate access keys
        2. Create and sign refresh request with old token
        3. Send to server
        4. Verify response
        5. Store new access token

        Raises:
            VerificationError: If response verification fails.
            AuthenticationError: If nonce mismatch occurs.
            StorageError: If storage operations fail.
            NetworkError: If network communication fails.
            ExpiredTokenError: If the current token is expired.
        """
        # Rotate access keys
        public_key, rotation_hash = await self.args.store.key.access.rotate()
        nonce = await self.args.crypto.noncer.generate128()

        # Create and sign the request
        request = RefreshAccessTokenRequest(
            {
                "access": {
                    "publicKey": public_key,
                    "rotationHash": rotation_hash,
                    "token": await self.args.store.token.access.get(),
                }
            },
            nonce,
        )

        await request.sign(await self.args.store.key.access.signer())
        message = await request.serialize()

        # Send request and parse response
        reply = await self.args.io.network.send_request(self.args.paths.rotate.access, message)

        response = RefreshAccessTokenResponse.parse(reply)
        await self._verify_response(response, response.payload["access"]["responseKeyHash"])

        # Verify nonce matches
        if response.payload["access"]["nonce"] != nonce:
            raise AuthenticationError("incorrect nonce")

        # Store new access token
        await self.args.store.token.access.store(response.payload["response"]["access"]["token"])

    async def recover_account(
        self, identity: str, recovery_key: ISigningKey, recovery_hash: str
    ) -> None:
        """Recover an account using the recovery key.

        This method allows account recovery when all devices are lost or
        compromised. It uses the recovery key to prove ownership and
        registers a new device.

        Steps:
        1. Initialize new authentication keys for this device
        2. Generate new device identifier
        3. Create and sign recovery request with recovery key
        4. Send to server
        5. Verify response
        6. Store identity and device

        Args:
            identity: The identity identifier to recover.
            recovery_key: The recovery signing key for this identity.

        Raises:
            VerificationError: If response verification fails.
            AuthenticationError: If nonce mismatch or recovery key invalid.
            StorageError: If storage operations fail.
            NetworkError: If network communication fails.
        """
        # Initialize new authentication keys
        _, current, rotation_hash = await self.args.store.key.authentication.initialize()
        device = await self.args.crypto.hasher.sum(current)
        nonce = await self.args.crypto.noncer.generate128()

        request = RecoverAccountRequest(
            {
                "authentication": {
                    "device": device,
                    "identity": identity,
                    "publicKey": current,
                    "recoveryHash": recovery_hash,
                    "recoveryKey": await recovery_key.public(),
                    "rotationHash": rotation_hash,
                }
            },
            nonce,
        )

        await request.sign(recovery_key)
        message = await request.serialize()

        # Send request and parse response
        reply = await self.args.io.network.send_request(self.args.paths.register.recover, message)

        response = RecoverAccountResponse.parse(reply)
        await self._verify_response(response, response.payload["access"]["responseKeyHash"])

        # Verify nonce matches
        if response.payload["access"]["nonce"] != nonce:
            raise AuthenticationError("incorrect nonce")

        # Store identity and device
        await self.args.store.identifier.identity.store(identity)
        await self.args.store.identifier.device.store(device)

    async def make_access_request(self, path: str, request: Any) -> str:
        """Make an authenticated request to the server.

        This method wraps an application-specific request with access control
        metadata (token, nonce, timestamp) and signs it with the access key.

        The response is verified to ensure the nonce matches, protecting
        against replay attacks.

        Args:
            path: The API path to send the request to.
            request: The request payload (any JSON-serializable type).

        Returns:
            The raw response string from the server.

        Raises:
            VerificationError: If response nonce verification fails.
            AuthenticationError: If access token is invalid or expired.
            StorageError: If storage operations fail.
            NetworkError: If network communication fails.

        Example:
            ```python
            # Make a request to get user data
            response_str = await client.make_access_request(
                "/api/user/profile",
                {"user_id": "12345"}
            )

            # Parse the response
            response_data = json.loads(response_str)
            ```
        """
        # Create access request with token, nonce, and timestamp
        access_request: AccessRequest[Any] = AccessRequest(
            {
                "access": {
                    "nonce": await self.args.crypto.noncer.generate128(),
                    "timestamp": self.args.encoding.timestamper.format(
                        self.args.encoding.timestamper.now()
                    ),
                    "token": await self.args.store.token.access.get(),
                },
                "request": request,
            }
        )

        # Sign the request
        await access_request.sign(await self.args.store.key.access.signer())
        message = await access_request.serialize()

        # Send request and parse response
        reply = await self.args.io.network.send_request(path, message)
        response = ScannableResponse.parse(reply)

        # Verify nonce matches
        if response.payload["access"]["nonce"] != access_request.payload["access"]["nonce"]:
            raise AuthenticationError("incorrect nonce")

        return reply
