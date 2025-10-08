"""Comprehensive API tests for better-auth protocol.

This module tests the complete authentication lifecycle including:
- Account creation
- Device linking
- Authentication (2-phase)
- Access token refresh
- Account recovery
- Authenticated API requests
- Key rotation
- Error handling and security checks
"""

from __future__ import annotations

from typing import Any, TypeVar

import pytest

from better_auth.api import (
    AccessVerifier,
    AccessVerifierConfig,
    BetterAuthClient,
    BetterAuthClientConfig,
    BetterAuthServer,
    BetterAuthServerConfig,
)
from better_auth.api.client import (
    CryptoConfig as ClientCryptoConfig,
    EncodingConfig as ClientEncodingConfig,
    IOConfig,
    IdentifierStoreConfig,
    KeyStoreConfig,
    PublicKeyConfig as ClientPublicKeyConfig,
    StoreConfig as ClientStoreConfig,
    TokenStoreConfig,
)
from better_auth.api.server import (
    AccessStoreConfig,
    AccessVerifierCryptoConfig,
    AccessVerifierEncodingConfig,
    AccessVerifierStorageConfig,
    AccessVerifierStoreConfig,
    AuthenticationStoreConfig,
    CryptoConfig as ServerCryptoConfig,
    EncodingConfig as ServerEncodingConfig,
    ExpiryConfig,
    KeyPairConfig,
    RecoveryStoreConfig,
    StoreConfig as ServerStoreConfig,
)
from better_auth.interfaces import (
    AccountPaths,
    AuthenticationPaths,
    DevicePaths,
    INetwork,
    ISigningKey,
    IVerifier,
    SessionPaths,
)
from better_auth.messages import AccessRequest, ServerResponse
from examples.implementation.crypto import Hasher, Noncer, Secp256r1, Secp256r1Verifier
from examples.implementation.encoding import (
    IdentityVerifier,
    Rfc3339Nano,
    TokenEncoder,
)
from examples.implementation.storage import (
    ClientRotatingKeyStore,
    ClientValueStore,
    ServerAuthenticationKeyStore,
    ServerAuthenticationNonceStore,
    ServerRecoveryHashStore,
    ServerTimeLockStore,
    VerificationKeyStore,
)

# Debug logging flag (set to True to see request/response messages)
DEBUG_LOGGING = False

# Test authentication paths
AUTHENTICATION_PATHS = {
    "account": {
        "create": "/account/create",
        "recover": "/account/recover",
    },
    "session": {
        "request": "/session/request",
        "create": "/session/create",
        "refresh": "/session/refresh",
    },
    "device": {
        "rotate": "/device/rotate",
        "link": "/device/link",
        "unlink": "/device/unlink",
    },
}


# Mock access attributes for testing
class MockAccessAttributes(dict):
    """Mock access attributes containing permissions by role."""

    def __init__(self, permissions_by_role: dict[str, list[str]]):
        """Initialize mock access attributes.

        Args:
            permissions_by_role: Dictionary mapping role names to lists of permissions.
        """
        super().__init__(permissions_by_role=permissions_by_role)
        self.permissions_by_role = permissions_by_role


# Type variables for generic request/response handling
T = TypeVar("T")
R = TypeVar("R")


class FakeRequest:
    """Fake request for testing access control."""

    def __init__(self, foo: str, bar: str):
        self.foo = foo
        self.bar = bar


class FakeResponse:
    """Fake response for testing access control."""

    def __init__(self, was_foo: str, was_bar: str):
        self.was_foo = was_foo
        self.was_bar = was_bar


class FakeServerResponse(ServerResponse):
    """Server response wrapper for fake response data."""

    @classmethod
    def parse(cls, message: str) -> FakeServerResponse:
        """Parse a serialized server response.

        Args:
            message: Serialized server response message.

        Returns:
            Parsed FakeServerResponse instance.
        """
        return ServerResponse._parse(message, cls)


class MockNetworkServer(INetwork):
    """Mock network server for testing client-server interactions.

    This class simulates a network layer that routes requests to the appropriate
    server endpoints and handles custom test endpoints.
    """

    def __init__(
        self,
        better_auth_server: BetterAuthServer,
        access_verifier: AccessVerifier,
        response_signer: ISigningKey,
        attributes: MockAccessAttributes,
        paths: dict[str, Any],
        hasher: Hasher,
    ):
        """Initialize mock network server.

        Args:
            better_auth_server: The BetterAuth server instance.
            access_verifier: Access token verifier.
            response_signer: Key for signing responses.
            attributes: Mock access attributes for testing.
            paths: Authentication path configuration.
            hasher: Hash function for computing response key hash.
        """
        self.better_auth_server = better_auth_server
        self.access_verifier = access_verifier
        self.response_signer = response_signer
        self.attributes = attributes
        self.paths = paths
        self.hasher = hasher

    async def respond_to_access_request(self, message: str, nonce: str | None = None) -> str:
        """Generate a signed response to an access request.

        Args:
            message: The access request message.
            nonce: Optional override nonce for testing nonce mismatches.

        Returns:
            Serialized signed server response.
        """
        request = AccessRequest.parse(message)

        reply_nonce = request.payload["access"]["nonce"]
        if nonce is not None:
            reply_nonce = nonce

        # Create response with swapped values to test data flow
        response_data = {
            "was_foo": request.payload["request"]["foo"],
            "was_bar": request.payload["request"]["bar"],
        }

        server_identity = await self.response_signer.public()

        response = FakeServerResponse(
            response=response_data,
            server_identity=server_identity,
            nonce=reply_nonce,
        )

        await response.sign(self.response_signer)
        return await response.serialize()

    async def send_request(self, path: str, message: str) -> str:
        """Send a request to the mock server.

        Args:
            path: The endpoint path.
            message: The request message.

        Returns:
            The server's response message.
        """
        if DEBUG_LOGGING:
            print(f"Request to {path}:")
            print(message)

        reply = await self._send_request(path, message)

        if DEBUG_LOGGING:
            print(f"Response from {path}:")
            print(reply)

        return reply

    async def _send_request(self, path: str, message: str) -> str:
        """Internal request routing implementation.

        Args:
            path: The endpoint path.
            message: The request message.

        Returns:
            The server's response message.

        Raises:
            ValueError: If the path is not recognized.
            RuntimeError: If access verification fails.
        """
        # Route to appropriate server endpoint
        if path == self.paths["account"]["create"]:
            return await self.better_auth_server.create_account(message)

        elif path == self.paths["account"]["recover"]:
            return await self.better_auth_server.recover_account(message)

        elif path == self.paths["device"]["link"]:
            return await self.better_auth_server.link_device(message)

        elif path == self.paths["device"]["unlink"]:
            return await self.better_auth_server.unlink_device(message)

        elif path == self.paths["device"]["rotate"]:
            return await self.better_auth_server.rotate_device(message)

        elif path == self.paths["session"]["request"]:
            return await self.better_auth_server.request_session(message)

        elif path == self.paths["session"]["create"]:
            return await self.better_auth_server.create_session(message, self.attributes)

        elif path == self.paths["session"]["refresh"]:
            return await self.better_auth_server.refresh_session(message)

        elif path == "/foo/bar":
            # Test endpoint for successful access
            request, token = await self.access_verifier.verify(message)

            if request is None:
                raise RuntimeError("null request")

            if token is None:
                raise RuntimeError("null token")

            if not token.identity.startswith("E"):
                raise RuntimeError("unexpected identity format")

            if len(token.identity) != 44:
                raise RuntimeError("unexpected identity length")

            if token.attributes.get("permissions_by_role") != self.attributes.permissions_by_role:
                raise RuntimeError("attributes do not match")

            return await self.respond_to_access_request(message)

        elif path == "/bad/nonce":
            # Test endpoint for nonce mismatch detection
            request, token = await self.access_verifier.verify(message)

            if request is None:
                raise RuntimeError("null request")

            if token is None:
                raise RuntimeError("null token")

            if not token.identity.startswith("E"):
                raise RuntimeError("unexpected identity format")

            if len(token.identity) != 44:
                raise RuntimeError("unexpected identity length")

            if token.attributes.get("permissions_by_role") != self.attributes.permissions_by_role:
                raise RuntimeError("attributes do not match")

            # Return response with wrong nonce
            return await self.respond_to_access_request(message, "0A0123456789abcdefghijkl")

        else:
            raise ValueError(f"unexpected path: {path}")


# Helper functions


async def create_response_key_store(response_signer: ISigningKey) -> VerificationKeyStore:
    """Create a verification key store with the response signer's public key.

    Args:
        response_signer: The response signing key.

    Returns:
        VerificationKeyStore with the response public key added.
    """
    response_key_store = VerificationKeyStore()
    response_identity = await response_signer.identity()
    response_key_store.add(response_identity, response_signer)
    return response_key_store


async def execute_flow(
    better_auth_client: BetterAuthClient,
    ecc_verifier: IVerifier,
    crypto_keys: dict[str, Secp256r1],
) -> None:
    """Execute the full authentication flow.

    This tests the complete lifecycle:
    1. Rotate authentication key
    2. Authenticate (2-phase)
    3. Refresh access token
    4. Make authenticated request

    Args:
        better_auth_client: The client instance.
        ecc_verifier: ECC signature verifier.
        crypto_keys: Cryptographic keys fixture.

    Raises:
        Exception: If any step fails.
    """
    await better_auth_client.rotate_device()
    await better_auth_client.create_session()
    await better_auth_client.refresh_session()

    await verify_access(better_auth_client, ecc_verifier, crypto_keys)


async def verify_access(
    better_auth_client: BetterAuthClient,
    ecc_verifier: IVerifier,
    crypto_keys: dict[str, Secp256r1],
) -> None:
    """Test making an authenticated access request.

    Args:
        better_auth_client: The client instance.
        ecc_verifier: ECC signature verifier.
        crypto_keys: Cryptographic keys fixture.

    Raises:
        RuntimeError: If response data is invalid.
    """
    message = {"foo": "bar", "bar": "foo"}
    reply = await better_auth_client.make_access_request("/foo/bar", message)
    response = FakeServerResponse.parse(reply)

    await response.verify(ecc_verifier, await crypto_keys["response_signer"].public())

    if (
        response.payload["response"]["was_foo"] != "bar"
        or response.payload["response"]["was_bar"] != "foo"
    ):
        raise RuntimeError("invalid data returned")


async def create_server(
    expiry: dict[str, int],
    keys: dict[str, ISigningKey],
) -> BetterAuthServer:
    """Create a BetterAuth server instance with test configuration.

    Args:
        expiry: Expiry configuration with keys:
            - access_lifetime_in_minutes: Access token lifetime
            - authentication_challenge_lifetime_in_seconds: Auth challenge lifetime
            - refresh_lifetime_in_hours: Refresh token lifetime
        keys: Signing keys with keys:
            - access_signer: Access token signing key
            - response_signer: Response signing key

    Returns:
        Configured BetterAuthServer instance.
    """
    ecc_verifier = Secp256r1Verifier()
    hasher = Hasher()

    access_key_hash_store = ServerTimeLockStore(60 * 60 * expiry["refresh_lifetime_in_hours"])
    authentication_nonce_store = ServerAuthenticationNonceStore(
        expiry["authentication_challenge_lifetime_in_seconds"]
    )

    config = BetterAuthServerConfig(
        crypto=ServerCryptoConfig(
            hasher=hasher,
            key_pair=KeyPairConfig(
                access=keys["access_signer"],
                response=keys["response_signer"],
            ),
            verifier=ecc_verifier,
        ),
        encoding=ServerEncodingConfig(
            identity_verifier=IdentityVerifier(),
            timestamper=Rfc3339Nano(),
            token_encoder=TokenEncoder(),
        ),
        expiry=ExpiryConfig(
            access_in_minutes=expiry["access_lifetime_in_minutes"],
            refresh_in_hours=expiry["refresh_lifetime_in_hours"],
        ),
        store=ServerStoreConfig(
            access=AccessStoreConfig(
                key_hash=access_key_hash_store,
            ),
            authentication=AuthenticationStoreConfig(
                key=ServerAuthenticationKeyStore(),
                nonce=authentication_nonce_store,
            ),
            recovery=RecoveryStoreConfig(
                hash=ServerRecoveryHashStore(),
            ),
        ),
    )

    return BetterAuthServer(config)


async def create_verifier(
    expiry: dict[str, int],
    keys: dict[str, ISigningKey],
) -> AccessVerifier:
    """Create an AccessVerifier instance with test configuration.

    Args:
        expiry: Expiry configuration with keys:
            - access_window_in_seconds: Access token validity window
        keys: Verification keys with keys:
            - access_verifier: Access token verification key

    Returns:
        Configured AccessVerifier instance.
    """
    ecc_verifier = Secp256r1Verifier()
    access_nonce_store = ServerTimeLockStore(expiry["access_window_in_seconds"])
    access_key_store = VerificationKeyStore()

    # Add the access verification key to the store
    # We need to get the server identity from the access signer
    access_identity = await keys["access_verifier"].identity()
    access_key_store.add(access_identity, keys["access_verifier"])

    config = AccessVerifierConfig(
        crypto=AccessVerifierCryptoConfig(
            access_key_store=access_key_store,
            verifier=ecc_verifier,
        ),
        encoding=AccessVerifierEncodingConfig(
            token_encoder=TokenEncoder(),
            timestamper=Rfc3339Nano(),
        ),
        store=AccessVerifierStorageConfig(
            access=AccessVerifierStoreConfig(
                nonce=access_nonce_store,
            ),
        ),
    )

    return AccessVerifier(config)


# Pytest fixtures


@pytest.fixture
async def crypto_keys() -> dict[str, Secp256r1]:
    """Create cryptographic key pairs for testing.

    Returns:
        Dictionary containing access_signer, response_signer, and recovery_signer.
    """
    access_signer = Secp256r1()
    response_signer = Secp256r1()
    recovery_signer = Secp256r1()

    await access_signer.generate()
    await response_signer.generate()
    await recovery_signer.generate()

    return {
        "access_signer": access_signer,
        "response_signer": response_signer,
        "recovery_signer": recovery_signer,
    }


@pytest.fixture
def ecc_verifier() -> Secp256r1Verifier:
    """Create an ECC signature verifier.

    Returns:
        Secp256r1Verifier instance.
    """
    return Secp256r1Verifier()


@pytest.fixture
def hasher() -> Hasher:
    """Create a hasher instance.

    Returns:
        Hasher instance.
    """
    return Hasher()


@pytest.fixture
def noncer() -> Noncer:
    """Create a noncer instance.

    Returns:
        Noncer instance.
    """
    return Noncer()


@pytest.fixture
async def better_auth_server(crypto_keys: dict[str, Secp256r1]) -> BetterAuthServer:
    """Create a BetterAuth server with standard test configuration.

    Args:
        crypto_keys: Cryptographic keys fixture.

    Returns:
        Configured BetterAuthServer instance.
    """
    return await create_server(
        expiry={
            "refresh_lifetime_in_hours": 12,
            "access_lifetime_in_minutes": 15,
            "authentication_challenge_lifetime_in_seconds": 60,
        },
        keys={
            "access_signer": crypto_keys["access_signer"],
            "response_signer": crypto_keys["response_signer"],
        },
    )


@pytest.fixture
async def access_verifier(crypto_keys: dict[str, Secp256r1]) -> AccessVerifier:
    """Create an access verifier with standard test configuration.

    Args:
        crypto_keys: Cryptographic keys fixture.

    Returns:
        Configured AccessVerifier instance.
    """
    return await create_verifier(
        expiry={
            "access_window_in_seconds": 30,
        },
        keys={
            "access_verifier": crypto_keys["access_signer"],
        },
    )


@pytest.fixture
def mock_access_attributes() -> MockAccessAttributes:
    """Create mock access attributes for testing.

    Returns:
        MockAccessAttributes with admin permissions.
    """
    return MockAccessAttributes({"admin": ["read", "write"]})


@pytest.fixture
def mock_network_server(
    better_auth_server: BetterAuthServer,
    access_verifier: AccessVerifier,
    crypto_keys: dict[str, Secp256r1],
    mock_access_attributes: MockAccessAttributes,
    hasher: Hasher,
) -> MockNetworkServer:
    """Create a mock network server for testing.

    Args:
        better_auth_server: BetterAuth server fixture.
        access_verifier: Access verifier fixture.
        crypto_keys: Cryptographic keys fixture.
        mock_access_attributes: Mock access attributes fixture.
        hasher: Hasher fixture.

    Returns:
        Configured MockNetworkServer instance.
    """
    return MockNetworkServer(
        better_auth_server,
        access_verifier,
        crypto_keys["response_signer"],
        mock_access_attributes,
        AUTHENTICATION_PATHS,
        hasher,
    )


@pytest.fixture
async def better_auth_client(
    hasher: Hasher,
    noncer: Noncer,
    crypto_keys: dict[str, Secp256r1],
    mock_network_server: MockNetworkServer,
) -> BetterAuthClient:
    """Create a BetterAuth client with standard test configuration.

    Args:
        hasher: Hasher fixture.
        noncer: Noncer fixture.
        crypto_keys: Cryptographic keys fixture.
        mock_network_server: Mock network server fixture.

    Returns:
        Configured BetterAuthClient instance.
    """
    config = BetterAuthClientConfig(
        crypto=ClientCryptoConfig(
            hasher=hasher,
            noncer=noncer,
            public_key=ClientPublicKeyConfig(
                response=await create_response_key_store(crypto_keys["response_signer"]),
            ),
        ),
        encoding=ClientEncodingConfig(
            timestamper=Rfc3339Nano(),
        ),
        io=IOConfig(
            network=mock_network_server,
        ),
        paths=AuthenticationPaths(
            account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
            session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
            device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
        ),
        store=ClientStoreConfig(
            identifier=IdentifierStoreConfig(
                device=ClientValueStore(),
                identity=ClientValueStore(),
            ),
            key=KeyStoreConfig(
                access=ClientRotatingKeyStore(),
                authentication=ClientRotatingKeyStore(),
            ),
            token=TokenStoreConfig(
                access=ClientValueStore(),
            ),
        ),
    )

    return BetterAuthClient(config)


# Test cases


@pytest.mark.asyncio
async def test_completes_auth_flows(
    better_auth_client: BetterAuthClient,
    ecc_verifier: Secp256r1Verifier,
    crypto_keys: dict[str, Secp256r1],
    hasher: Hasher,
) -> None:
    """Test complete authentication flow including account creation and access.

    This test verifies:
    1. Account creation with recovery hash
    2. Authentication key rotation
    3. Two-phase authentication
    4. Access token refresh
    5. Authenticated API request
    """
    recovery_hash = await hasher.sum(await crypto_keys["recovery_signer"].public())
    await better_auth_client.create_account(recovery_hash)
    await execute_flow(better_auth_client, ecc_verifier, crypto_keys)


@pytest.mark.asyncio
async def test_recovers_from_loss(
    hasher: Hasher,
    noncer: Noncer,
    crypto_keys: dict[str, Secp256r1],
    better_auth_server: BetterAuthServer,
    access_verifier: AccessVerifier,
    mock_access_attributes: MockAccessAttributes,
    ecc_verifier: Secp256r1Verifier,
) -> None:
    """Test account recovery flow after device loss.

    This test verifies:
    1. Original account creation
    2. Account recovery on new device using recovery key
    3. Full authentication flow on recovered device
    """
    mock_network_server = MockNetworkServer(
        better_auth_server,
        access_verifier,
        crypto_keys["response_signer"],
        mock_access_attributes,
        AUTHENTICATION_PATHS,
        hasher,
    )

    # Original device client
    better_auth_client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=ClientCryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=ClientPublicKeyConfig(
                    response=await create_response_key_store(crypto_keys["response_signer"]),
                ),
            ),
            encoding=ClientEncodingConfig(
                timestamper=Rfc3339Nano(),
            ),
            io=IOConfig(
                network=mock_network_server,
            ),
            paths=AuthenticationPaths(
                account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
                session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
                device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
            ),
            store=ClientStoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(
                    access=ClientValueStore(),
                ),
            ),
        )
    )

    # Recovered device client (simulates new device)
    recovered_better_auth_client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=ClientCryptoConfig(
                hasher=Hasher(),
                noncer=Noncer(),
                public_key=ClientPublicKeyConfig(
                    response=await create_response_key_store(crypto_keys["response_signer"]),
                ),
            ),
            encoding=ClientEncodingConfig(
                timestamper=Rfc3339Nano(),
            ),
            io=IOConfig(
                network=mock_network_server,
            ),
            paths=AuthenticationPaths(
                account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
                session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
                device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
            ),
            store=ClientStoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(
                    access=ClientValueStore(),
                ),
            ),
        )
    )

    # Create account on original device
    recovery_hash = await hasher.sum(await crypto_keys["recovery_signer"].public())
    await better_auth_client.create_account(recovery_hash)
    identity = await better_auth_client.identity()

    next_recovery_signer = Secp256r1()
    await next_recovery_signer.generate()
    next_recovery_hash = await hasher.sum(await next_recovery_signer.public())

    # Recover account on new device
    await recovered_better_auth_client.recover_account(
        identity, crypto_keys["recovery_signer"], next_recovery_hash
    )

    # Test full flow on recovered device
    await execute_flow(recovered_better_auth_client, ecc_verifier, crypto_keys)


@pytest.mark.asyncio
async def test_links_another_device(
    hasher: Hasher,
    noncer: Noncer,
    crypto_keys: dict[str, Secp256r1],
    better_auth_server: BetterAuthServer,
    access_verifier: AccessVerifier,
    mock_access_attributes: MockAccessAttributes,
    ecc_verifier: Secp256r1Verifier,
) -> None:
    """Test device linking flow.

    This test verifies:
    1. Account creation on original device
    2. Link container generation on new device
    3. Link container endorsement and submission from original device
    4. Full authentication flow on linked device
    """
    mock_network_server = MockNetworkServer(
        better_auth_server,
        access_verifier,
        crypto_keys["response_signer"],
        mock_access_attributes,
        AUTHENTICATION_PATHS,
        hasher,
    )

    # Original device client
    better_auth_client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=ClientCryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=ClientPublicKeyConfig(
                    response=await create_response_key_store(crypto_keys["response_signer"]),
                ),
            ),
            encoding=ClientEncodingConfig(
                timestamper=Rfc3339Nano(),
            ),
            io=IOConfig(
                network=mock_network_server,
            ),
            paths=AuthenticationPaths(
                account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
                session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
                device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
            ),
            store=ClientStoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(
                    access=ClientValueStore(),
                ),
            ),
        )
    )

    # Linked device client (simulates new device)
    linked_better_auth_client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=ClientCryptoConfig(
                hasher=Hasher(),
                noncer=Noncer(),
                public_key=ClientPublicKeyConfig(
                    response=await create_response_key_store(crypto_keys["response_signer"]),
                ),
            ),
            encoding=ClientEncodingConfig(
                timestamper=Rfc3339Nano(),
            ),
            io=IOConfig(
                network=mock_network_server,
            ),
            paths=AuthenticationPaths(
                account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
                session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
                device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
            ),
            store=ClientStoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(
                    access=ClientValueStore(),
                ),
            ),
        )
    )

    # Create account on original device
    recovery_hash = await hasher.sum(await crypto_keys["recovery_signer"].public())
    await better_auth_client.create_account(recovery_hash)
    identity = await better_auth_client.identity()

    # Generate link container on new device
    link_container = await linked_better_auth_client.generate_link_container(identity)
    if DEBUG_LOGGING:
        print(f"Link container: {link_container}")

    # Submit endorsed link container from original device
    await better_auth_client.link_device(link_container)

    # Test full flow on linked device
    await execute_flow(linked_better_auth_client, ecc_verifier, crypto_keys)

    await linked_better_auth_client.unlink_device(await better_auth_client.device())


@pytest.mark.asyncio
async def test_rejects_expired_authentication_challenges(
    hasher: Hasher,
    noncer: Noncer,
    crypto_keys: dict[str, Secp256r1],
    mock_access_attributes: MockAccessAttributes,
    ecc_verifier: Secp256r1Verifier,
) -> None:
    """Test rejection of expired authentication challenges.

    This test verifies that authentication challenges with negative lifetime
    (already expired) are properly rejected.
    """
    # Create server with expired authentication challenge lifetime
    better_auth_server = await create_server(
        expiry={
            "refresh_lifetime_in_hours": 12,
            "access_lifetime_in_minutes": 15,
            "authentication_challenge_lifetime_in_seconds": -5,  # Already expired
        },
        keys={
            "access_signer": crypto_keys["access_signer"],
            "response_signer": crypto_keys["response_signer"],
        },
    )

    access_verifier = await create_verifier(
        expiry={
            "access_window_in_seconds": 30,
        },
        keys={
            "access_verifier": crypto_keys["access_signer"],
        },
    )

    mock_network_server = MockNetworkServer(
        better_auth_server,
        access_verifier,
        crypto_keys["response_signer"],
        mock_access_attributes,
        AUTHENTICATION_PATHS,
        hasher,
    )

    better_auth_client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=ClientCryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=ClientPublicKeyConfig(
                    response=await create_response_key_store(crypto_keys["response_signer"]),
                ),
            ),
            encoding=ClientEncodingConfig(
                timestamper=Rfc3339Nano(),
            ),
            io=IOConfig(
                network=mock_network_server,
            ),
            paths=AuthenticationPaths(
                account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
                session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
                device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
            ),
            store=ClientStoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(
                    access=ClientValueStore(),
                ),
            ),
        )
    )

    recovery_hash = await hasher.sum(await crypto_keys["recovery_signer"].public())
    await better_auth_client.create_account(recovery_hash)

    with pytest.raises(Exception) as exc_info:
        await execute_flow(better_auth_client, ecc_verifier, crypto_keys)

    assert "expired nonce" in str(exc_info.value)


@pytest.mark.asyncio
async def test_rejects_expired_refresh_tokens(
    hasher: Hasher,
    noncer: Noncer,
    crypto_keys: dict[str, Secp256r1],
    mock_access_attributes: MockAccessAttributes,
    ecc_verifier: Secp256r1Verifier,
) -> None:
    """Test rejection of expired refresh tokens.

    This test verifies that refresh tokens with negative lifetime
    (already expired) are properly rejected.
    """
    # Create server with expired refresh token lifetime
    better_auth_server = await create_server(
        expiry={
            "refresh_lifetime_in_hours": -1,  # Already expired
            "access_lifetime_in_minutes": 15,
            "authentication_challenge_lifetime_in_seconds": 60,
        },
        keys={
            "access_signer": crypto_keys["access_signer"],
            "response_signer": crypto_keys["response_signer"],
        },
    )

    access_verifier = await create_verifier(
        expiry={
            "access_window_in_seconds": 30,
        },
        keys={
            "access_verifier": crypto_keys["access_signer"],
        },
    )

    mock_network_server = MockNetworkServer(
        better_auth_server,
        access_verifier,
        crypto_keys["response_signer"],
        mock_access_attributes,
        AUTHENTICATION_PATHS,
        hasher,
    )

    better_auth_client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=ClientCryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=ClientPublicKeyConfig(
                    response=await create_response_key_store(crypto_keys["response_signer"]),
                ),
            ),
            encoding=ClientEncodingConfig(
                timestamper=Rfc3339Nano(),
            ),
            io=IOConfig(
                network=mock_network_server,
            ),
            paths=AuthenticationPaths(
                account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
                session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
                device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
            ),
            store=ClientStoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(
                    access=ClientValueStore(),
                ),
            ),
        )
    )

    recovery_hash = await hasher.sum(await crypto_keys["recovery_signer"].public())
    await better_auth_client.create_account(recovery_hash)

    with pytest.raises(Exception) as exc_info:
        await execute_flow(better_auth_client, ecc_verifier, crypto_keys)

    assert "refresh has expired" in str(exc_info.value)


@pytest.mark.asyncio
async def test_rejects_expired_access_tokens(
    hasher: Hasher,
    noncer: Noncer,
    crypto_keys: dict[str, Secp256r1],
    mock_access_attributes: MockAccessAttributes,
    ecc_verifier: Secp256r1Verifier,
) -> None:
    """Test rejection of expired access tokens.

    This test verifies that access tokens with negative lifetime
    (already expired) are properly rejected.
    """
    # Create server with expired access token lifetime
    better_auth_server = await create_server(
        expiry={
            "refresh_lifetime_in_hours": 12,
            "access_lifetime_in_minutes": -1,  # Already expired
            "authentication_challenge_lifetime_in_seconds": 60,
        },
        keys={
            "access_signer": crypto_keys["access_signer"],
            "response_signer": crypto_keys["response_signer"],
        },
    )

    access_verifier = await create_verifier(
        expiry={
            "access_window_in_seconds": 30,
        },
        keys={
            "access_verifier": crypto_keys["access_signer"],
        },
    )

    mock_network_server = MockNetworkServer(
        better_auth_server,
        access_verifier,
        crypto_keys["response_signer"],
        mock_access_attributes,
        AUTHENTICATION_PATHS,
        hasher,
    )

    better_auth_client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=ClientCryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=ClientPublicKeyConfig(
                    response=await create_response_key_store(crypto_keys["response_signer"]),
                ),
            ),
            encoding=ClientEncodingConfig(
                timestamper=Rfc3339Nano(),
            ),
            io=IOConfig(
                network=mock_network_server,
            ),
            paths=AuthenticationPaths(
                account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
                session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
                device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
            ),
            store=ClientStoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(
                    access=ClientValueStore(),
                ),
            ),
        )
    )

    recovery_hash = await hasher.sum(await crypto_keys["recovery_signer"].public())
    await better_auth_client.create_account(recovery_hash)

    with pytest.raises(Exception) as exc_info:
        await execute_flow(better_auth_client, ecc_verifier, crypto_keys)

    assert "token expired" in str(exc_info.value)


@pytest.mark.asyncio
async def test_detects_tampered_access_tokens(
    hasher: Hasher,
    noncer: Noncer,
    crypto_keys: dict[str, Secp256r1],
    better_auth_server: BetterAuthServer,
    access_verifier: AccessVerifier,
    mock_access_attributes: MockAccessAttributes,
    ecc_verifier: Secp256r1Verifier,
) -> None:
    """Test detection of tampered access tokens.

    This test verifies that tampering with the token payload is detected
    through signature verification failure.
    """
    mock_network_server = MockNetworkServer(
        better_auth_server,
        access_verifier,
        crypto_keys["response_signer"],
        mock_access_attributes,
        AUTHENTICATION_PATHS,
        hasher,
    )

    access_token_store = ClientValueStore()
    better_auth_client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=ClientCryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=ClientPublicKeyConfig(
                    response=await create_response_key_store(crypto_keys["response_signer"]),
                ),
            ),
            encoding=ClientEncodingConfig(
                timestamper=Rfc3339Nano(),
            ),
            io=IOConfig(
                network=mock_network_server,
            ),
            paths=AuthenticationPaths(
                account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
                session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
                device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
            ),
            store=ClientStoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(
                    access=access_token_store,
                ),
            ),
        )
    )

    recovery_hash = await hasher.sum(await crypto_keys["recovery_signer"].public())
    await better_auth_client.create_account(recovery_hash)

    token_encoder = TokenEncoder()

    with pytest.raises(Exception) as exc_info:
        await better_auth_client.create_session()
        token = await access_token_store.get()

        # Tamper with the token by modifying the identity field
        token_string = await token_encoder.decode(token[88:])
        tampered_token_string = token_string.replace('"identity":"E', '"identity":"X')
        tampered_token = await token_encoder.encode(tampered_token_string)
        await access_token_store.store(token[:88] + tampered_token)

        # Attempt to use tampered token
        await verify_access(better_auth_client, ecc_verifier, crypto_keys)

    assert "invalid signature" in str(exc_info.value)


@pytest.mark.asyncio
async def test_detects_mismatched_access_nonce(
    hasher: Hasher,
    noncer: Noncer,
    crypto_keys: dict[str, Secp256r1],
    better_auth_server: BetterAuthServer,
    access_verifier: AccessVerifier,
    mock_access_attributes: MockAccessAttributes,
) -> None:
    """Test detection of mismatched access nonce in response.

    This test verifies that when the server returns a response with a different
    nonce than the one sent in the request, the client detects the mismatch.
    """
    mock_network_server = MockNetworkServer(
        better_auth_server,
        access_verifier,
        crypto_keys["response_signer"],
        mock_access_attributes,
        AUTHENTICATION_PATHS,
        hasher,
    )

    access_token_store = ClientValueStore()
    better_auth_client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=ClientCryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=ClientPublicKeyConfig(
                    response=await create_response_key_store(crypto_keys["response_signer"]),
                ),
            ),
            encoding=ClientEncodingConfig(
                timestamper=Rfc3339Nano(),
            ),
            io=IOConfig(
                network=mock_network_server,
            ),
            paths=AuthenticationPaths(
                account=AccountPaths(**AUTHENTICATION_PATHS["account"]),
                session=SessionPaths(**AUTHENTICATION_PATHS["session"]),
                device=DevicePaths(**AUTHENTICATION_PATHS["device"]),
            ),
            store=ClientStoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(
                    access=access_token_store,
                ),
            ),
        )
    )

    recovery_hash = await hasher.sum(await crypto_keys["recovery_signer"].public())
    await better_auth_client.create_account(recovery_hash)

    with pytest.raises(Exception) as exc_info:
        await better_auth_client.create_session()

        # Make request to endpoint that returns wrong nonce
        message = {"foo": "bar", "bar": "foo"}
        await better_auth_client.make_access_request("/bad/nonce", message)

    assert "incorrect nonce" in str(exc_info.value)
