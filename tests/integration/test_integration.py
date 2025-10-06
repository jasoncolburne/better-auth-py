"""Integration tests for better-auth client against live servers."""

import asyncio
from typing import Any, Dict

import httpx
import pytest

from better_auth.api.client import (
    BetterAuthClient,
    BetterAuthClientConfig,
    CryptoConfig,
    EncodingConfig,
    IdentifierStoreConfig,
    IOConfig,
    KeyStoreConfig,
    PublicKeyConfig,
    StoreConfig,
    TokenStoreConfig,
)
from better_auth.interfaces import (
    AccountPaths,
    AuthenticatePaths,
    AuthenticationPaths,
    IHasher,
    INetwork,
    INoncer,
    ITimestamper,
    IVerificationKeyStore,
    IVerifier,
    RotatePaths,
)
from better_auth.messages import ServerResponse

# Import test implementations from examples
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'examples'))

from implementation.crypto import Hasher, Noncer, Secp256r1, Secp256r1Verifier
from implementation.encoding import Rfc3339Nano
from implementation.storage import ClientRotatingKeyStore, ClientValueStore, VerificationKeyStore

DEBUG_LOGGING = False

# Authentication paths matching the server
authentication_paths = AuthenticationPaths(
    authenticate=AuthenticatePaths(
        start="/authenticate/start",
        finish="/authenticate/finish",
    ),
    account=AccountPaths(
        create="/account/create",
    ),
    rotate=RotatePaths(
        authentication="/rotate/authentication",
        access="/rotate/access",
        link="/rotate/link",
        unlink="/rotate/unlink",
        recover="/rotate/recover",
    ),
)


class Network(INetwork):
    """HTTP network implementation for integration tests."""

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.client = httpx.AsyncClient()

    async def send_request(self, path: str, message: str) -> str:
        if DEBUG_LOGGING:
            print(f"Request to {path}:")
            print(message)

        response = await self.client.post(
            f"{self.base_url}{path}",
            headers={"Content-Type": "application/json"},
            content=message,
        )

        reply = response.text

        if DEBUG_LOGGING:
            print(f"Response from {path}:")
            print(reply)

        return reply

    async def close(self):
        await self.client.aclose()


class FakeResponse(ServerResponse[Dict[str, Any]]):
    """Test response message for access requests."""

    @classmethod
    def parse(cls, message: str) -> "FakeResponse":
        return super()._parse(message, cls)


async def execute_flow(
    better_auth_client: BetterAuthClient,
    ecc_verifier: IVerifier,
    verification_key_store: IVerificationKeyStore,
) -> None:
    """Execute the standard authentication flow."""
    await better_auth_client.rotate_authentication_key()
    await better_auth_client.authenticate()
    await better_auth_client.refresh_access_token()

    await _test_access(better_auth_client, ecc_verifier, verification_key_store)


async def _test_access(
    better_auth_client: BetterAuthClient,
    ecc_verifier: IVerifier,
    verification_key_store: IVerificationKeyStore,
) -> None:
    """Test authenticated access request."""
    message = {"foo": "bar", "bar": "foo"}

    reply = await better_auth_client.make_access_request("/foo/bar", message)
    response = FakeResponse.parse(reply)

    # Get the verification key for this server
    response_key = await verification_key_store.get(response.payload["access"]["serverIdentity"])
    await response.verify(ecc_verifier, await response_key.public())

    assert response.payload["response"]["wasFoo"] == "bar"
    assert response.payload["response"]["wasBar"] == "foo"


@pytest.fixture
async def client_components():
    """Create reusable client components."""
    hasher = Hasher()
    noncer = Noncer()
    verifier = Secp256r1Verifier()
    timestamper = Rfc3339Nano()
    network = Network()

    # Fetch server's response public key
    response_public_key = await network.send_request("/key/response", "")

    # Create a verification key wrapper for the server's public key
    class ServerVerificationKey:
        def __init__(self, public_key: str):
            self._public_key = public_key
            self._verifier = Secp256r1Verifier()

        async def public(self):
            return self._public_key

        def verifier(self):
            return self._verifier

    server_verification_key = ServerVerificationKey(response_public_key)

    # Create verification key store and add server's response key
    # Server identity is the public key itself (not hashed)
    verification_key_store = VerificationKeyStore()
    server_identity = response_public_key
    verification_key_store.add(server_identity, server_verification_key)

    yield {
        "hasher": hasher,
        "noncer": noncer,
        "verifier": verifier,
        "timestamper": timestamper,
        "network": network,
        "verification_key_store": verification_key_store,
    }

    await network.close()


@pytest.mark.asyncio
async def test_completes_auth_flows(client_components):
    """Test that authentication flow completes successfully."""
    hasher: IHasher = client_components["hasher"]
    noncer: INoncer = client_components["noncer"]
    verifier: IVerifier = client_components["verifier"]
    timestamper: ITimestamper = client_components["timestamper"]
    network: INetwork = client_components["network"]
    verification_key_store: IVerificationKeyStore = client_components["verification_key_store"]

    # Create recovery key
    recovery_signer = Secp256r1()
    await recovery_signer.generate()
    recovery_hash = await hasher.sum(await recovery_signer.public())

    # Create client
    client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=CryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=PublicKeyConfig(
                    response=verification_key_store,
                ),
            ),
            encoding=EncodingConfig(timestamper=timestamper),
            io=IOConfig(network=network),
            paths=authentication_paths,
            store=StoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(access=ClientValueStore()),
            ),
        )
    )

    await client.create_account(recovery_hash)
    await execute_flow(client, verifier, verification_key_store)


@pytest.mark.asyncio
async def test_recovers_from_loss(client_components):
    """Test account recovery flow."""
    hasher: IHasher = client_components["hasher"]
    noncer: INoncer = client_components["noncer"]
    verifier: IVerifier = client_components["verifier"]
    timestamper: ITimestamper = client_components["timestamper"]
    network: INetwork = client_components["network"]
    verification_key_store: IVerificationKeyStore = client_components["verification_key_store"]

    # Shared stores for recovery scenario
    identity_store = ClientValueStore()

    # Create recovery key
    recovery_signer = Secp256r1()
    await recovery_signer.generate()
    recovery_hash = await hasher.sum(await recovery_signer.public())

    # Create initial client
    client1 = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=CryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=PublicKeyConfig(
                    response=verification_key_store,
                ),
            ),
            encoding=EncodingConfig(timestamper=timestamper),
            io=IOConfig(network=network),
            paths=authentication_paths,
            store=StoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=identity_store,
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(access=ClientValueStore()),
            ),
        )
    )

    await client1.create_account(recovery_hash)

    # Get the identity before we lose the device
    identity = await identity_store.get()

    await execute_flow(client1, verifier, verification_key_store)

    # Simulate device loss - create new client with only identity preserved
    client2 = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=CryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=PublicKeyConfig(
                    response=verification_key_store,
                ),
            ),
            encoding=EncodingConfig(timestamper=timestamper),
            io=IOConfig(network=network),
            paths=authentication_paths,
            store=StoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=identity_store,
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(access=ClientValueStore()),
            ),
        )
    )

    # Create next recovery key
    next_recovery_signer = Secp256r1()
    await next_recovery_signer.generate()
    next_recovery_hash = await hasher.sum(await next_recovery_signer.public())

    # Recover account with recovery key
    await client2.recover_account(identity, recovery_signer, next_recovery_hash)
    await execute_flow(client2, verifier, verification_key_store)


@pytest.mark.asyncio
async def test_links_another_device(client_components):
    """Test device linking flow."""
    hasher: IHasher = client_components["hasher"]
    noncer: INoncer = client_components["noncer"]
    verifier: IVerifier = client_components["verifier"]
    timestamper: ITimestamper = client_components["timestamper"]
    network: INetwork = client_components["network"]
    verification_key_store: IVerificationKeyStore = client_components["verification_key_store"]

    # Create recovery key
    recovery_signer = Secp256r1()
    await recovery_signer.generate()
    recovery_hash = await hasher.sum(await recovery_signer.public())

    # Create first client
    client1 = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=CryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=PublicKeyConfig(
                    response=verification_key_store,
                ),
            ),
            encoding=EncodingConfig(timestamper=timestamper),
            io=IOConfig(network=network),
            paths=authentication_paths,
            store=StoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(access=ClientValueStore()),
            ),
        )
    )

    # Create second client (linked device)
    client2 = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=CryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=PublicKeyConfig(
                    response=verification_key_store,
                ),
            ),
            encoding=EncodingConfig(timestamper=timestamper),
            io=IOConfig(network=network),
            paths=authentication_paths,
            store=StoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(access=ClientValueStore()),
            ),
        )
    )

    await client1.create_account(recovery_hash)
    identity = await client1.identity()

    # Get link container from the new device
    link_container = await client2.generate_link_container(identity)
    if DEBUG_LOGGING:
        print(link_container)

    # Submit an endorsed link container with existing device
    await client1.link_device(link_container)

    await execute_flow(client2, verifier, verification_key_store)

    # Unlink the original device
    await client2.unlink_device(await client1.device())


@pytest.mark.asyncio
async def test_detects_mismatched_access_nonce(client_components):
    """Test that mismatched access nonces are detected."""
    hasher: IHasher = client_components["hasher"]
    noncer: INoncer = client_components["noncer"]
    timestamper: ITimestamper = client_components["timestamper"]
    network: INetwork = client_components["network"]
    verification_key_store: IVerificationKeyStore = client_components["verification_key_store"]

    # Create recovery key
    recovery_signer = Secp256r1()
    await recovery_signer.generate()
    recovery_hash = await hasher.sum(await recovery_signer.public())

    # Create client
    access_token_store = ClientValueStore()
    client = BetterAuthClient(
        BetterAuthClientConfig(
            crypto=CryptoConfig(
                hasher=hasher,
                noncer=noncer,
                public_key=PublicKeyConfig(
                    response=verification_key_store,
                ),
            ),
            encoding=EncodingConfig(timestamper=timestamper),
            io=IOConfig(network=network),
            paths=authentication_paths,
            store=StoreConfig(
                identifier=IdentifierStoreConfig(
                    device=ClientValueStore(),
                    identity=ClientValueStore(),
                ),
                key=KeyStoreConfig(
                    access=ClientRotatingKeyStore(),
                    authentication=ClientRotatingKeyStore(),
                ),
                token=TokenStoreConfig(access=access_token_store),
            ),
        )
    )

    await client.create_account(recovery_hash)

    with pytest.raises(Exception) as exc_info:
        await client.authenticate()
        message = {"foo": "bar", "bar": "foo"}
        await client.make_access_request("/bad/nonce", message)

    assert "incorrect nonce" in str(exc_info.value)
