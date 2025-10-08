"""Example server implementation for better-auth Python.

This server provides HTTP endpoints for testing the better-auth protocol,
matching the functionality of the Go server example.
"""

import json
import sys
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, TypedDict

from better_auth import AccessVerifier, BetterAuthServer, BetterAuthServerConfig
from better_auth.api.server import (
    AccessStoreConfig,
    AccessVerifierConfig,
    AccessVerifierCryptoConfig,
    AccessVerifierEncodingConfig,
    AccessVerifierStorageConfig,
    AccessVerifierStoreConfig,
    AuthenticationStoreConfig,
    CryptoConfig,
    EncodingConfig,
    ExpiryConfig,
    KeyPairConfig,
    RecoveryStoreConfig,
    StoreConfig,
)
from better_auth.messages import AccessRequest, ServerResponse
from .implementation.crypto import Hasher, Noncer, Secp256r1, Secp256r1Verifier
from .implementation.encoding import IdentityVerifier, Rfc3339Nano, TokenEncoder
from .implementation.storage import (
    ServerAuthenticationKeyStore,
    ServerAuthenticationNonceStore,
    ServerRecoveryHashStore,
    ServerTimeLockStore,
    VerificationKeyStore,
)


class MockTokenAttributes(TypedDict):
    """Mock token attributes for testing."""

    permissionsByRole: Dict[str, list[str]]


class MockRequestPayload(TypedDict):
    """Mock request payload."""

    foo: str
    bar: str


class MockResponsePayload(TypedDict):
    """Mock response payload."""

    wasFoo: str
    wasBar: str


class Server:
    """Better-auth example server with HTTP endpoints."""

    def __init__(self) -> None:
        """Initialize the server with crypto, storage, and auth components."""
        # Lifetimes
        access_lifetime = timedelta(minutes=15)
        access_window = timedelta(seconds=30)
        refresh_lifetime = timedelta(hours=12)
        authentication_challenge_lifetime = timedelta(minutes=1)

        # Crypto components
        self.hasher = Hasher()
        self.verifier = Secp256r1Verifier()
        self.noncer = Noncer()

        # Storage components
        access_key_hash_store = ServerTimeLockStore(int(refresh_lifetime.total_seconds()))
        access_nonce_store = ServerTimeLockStore(int(access_window.total_seconds()))
        authentication_key_store = ServerAuthenticationKeyStore()
        authentication_nonce_store = ServerAuthenticationNonceStore(
            int(authentication_challenge_lifetime.total_seconds())
        )
        recovery_hash_store = ServerRecoveryHashStore()

        # Encoding components
        identity_verifier = IdentityVerifier()
        timestamper = Rfc3339Nano()
        token_encoder = TokenEncoder()

        # Generate server keys
        self.server_response_key = Secp256r1()
        self.server_access_key = Secp256r1()

        # Initialize the keys synchronously (we'll handle this in start_server)
        self._keys_initialized = False

        # Create BetterAuthServer config
        self.server_config = BetterAuthServerConfig(
            crypto=CryptoConfig(
                hasher=self.hasher,
                key_pair=KeyPairConfig(
                    response=self.server_response_key,
                    access=self.server_access_key,
                ),
                verifier=self.verifier,
            ),
            encoding=EncodingConfig(
                identity_verifier=identity_verifier,
                timestamper=timestamper,
                token_encoder=token_encoder,
            ),
            expiry=ExpiryConfig(
                access_in_minutes=int(access_lifetime.total_seconds() / 60),
                refresh_in_hours=int(refresh_lifetime.total_seconds() / 3600),
            ),
            store=StoreConfig(
                access=AccessStoreConfig(
                    key_hash=access_key_hash_store,
                ),
                authentication=AuthenticationStoreConfig(
                    key=authentication_key_store,
                    nonce=authentication_nonce_store,
                ),
                recovery=RecoveryStoreConfig(
                    hash=recovery_hash_store,
                ),
            ),
        )

        self.ba = BetterAuthServer(self.server_config)

        # Create access key store
        self.access_key_store = VerificationKeyStore()

        # Create AccessVerifier
        self.av = AccessVerifier(
            AccessVerifierConfig(
                crypto=AccessVerifierCryptoConfig(
                    access_key_store=self.access_key_store,
                    verifier=self.verifier,
                ),
                encoding=AccessVerifierEncodingConfig(
                    token_encoder=token_encoder,
                    timestamper=timestamper,
                ),
                store=AccessVerifierStorageConfig(
                    access=AccessVerifierStoreConfig(
                        nonce=access_nonce_store,
                    ),
                ),
            )
        )

    async def _initialize_keys(self) -> None:
        """Initialize the server keys."""
        if not self._keys_initialized:
            await self.server_response_key.generate()
            await self.server_access_key.generate()
            # Add access key to the store
            server_access_identity = await self.server_access_key.identity()
            self.access_key_store.add(server_access_identity, self.server_access_key)
            self._keys_initialized = True

    async def _wrap_response(self, body: bytes, logic: Callable[[str], Any]) -> tuple[int, str]:
        """Wrap a request handler with error handling.

        Args:
            body: The request body bytes.
            logic: The async handler function.

        Returns:
            A tuple of (status_code, response_body).
        """
        try:
            message = body.decode("utf-8")
            reply = await logic(message)
            return (200, reply)
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            return (500, json.dumps({"error": "an error occurred"}))

    async def create(self, body: bytes) -> tuple[int, str]:
        """Handle account creation requests."""
        return await self._wrap_response(body, self.ba.create_account)

    async def recover(self, body: bytes) -> tuple[int, str]:
        """Handle account recovery requests."""
        return await self._wrap_response(body, self.ba.recover_account)

    async def link(self, body: bytes) -> tuple[int, str]:
        """Handle device linking requests."""
        return await self._wrap_response(body, self.ba.link_device)

    async def unlink(self, body: bytes) -> tuple[int, str]:
        """Handle device unlinking requests."""
        return await self._wrap_response(body, self.ba.unlink_device)

    async def start_authentication(self, body: bytes) -> tuple[int, str]:
        """Handle authentication start requests."""
        return await self._wrap_response(body, self.ba.start_authentication)

    async def finish_authentication(self, body: bytes) -> tuple[int, str]:
        """Handle authentication finish requests."""

        async def handler(message: str) -> str:
            return await self.ba.finish_authentication(
                message,
                MockTokenAttributes(
                    permissionsByRole={
                        "admin": ["read", "write"],
                    }
                ),
            )

        return await self._wrap_response(body, handler)

    async def rotate_authentication(self, body: bytes) -> tuple[int, str]:
        """Handle authentication key rotation requests."""
        return await self._wrap_response(body, self.ba.rotate_authentication_key)

    async def rotate_access(self, body: bytes) -> tuple[int, str]:
        """Handle access token refresh requests."""
        return await self._wrap_response(body, self.ba.refresh_access_token)

    async def response_key(self, body: bytes) -> tuple[int, str]:
        """Handle server response key requests."""

        async def handler(message: str) -> str:
            return await self.server_response_key.public()

        return await self._wrap_response(body, handler)

    async def _respond_to_access_request(self, message: str, bad_nonce: bool) -> str:
        """Handle an access request and create a signed response.

        Args:
            message: The serialized access request.
            bad_nonce: Whether to use an incorrect nonce (for testing).

        Returns:
            The serialized server response.
        """
        # Verify the access token
        _, _ = await self.av.verify(message)

        # Parse the access request
        # request_data = json.loads(message)
        request = AccessRequest[MockRequestPayload].parse(message)

        # Get the server identity
        server_identity = await self.server_response_key.identity()

        # Use the request nonce or a bad one for testing
        nonce = request.payload["access"]["nonce"]
        if bad_nonce:
            nonce = "0A0123456789"

        # Create the response
        response = ServerResponse(
            response=MockResponsePayload(
                wasFoo=request.payload["request"]["foo"],
                wasBar=request.payload["request"]["bar"],
            ),
            server_identity=server_identity,
            nonce=nonce,
        )

        # Sign the response
        await response.sign(self.server_response_key)

        return await response.serialize()

    async def foo_bar(self, body: bytes) -> tuple[int, str]:
        """Handle foo/bar test requests."""

        async def handler(message: str) -> str:
            return await self._respond_to_access_request(message, False)

        return await self._wrap_response(body, handler)

    async def bad_nonce(self, body: bytes) -> tuple[int, str]:
        """Handle bad nonce test requests."""

        async def handler(message: str) -> str:
            return await self._respond_to_access_request(message, True)

        return await self._wrap_response(body, handler)


class RequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the better-auth server."""

    server_instance: Server

    def do_POST(self) -> None:
        """Handle POST requests."""
        import asyncio

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Route the request
        routes = {
            "/account/create": self.server_instance.create,
            "/account/recover": self.server_instance.recover,
            "/session/request": self.server_instance.start_authentication,
            "/session/create": self.server_instance.finish_authentication,
            "/session/refresh": self.server_instance.rotate_access,
            "/device/rotate": self.server_instance.rotate_authentication,
            "/device/link": self.server_instance.link,
            "/device/unlink": self.server_instance.unlink,
            "/key/response": self.server_instance.response_key,
            "/foo/bar": self.server_instance.foo_bar,
            "/bad/nonce": self.server_instance.bad_nonce,
        }

        handler = routes.get(self.path)
        if handler:
            try:
                status_code, response = asyncio.run(handler(body))
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(response.encode("utf-8"))
            except Exception as e:
                print(f"Request handling error: {e}", file=sys.stderr)
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self) -> None:
        """Handle OPTIONS requests for CORS."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        """Log HTTP requests to stderr."""
        sys.stderr.write(f"{self.address_string()} - {format % args}\n")


def main() -> None:
    """Start the server."""
    server_instance = Server()
    import asyncio

    asyncio.run(server_instance._initialize_keys())

    RequestHandler.server_instance = server_instance

    httpd = HTTPServer(("localhost", 8080), RequestHandler)
    print("Server running on http://localhost:8080")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.shutdown()


if __name__ == "__main__":
    main()
