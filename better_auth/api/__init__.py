"""Better-auth API package.

This package provides client and server implementations for the BetterAuth protocol.
"""

from better_auth.api.client import (
    BetterAuthClient,
    BetterAuthClientConfig,
    CryptoConfig,
    EncodingConfig,
    IdentifierStoreConfig,
    IOConfig,
    KeyStoreConfig,
    StoreConfig,
    TokenStoreConfig,
)
from better_auth.api.server import (
    AccessStoreConfig,
    AccessVerifier,
    AccessVerifierConfig,
    AccessVerifierCryptoConfig,
    AccessVerifierEncodingConfig,
    AccessVerifierStorageConfig,
    AccessVerifierStoreConfig,
    AuthenticationStoreConfig,
    BetterAuthServer,
    BetterAuthServerConfig,
    ExpiryConfig,
    KeyPairConfig,
    RecoveryStoreConfig,
)

__all__ = [
    # Client
    "BetterAuthClient",
    # Server
    "BetterAuthServer",
    "AccessVerifier",
    # Client configuration types
    "BetterAuthClientConfig",
    "CryptoConfig",
    "EncodingConfig",
    "IOConfig",
    "StoreConfig",
    "IdentifierStoreConfig",
    "KeyStoreConfig",
    "TokenStoreConfig",
    # Server configuration types
    "BetterAuthServerConfig",
    "KeyPairConfig",
    "ExpiryConfig",
    "AccessStoreConfig",
    "AuthenticationStoreConfig",
    "RecoveryStoreConfig",
    # AccessVerifier configuration types
    "AccessVerifierConfig",
    "AccessVerifierCryptoConfig",
    "AccessVerifierEncodingConfig",
    "AccessVerifierStorageConfig",
    "AccessVerifierStoreConfig",
]
